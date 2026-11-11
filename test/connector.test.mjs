import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,scryptSync} from 'node:crypto';
import {createConnector,configFromEnv,encrypt,decrypt} from '../server.mjs';

const salt='a'.repeat(32),password='test-only-password-very-long';
const admin=`Basic ${Buffer.from(`brian:${password}`).toString('base64')}`;
function config(dataDir){return configFromEnv({PUBLIC_ORIGIN:'http://127.0.0.1:3000',QBO_ENV:'sandbox',TOKEN_ENCRYPTION_KEY_BASE64:randomBytes(32).toString('base64'),ADMIN_PASSWORD_SCRYPT:`${salt}:${scryptSync(password,salt,64).toString('hex')}`,ERP_READ_KEY:'r'.repeat(43),QBO_CLIENT_ID:'test-id',QBO_CLIENT_SECRET:'test-secret',QBO_ALLOWED_REALM_ID:'123456',DATA_DIR:dataDir});}
async function setup(t,vendor){
  const dir=await mkdtemp(join(tmpdir(),'smackin-qbo-'));
  let clock=Date.now();const calls=[];const c=config(dir);
  const app=await createConnector(c,{now:()=>clock,fetchImpl:async(url,opts)=>{calls.push({url:String(url),opts});return vendor(String(url),opts);}});
  await new Promise(r=>app.server.listen(0,'127.0.0.1',r));c.origin=`http://127.0.0.1:${app.server.address().port}`;
  // For tests, the OAuth callback origin is the configured origin at construction.
  const call=(path,options={})=>fetch(c.origin+path,{redirect:'manual',...options});
  t.after(async()=>{await app.close();await rm(dir,{recursive:true,force:true});});
  return {dir,c,app,calls,call,advance:n=>clock+=n};
}
async function start(ctx){
  const get=await ctx.call('/quickbooks/connect',{headers:{Authorization:admin}});assert.equal(get.status,200);
  const cookie=get.headers.get('set-cookie').split(';')[0];const body=await get.text();
  const csrf=body.match(/name="csrf" value="([^"]+)"/)[1];
  const post=await ctx.call('/quickbooks/connect',{method:'POST',headers:{Authorization:admin,Cookie:cookie,Origin:ctx.c.origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf})});
  assert.equal(post.status,302);const redirect=new URL(post.headers.get('location'));
  assert.equal(redirect.origin,'https://appcenter.intuit.com');
  assert.equal(redirect.searchParams.get('scope'),'com.intuit.quickbooks.accounting');
  return {cookie,csrf,state:redirect.searchParams.get('state')};
}
const token=()=>new Response(JSON.stringify({access_token:'secret-access',refresh_token:'secret-refresh',expires_in:3600}),{status:200});
const callback=(ctx,s,realm='123456')=>ctx.call(`/quickbooks/callback?code=one-time-code&realmId=${realm}&state=${s.state}`,{headers:{Cookie:s.cookie}});
const readHeaders={Authorization:`Bearer ${'r'.repeat(43)}`};

test('AES encryption protects tokens and rejects tampering',()=>{
  const key=randomBytes(32);const sealed=encrypt({token:'secret-value'},key);
  assert.ok(!sealed.includes('secret-value'));assert.equal(decrypt(sealed,key).token,'secret-value');
  const obj=JSON.parse(sealed),body=Buffer.from(obj.body,'base64');body[0]^=1;obj.body=body.toString('base64');
  assert.throws(()=>decrypt(JSON.stringify(obj),key));assert.throws(()=>decrypt(sealed,randomBytes(32)));
});
test('production refuses HTTP and unknown environment',()=>{
  assert.throws(()=>configFromEnv({PUBLIC_ORIGIN:'http://127.0.0.1:3000',QBO_ENV:'production'}),/HTTPS/);
  assert.throws(()=>configFromEnv({QBO_ENV:'typo'}),/QBO_ENV/);
});
test('public documents are drafts and secrets/admin endpoints are protected',async t=>{
  const ctx=await setup(t,()=>{throw new Error('No vendor calls expected');});
  assert.equal((await ctx.call('/quickbooks/connect')).status,401);
  assert.equal((await ctx.call('/api/company')).status,401);
  const privacy=await ctx.call('/privacy');assert.equal(privacy.status,200);assert.match(await privacy.text(),/DRAFT/);
  assert.equal((await ctx.call('/data/tokens.aes.json')).status,404);
  assert.equal(ctx.calls.length,0);
});
test('CSRF origin and token checks reject connection attempts',async t=>{
  const ctx=await setup(t,token);const s=await start(ctx);
  for(const [origin,csrf] of [['https://evil.invalid',s.csrf],[ctx.c.origin,'wrong']]){
    const r=await ctx.call('/quickbooks/connect',{method:'POST',headers:{Authorization:admin,Cookie:s.cookie,Origin:origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf})});assert.equal(r.status,403);
  }
  assert.equal(ctx.calls.length,0);
});
test('OAuth state requires the original browser and expires',async t=>{
  const ctx=await setup(t,token);const s=await start(ctx);
  assert.equal((await ctx.call(`/quickbooks/callback?state=${s.state}&code=x&realmId=123456`)).status,403);
  assert.equal((await callback(ctx,{...s,state:'wrong'})).status,403);
  ctx.advance(11*60000);assert.equal((await callback(ctx,s)).status,403);assert.equal(ctx.calls.length,0);
});
test('wrong company is refused before exchanging authorization code',async t=>{
  const ctx=await setup(t,token);const s=await start(ctx);
  assert.equal((await callback(ctx,s,'987654')).status,400);assert.equal(ctx.calls.length,0);
});
test('OAuth code is consumed once and saved tokens are encrypted',async t=>{
  const ctx=await setup(t,token);const s=await start(ctx);
  const done=await callback(ctx,s);assert.equal(done.status,302);assert.equal(done.headers.get('location'),'/quickbooks/connect?result=connected');
  assert.equal((await callback(ctx,s)).status,403);assert.equal(ctx.calls.length,1);
  const stored=await readFile(join(ctx.dir,'tokens.aes.json'),'utf8');assert.ok(!stored.includes('secret-access'));assert.ok(!stored.includes('secret-refresh'));
  assert.equal(decrypt(stored,ctx.c.key).realm,'123456');
});
test('ERP write requests and arbitrary paths cannot reach QuickBooks',async t=>{
  const ctx=await setup(t,token);const s=await start(ctx);await callback(ctx,s);const before=ctx.calls.length;
  assert.equal((await ctx.call('/api/entities/Invoice',{method:'POST',headers:readHeaders,body:'{}'})).status,405);
  assert.equal((await ctx.call('/api/entities/Invoice?limit=1%20delete',{headers:readHeaders})).status,400);
  assert.equal((await ctx.call('/api/https://evil.invalid',{headers:readHeaders})).status,404);
  assert.equal((await ctx.call('/api/reports/ProfitAndLoss?url=https://evil.invalid',{headers:readHeaders})).status,400);
  assert.equal((await ctx.call('/api/reports/ProfitAndLoss?start_date=2026-02-30',{headers:readHeaders})).status,400);
  assert.equal((await ctx.call('/api/reports/ProfitAndLoss?start_date=2026-10-01&end_date=2026-09-01',{headers:readHeaders})).status,400);
  assert.equal(ctx.calls.length,before);
});
test('concurrent reads refresh once, save the newest token and use only GET',async t=>{
  let refreshCount=0;
  const ctx=await setup(t,(url,opts)=>{
    if(url.includes('/tokens/bearer')){
      if(opts.body.get('grant_type')==='refresh_token'){refreshCount++;assert.equal(opts.body.get('refresh_token'),'secret-refresh');return new Response(JSON.stringify({access_token:'new-access',refresh_token:'new-refresh',expires_in:3600}));}
      return token();
    }
    assert.equal(opts.method,'GET');assert.equal(opts.headers.Authorization,'Bearer new-access');
    assert.ok(url.startsWith('https://sandbox-quickbooks.api.intuit.com/v3/company/123456/'));
    return new Response(JSON.stringify({ok:true}));
  });
  const s=await start(ctx);await callback(ctx,s);ctx.advance(3600000);
  const responses=await Promise.all([ctx.call('/api/company',{headers:readHeaders}),ctx.call('/api/reports/ProfitAndLoss?accounting_method=Accrual',{headers:readHeaders})]);
  assert.deepEqual(responses.map(r=>r.status),[200,200]);assert.equal(refreshCount,1);
  assert.equal(decrypt(await readFile(join(ctx.dir,'tokens.aes.json'),'utf8'),ctx.c.key).refresh,'new-refresh');
});
test('GET disconnect is informational; POST revokes before deleting tokens',async t=>{
  let revoked=false;
  const ctx=await setup(t,(url,opts)=>{
    if(url.endsWith('/tokens/revoke')){assert.equal(opts.method,'POST');assert.equal(JSON.parse(opts.body).token,'secret-refresh');revoked=true;return new Response('');}
    return token();
  });const s=await start(ctx);await callback(ctx,s);
  assert.equal((await ctx.call('/quickbooks/disconnect',{headers:{Authorization:admin,Cookie:s.cookie}})).status,200);assert.equal(revoked,false);
  const r=await ctx.call('/quickbooks/disconnect',{method:'POST',headers:{Authorization:admin,Cookie:s.cookie,Origin:ctx.c.origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:s.csrf})});
  assert.equal(r.status,302);assert.equal(revoked,true);assert.ok(!(await readdir(ctx.dir)).includes('tokens.aes.json'));
  assert.equal((await ctx.call('/api/company',{headers:readHeaders})).status,409);
});
test('failed revoke preserves tokens for an explicit retry',async t=>{
  const ctx=await setup(t,(url)=>url.endsWith('/tokens/revoke')?new Response('',{status:500}):token());
  const s=await start(ctx);await callback(ctx,s);
  const r=await ctx.call('/quickbooks/disconnect',{method:'POST',headers:{Authorization:admin,Cookie:s.cookie,Origin:ctx.c.origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:s.csrf})});
  assert.equal(r.status,502);assert.ok((await readdir(ctx.dir)).includes('tokens.aes.json'));
});
test('a second process cannot open the same token store',async t=>{
  const ctx=await setup(t,token);await assert.rejects(createConnector(ctx.c),{code:'EEXIST'});
});
