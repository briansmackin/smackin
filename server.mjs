import http from 'node:http';
import {createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync, timingSafeEqual} from 'node:crypto';
import {readFile, writeFile, mkdir, rename, chmod, open, unlink} from 'node:fs/promises';
import {resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';

const AUTHORIZE='https://appcenter.intuit.com/connect/oauth2';
const TOKEN='https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
const REVOKE='https://developer.api.intuit.com/v2/oauth2/tokens/revoke';
const REPORTS=new Set(['ProfitAndLoss','BalanceSheet','CashFlow']);
const ENTITIES=new Set(['Account','Customer','Vendor','Invoice','Bill','Payment','BillPayment','Purchase','JournalEntry','SalesReceipt','CreditMemo']);
const ROOT=fileURLToPath(new URL('.',import.meta.url));
const htmlEscape=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hash=x=>createHash('sha256').update(x).digest('hex');
const random=()=>randomBytes(32).toString('base64url');
const equal=(a,b)=>timingSafeEqual(Buffer.from(hash(a)),Buffer.from(hash(b)));
function fault(status,message){const e=new Error(message);e.status=status;return e;}

export function configFromEnv(e=process.env){
  const origin=new URL(e.PUBLIC_ORIGIN || 'http://127.0.0.1:3000');
  const mode=e.QBO_ENV || 'sandbox';
  if(!['sandbox','production'].includes(mode)) throw new Error('QBO_ENV must be sandbox or production.');
  const local=origin.protocol==='http:' && ['localhost','127.0.0.1','[::1]'].includes(origin.hostname);
  if(origin.username || origin.password || origin.pathname!=='/' || origin.search || origin.hash || (!local && origin.protocol!=='https:')) throw new Error('PUBLIC_ORIGIN must be an HTTPS origin, or loopback HTTP for sandbox.');
  if(mode==='production' && origin.protocol!=='https:') throw new Error('Production requires HTTPS.');
  const key=Buffer.from(e.TOKEN_ENCRYPTION_KEY_BASE64 || '', 'base64');
  if(key.length!==32) throw new Error('TOKEN_ENCRYPTION_KEY_BASE64 must decode to 32 random bytes.');
  if(!/^[a-f0-9]{32}:[a-f0-9]{128}$/.test(e.ADMIN_PASSWORD_SCRYPT || '')) throw new Error('Set a valid ADMIN_PASSWORD_SCRYPT.');
  if((e.ERP_READ_KEY || '').length<43) throw new Error('Set ERP_READ_KEY to at least 32 random bytes encoded as base64url.');
  if(e.QBO_ALLOWED_REALM_ID && !/^\d{1,30}$/.test(e.QBO_ALLOWED_REALM_ID)) throw new Error('QBO_ALLOWED_REALM_ID must be numeric.');
  return {
    origin:origin.origin,mode,key,adminUser:e.ADMIN_USER || 'brian',passwordHash:e.ADMIN_PASSWORD_SCRYPT,
    readKey:e.ERP_READ_KEY,clientId:e.QBO_CLIENT_ID || '',clientSecret:e.QBO_CLIENT_SECRET || '',
    allowedRealm:e.QBO_ALLOWED_REALM_ID || '',dataDir:resolve(e.DATA_DIR || './data'),
    policiesApproved:e.POLICIES_APPROVED==='true',secure:origin.protocol==='https:'
  };
}

export function encrypt(data,key){
  const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from('smackin-qbo-token-v1'));
  const body=Buffer.concat([cipher.update(JSON.stringify(data),'utf8'),cipher.final()]);
  return JSON.stringify({v:1,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),body:body.toString('base64')});
}
export function decrypt(text,key){
  const x=JSON.parse(text);if(x.v!==1) throw new Error('Unsupported token envelope.');
  const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(x.iv,'base64'));
  decipher.setAAD(Buffer.from('smackin-qbo-token-v1'));decipher.setAuthTag(Buffer.from(x.tag,'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(x.body,'base64')),decipher.final()]).toString('utf8'));
}

export async function createConnector(config,{fetchImpl=fetch,now=Date.now}={}){
  await mkdir(config.dataDir,{recursive:true,mode:0o700});await chmod(config.dataDir,0o700);
  // A persistent lock deliberately refuses a second process. After a crash, an operator
  // must verify the old process is gone before removing connector.lock.
  const lockPath=join(config.dataDir,'connector.lock');
  const lock=await open(lockPath,'wx',0o600);await lock.writeFile(String(process.pid));await lock.close();
  const tokenPath=join(config.dataDir,'tokens.aes.json');
  let queue=Promise.resolve();
  function serial(fn){const run=queue.then(fn,fn);queue=run.catch(()=>{});return run;}
  const sessions=new Map();
  let authFailures=0,authWindow=now();
  const configured=()=>Boolean(config.clientId && config.clientSecret && config.allowedRealm);
  const base=config.mode==='production'?'https://quickbooks.api.intuit.com':'https://sandbox-quickbooks.api.intuit.com';
  const callback=`${config.origin}/quickbooks/callback`;
  const basic=()=>`Basic ${Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')}`;
  async function load(){try{return decrypt(await readFile(tokenPath,'utf8'),config.key);}catch(e){if(e.code==='ENOENT') return null;throw fault(503,'Token storage could not be read.');}}
  async function save(value){
    const tmp=join(config.dataDir,`token-${random()}.tmp`);
    await writeFile(tmp,encrypt(value,config.key),{mode:0o600,flag:'wx',flush:true});
    await rename(tmp,tokenPath);
  }
  async function upstream(url,options={}){
    let result;
    try{result=await fetchImpl(url,{...options,redirect:'error',signal:AbortSignal.timeout(20000)});}catch{throw fault(502,'QuickBooks request failed or timed out. No automatic retry was made.');}
    if(!result.ok){
      if(result.status===401) throw fault(409,'QuickBooks authorization needs attention. Reconnect from the connection page.');
      if(result.status===429) throw fault(429,'QuickBooks rate limit reached. Retry later.');
      throw fault(502,'QuickBooks did not accept the request.');
    }
    return result;
  }
  function tokenRecord(j,realm){
    if(typeof j.access_token!=='string' || typeof j.refresh_token!=='string' || !Number.isFinite(j.expires_in) || j.expires_in<=0) throw fault(502,'QuickBooks returned an incomplete token response. Reconnect.');
    return {realm,access:j.access_token,refresh:j.refresh_token,expires:now()+j.expires_in*1000};
  }
  async function activeToken(){
    let t=await load();if(!t) throw fault(409,'QuickBooks is not connected.');
    if(t.realm!==config.allowedRealm) throw fault(409,'Stored company does not match the configured company.');
    if(t.expires>now()+60000) return t;
    const r=await upstream(TOKEN,{method:'POST',headers:{Authorization:basic(),'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:t.refresh})});
    t=tokenRecord(await r.json(),t.realm);await save(t);return t;
  }
  function headers(res,type='text/html; charset=utf-8'){
    res.setHeader('Content-Type',type);res.setHeader('Cache-Control','no-store');
    res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('X-Frame-Options','DENY');
    res.setHeader('Content-Security-Policy',"default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    if(config.secure) res.setHeader('Strict-Transport-Security','max-age=31536000');
  }
  function send(res,status,body,type){headers(res,type);res.writeHead(status);res.end(body);}
  function json(res,status,obj){send(res,status,JSON.stringify(obj),'application/json; charset=utf-8');}
  function redirect(res,path){headers(res);res.writeHead(302,{Location:path});res.end();}
  function page(title,body){return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(title)} | SMACKIN ERP</title><link rel="stylesheet" href="/style.css"></head><body><main><p class="brand">SMACKIN' / INTERNAL SYSTEMS</p><h1>${htmlEscape(title)}</h1>${body}<footer><a href="/">Home</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a></footer></main></body></html>`;}
  function administrator(req,res){
    if(now()-authWindow>60000){authFailures=0;authWindow=now();}
    if(authFailures>=12) throw fault(429,'Too many sign-in attempts. Wait one minute.');
    const h=req.headers.authorization || '';
    if(h.length>4096) throw fault(401,'Sign-in required.');
    let raw='';if(h.startsWith('Basic '))raw=Buffer.from(h.slice(6),'base64').toString('utf8');
    const split=raw.indexOf(':');const user=raw.slice(0,split);const pass=raw.slice(split+1);
    const [salt,expected]=config.passwordHash.split(':');
    const valid=split>0 && equal(user,config.adminUser) && equal(scryptSync(pass,salt,64).toString('hex'),expected);
    if(!valid){authFailures++;res.setHeader('WWW-Authenticate','Basic realm="SMACKIN ERP connector", charset="UTF-8"');throw fault(401,'Administrator sign-in required.');}
  }
  function cookie(req){const m=(req.headers.cookie || '').match(/(?:^|;\s*)smackin_qbo_session=([A-Za-z0-9_-]{43})(?:;|$)/);return m?.[1];}
  function session(req,res,create=false){
    for(const [key,value] of sessions)if(value.exp<=now())sessions.delete(key);
    let id=cookie(req),value=id?sessions.get(hash(id)):null;
    if(!value && create){
      if(sessions.size>=100) throw fault(429,'Too many sessions. Retry later.');
      id=random();value={csrf:random(),exp:now()+15*60000,state:null};sessions.set(hash(id),value);
      res.setHeader('Set-Cookie',`smackin_qbo_session=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900${config.secure?'; Secure':''}`);
    }
    if(!value) throw fault(403,'Session expired. Open the connection page again.');
    return value;
  }
  async function form(req,res){
    if(req.headers.origin!==config.origin) throw fault(403,'Request origin rejected.');
    if(!(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) throw fault(415,'Form request required.');
    let text='';for await(const chunk of req){text+=chunk;if(text.length>4096)throw fault(413,'Request too large.');}
    const params=new URLSearchParams(text);const s=session(req,res);
    if(!equal(params.get('csrf') || '',s.csrf))throw fault(403,'Request verification failed.');
    return s;
  }
  function formHTML(action,csrf,label){return `<form method="post" action="${action}"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">${label}</button></form>`;}
  function apiAccess(req){const h=req.headers.authorization || '';if(!h.startsWith('Bearer ') || !equal(h.slice(7),config.readKey))throw fault(401,'ERP authorization required.');}
  function reportQuery(url){
    const q=new URLSearchParams();
    for(const [k,v] of url.searchParams){
      if(['start_date','end_date'].includes(k) && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString().slice(0,10)===v)q.set(k,v);
      else if(k==='accounting_method' && ['Cash','Accrual'].includes(v))q.set(k,v);
      else if(k==='summarize_column_by' && ['Total','Month','Quarter','Year'].includes(v))q.set(k,v);
      else throw fault(400,'Unsupported report parameter.');
    }
    if(q.has('start_date') && q.has('end_date') && q.get('start_date')>q.get('end_date'))throw fault(400,'Report dates are reversed.');
    return q;
  }
  async function handler(req,res){
    try{
      // Ignore forwarded host/proto headers; all callback URLs use PUBLIC_ORIGIN.
      const url=new URL(req.url,config.origin),path=url.pathname;
      if(!req.url.startsWith('/') || req.url.startsWith('//')) throw fault(400,'Invalid request target.');
      if(req.method==='GET' && path==='/health') return json(res,200,{status:'ok'});
      if(req.method==='GET' && path==='/style.css') return send(res,200,await readFile(join(ROOT,'public/style.css'),'utf8'),'text/css');
      if(req.method==='GET' && ['/terms','/privacy'].includes(path)){
        const draft=config.policiesApproved?'':'<p class="notice">DRAFT — pending owner review and deployment verification. Not an effective policy.</p>';
        return send(res,200,page(path==='/terms'?'Internal application terms':'Application privacy notice',draft+await readFile(join(ROOT,`public${path}.html`),'utf8')));
      }
      if(req.method==='GET' && path==='/') return send(res,200,page('QuickBooks connection',`<p>SMACKIN ERP is an internal reporting tool for Smackin', Inc.</p><p>This connector provides authorized accounting reads to the ERP. It does not provide payment initiation or accounting write routes.</p><p><a class="button" href="/quickbooks/connect">Manage QuickBooks connection</a></p><p><a href="https://smackin-erp-dashboard-5fkt.pages.grok.bot/">Open ERP dashboard</a></p>`));
      if(req.method==='GET' && path==='/quickbooks/callback'){
        const s=session(req,res);const state=url.searchParams.get('state') || '';
        if(!s.state || s.state.exp<=now() || !equal(hash(state),s.state.hash)) throw fault(403,'OAuth state rejected. Start a new connection.');
        s.state=null; // Consume before any async exchange; replay cannot exchange twice.
        if(url.searchParams.has('error')) return redirect(res,'/quickbooks/connect?result=declined');
        const code=url.searchParams.get('code'),realm=url.searchParams.get('realmId');
        if(!configured() || !code || code.length>4096 || realm!==config.allowedRealm) throw fault(400,'Company or authorization response rejected.');
        await serial(async()=>{
          const r=await upstream(TOKEN,{method:'POST',headers:{Authorization:basic(),'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:callback})});
          await save(tokenRecord(await r.json(),realm));
        });
        return redirect(res,'/quickbooks/connect?result=connected');
      }
      if(['/quickbooks/connect','/quickbooks/disconnect'].includes(path)){
        administrator(req,res);
        if(req.method==='GET'){
          const s=session(req,res,true),connected=await serial(async()=>Boolean(await load()));
          const isDisconnect=path.endsWith('disconnect');
          let body=`<p>Status: <strong>${connected?'Connected':'Not connected'}</strong>.</p>`;
          if(!configured())body+='<p class="notice">Setup is incomplete. The app credentials and allowed QuickBooks company ID must be configured before connecting.</p>';
          else if(isDisconnect)body+=`<p>Disconnecting revokes this app's QuickBooks access and removes its local tokens. It does not delete financial records in QuickBooks or exports already held by the ERP.</p>${formHTML(path,s.csrf,'Disconnect QuickBooks')}`;
          else body+=`<p>Authorize only SMACKIN's configured QuickBooks company. Intuit's accounting scope includes write capabilities; this connector exposes only approved reads.</p>${formHTML(path,s.csrf,connected?'Reconnect QuickBooks':'Connect QuickBooks')}<p><a href="/quickbooks/disconnect">Disconnect</a></p>`;
          return send(res,200,page(isDisconnect?'Disconnect QuickBooks':'Connect QuickBooks',body));
        }
        if(req.method!=='POST')throw fault(405,'Method not allowed.');
        const s=await form(req,res);if(!configured())throw fault(503,'Connection configuration is incomplete.');
        if(path.endsWith('connect') && !path.endsWith('disconnect')){
          const state=random();s.state={hash:hash(state),exp:now()+10*60000};
          const next=new URL(AUTHORIZE);next.search=new URLSearchParams({client_id:config.clientId,response_type:'code',scope:'com.intuit.quickbooks.accounting',redirect_uri:callback,state}).toString();
          return redirect(res,next.toString());
        }
        await serial(async()=>{
          const t=await load();if(!t)return;
          await upstream(REVOKE,{method:'POST',headers:{Authorization:basic(),'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({token:t.refresh})});
          await unlink(tokenPath);
        });s.state=null;
        return redirect(res,'/quickbooks/connect?result=disconnected');
      }
      if(path.startsWith('/api/')){
        apiAccess(req);if(req.method!=='GET')throw fault(405,'Only GET is allowed for ERP data.');
        if(!configured())throw fault(503,'Connection configuration is incomplete.');
        let resource,params;
        if(path==='/api/company'){resource='companyinfo';params=new URLSearchParams();if(url.search)throw fault(400,'Unsupported parameter.');}
        else if(path.startsWith('/api/reports/') && REPORTS.has(path.split('/')[3]) && path.split('/').length===4){resource=`reports/${path.split('/')[3]}`;params=reportQuery(url);}
        else if(path.startsWith('/api/entities/') && ENTITIES.has(path.split('/')[3]) && path.split('/').length===4){
          for(const k of url.searchParams.keys())if(!['start','limit'].includes(k))throw fault(400,'Unsupported parameter.');
          const start=url.searchParams.get('start') || '1',limit=url.searchParams.get('limit') || '100';
          if(!/^\d{1,7}$/.test(start) || Number(start)<1 || !/^\d{1,4}$/.test(limit) || Number(limit)<1 || Number(limit)>1000)throw fault(400,'Invalid pagination.');
          resource='query';params=new URLSearchParams({query:`select * from ${path.split('/')[3]} startposition ${Number(start)} maxresults ${Number(limit)}`});
        }else throw fault(404,'Read endpoint not available.');
        const payload=await serial(async()=>{
          const t=await activeToken();const suffix=resource==='companyinfo'?`companyinfo/${t.realm}`:resource;
          const target=new URL(`${base}/v3/company/${t.realm}/${suffix}`);target.search=params.toString();
          const r=await upstream(target.toString(),{method:'GET',headers:{Authorization:`Bearer ${t.access}`,Accept:'application/json'}});
          return await r.json();
        });
        return json(res,200,payload);
      }
      throw fault(404,'Page not found.');
    }catch(e){if(!res.headersSent)json(res,e.status || 500,{error:e.status?e.message:'The connector encountered an internal error.'});else res.end();}
  }
  const server=http.createServer(handler);server.requestTimeout=30000;server.headersTimeout=10000;
  return {server,close:async()=>{await queue;await new Promise(r=>server.listening?server.close(r):r());await unlink(lockPath);}};
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const config=configFromEnv();const app=await createConnector(config);
  app.server.listen(Number(process.env.PORT || 3000),process.env.HOST || '127.0.0.1',()=>console.log('SMACKIN QuickBooks connector started. Request URLs and credentials are not logged.'));
  for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>app.close().then(()=>process.exit(0)));
}
