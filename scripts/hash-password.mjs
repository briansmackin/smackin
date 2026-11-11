import {randomBytes, scryptSync} from 'node:crypto';
let input='';
for await (const part of process.stdin) input += part;
const password=input.replace(/\r?\n$/, '');
if(password.length < 20) throw new Error('Use a unique password of at least 20 characters.');
const salt=randomBytes(16).toString('hex');
process.stdout.write(`${salt}:${scryptSync(password,salt,64).toString('hex')}\n`);
