// Release signing with the Tauri signer key format (minisign: Ed25519, BLAKE2b-512 prehash).
// The private key stays outside the repository; only the public key is pinned here.
// Verification uses node:crypto only, so checking a release needs no extra dependency.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readFile,readdir,lstat,writeFile,mkdir,copyFile,access} from 'node:fs/promises';
import {dirname,resolve,join,basename} from 'node:path';
import {homedir} from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export const pinnedPublicKey=join(root,'release','nymwrap-release.pub');
export const defaultPrivateKey=join(homedir(),'.nymwrap-release','nymwrap-release.key');
export const sumsName='SHA256SUMS';
const tauriCli=join(root,'app','node_modules','@tauri-apps','cli','tauri.js');
const spkiEd25519=Buffer.from('302a300506032b6570032100','hex');
const nameRule=/^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/;

// Tauri wraps minisign text in one more base64 layer; plain minisign text is accepted too.
function minisignLines(text){
  let body=String(text).trim();
  if(!body.startsWith('untrusted comment:')){
    if(!/^[A-Za-z0-9+/=\s]+$/.test(body))throw Error('signature_format');
    body=Buffer.from(body,'base64').toString('utf8').trim();
  }
  const lines=body.split(/\r?\n/);
  if(!lines[0]?.startsWith('untrusted comment:'))throw Error('signature_format');
  return lines;
}
function strictBase64(line,length,error){
  if(!/^[A-Za-z0-9+/]+={0,2}$/.test(line??''))throw Error(error);
  const bytes=Buffer.from(line,'base64');
  if(bytes.length!==length||bytes.toString('base64')!==line)throw Error(error);
  return bytes;
}
export function parsePublicKey(text){
  const lines=minisignLines(text);
  if(lines.length!==2)throw Error('public_key_format');
  const bytes=strictBase64(lines[1],42,'public_key_format');
  if(bytes.subarray(0,2).toString('latin1')!=='Ed')throw Error('public_key_algorithm');
  return {keyId:bytes.subarray(2,10),key:createPublicKey({key:Buffer.concat([spkiEd25519,bytes.subarray(10)]),format:'der',type:'spki'})};
}
export function parseSignature(text){
  const lines=minisignLines(text);
  if(lines.length!==4||!lines[2].startsWith('trusted comment: '))throw Error('signature_format');
  const bytes=strictBase64(lines[1],74,'signature_format');
  const algorithm=bytes.subarray(0,2).toString('latin1');
  if(algorithm!=='ED'&&algorithm!=='Ed')throw Error('signature_algorithm');
  return {algorithm,keyId:bytes.subarray(2,10),signature:bytes.subarray(10),trusted:lines[2].slice('trusted comment: '.length),global:strictBase64(lines[3],64,'signature_format')};
}
// Returns the trusted comment only after both the file and the comment signatures verify.
export function verifyDetached(content,signatureText,publicKeyText,expectedName){
  const publicKey=parsePublicKey(publicKeyText),signature=parseSignature(signatureText);
  if(!publicKey.keyId.equals(signature.keyId))throw Error('signature_key_mismatch');
  const message=signature.algorithm==='ED'?createHash('blake2b512').update(content).digest():content;
  if(!verify(null,message,publicKey.key,signature.signature))throw Error('signature_invalid');
  if(!verify(null,Buffer.concat([signature.signature,Buffer.from(signature.trusted,'utf8')]),publicKey.key,signature.global))throw Error('trusted_comment_invalid');
  const file=/(?:^|\t)file:([^\t]*)(?:\t|$)/.exec(signature.trusted)?.[1];
  if(expectedName!==undefined&&file!==expectedName)throw Error('signature_file_mismatch');
  return signature.trusted;
}

// Flat directory only: no subdirectories or links, so the list is exactly what is published.
async function releaseFiles(directory){
  const names=[];
  for(const name of (await readdir(directory)).sort()){
    if(name===sumsName||name===sumsName+'.sig')continue;
    const info=await lstat(join(directory,name));
    if(!info.isFile()||info.isSymbolicLink())throw Error('release_entry_not_regular_file');
    if(!nameRule.test(name))throw Error('release_file_name');
    names.push(name);
  }
  if(!names.length)throw Error('release_empty');
  return names;
}
export async function checksums(directory){
  let text='';
  for(const name of await releaseFiles(directory))text+=createHash('sha256').update(await readFile(join(directory,name))).digest('hex')+'  '+name+'\n';
  return text;
}
export function parseChecksums(text){
  const entries=new Map();
  if(!text.endsWith('\n'))throw Error('checksums_format');
  for(const line of text.slice(0,-1).split('\n')){
    const found=/^([0-9a-f]{64})  (.+)$/.exec(line);
    if(!found||!nameRule.test(found[2])||entries.has(found[2]))throw Error('checksums_format');
    entries.set(found[2],found[1]);
  }
  return entries;
}
// Fails closed: a missing, changed or unlisted file rejects the whole release.
export async function verifyRelease(directory,publicKeyText){
  const sums=await readFile(join(directory,sumsName));
  verifyDetached(sums,await readFile(join(directory,sumsName+'.sig'),'utf8'),publicKeyText,sumsName);
  const listed=parseChecksums(sums.toString('utf8'));
  const present=await releaseFiles(directory);
  if(present.length!==listed.size||present.some(name=>!listed.has(name)))throw Error('release_file_set_mismatch');
  for(const name of present)if(createHash('sha256').update(await readFile(join(directory,name))).digest('hex')!==listed.get(name))throw Error('release_hash_mismatch');
  return [...listed.keys()];
}

function tauri(args,environment={}){
  const result=spawnSync(process.execPath,[tauriCli,...args],{stdio:'inherit',env:{...process.env,...environment}});
  if(result.status!==0)throw Error('tauri_signer_failed');
}
async function exists(path){try{await access(path);return true;}catch{return false;}}
// tauri signer sign does not prompt; it silently assumes an empty password. Ask without echo.
function hiddenPassword(prompt){
  if(process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD!==undefined)return Promise.resolve(process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD);
  if(!process.stdin.isTTY)throw Error('release_password_required');
  return new Promise((done,fail)=>{
    let value='';process.stderr.write(prompt);process.stdin.setRawMode(true);process.stdin.resume();process.stdin.setEncoding('utf8');
    const finish=error=>{process.stdin.setRawMode(false);process.stdin.pause();process.stdin.off('data',input);process.stderr.write('\n');error?fail(error):done(value);};
    const input=chunk=>{for(const character of chunk){
      if(character==='\r'||character==='\n')return finish();
      if(character==='\u0003')return finish(Error('release_password_cancelled'));
      if(character==='\u007f'||character==='\b')value=value.slice(0,-1);else value+=character;
    }};
    process.stdin.on('data',input);
  });
}
async function readPinnedKey(path){
  if(!await exists(path))throw Error('release_public_key_missing: run "node scripts/release-signature.mjs keygen" first');
  return readFile(path,'utf8');
}
async function keygen(privateKey){
  if(await exists(privateKey)||await exists(pinnedPublicKey))throw Error('release_key_exists');
  await mkdir(dirname(privateKey),{recursive:true});
  tauri(['signer','generate','-w',privateKey]);
  await mkdir(dirname(pinnedPublicKey),{recursive:true});
  await copyFile(privateKey+'.pub',pinnedPublicKey);
}
async function sign(directory,privateKey,publicKeyPath){
  const publicKeyText=await readPinnedKey(publicKeyPath);
  if(!await exists(privateKey))throw Error('release_private_key_missing');
  await writeFile(join(directory,sumsName),await checksums(directory));
  tauri(['signer','sign','-f',privateKey,join(directory,sumsName)],{TAURI_SIGNING_PRIVATE_KEY_PASSWORD:await hiddenPassword('Пароль ключа выпуска: ')});
  return verifyRelease(directory,publicKeyText);
}
function option(args,name,fallback){const index=args.indexOf(name);return index<0?fallback:resolve(args[index+1]??'');}
async function main(){
  const [command,directory,...rest]=process.argv.slice(2);
  const privateKey=option(rest,'--key',defaultPrivateKey);
  if(command==='keygen'){await keygen(option([directory,...rest].filter(Boolean),'--key',defaultPrivateKey));console.log('release_key_created '+basename(pinnedPublicKey));return;}
  if(!directory||(command!=='sign'&&command!=='verify'))throw Error('usage: release-signature.mjs keygen [--key path] | sign <dir> [--key path] [--pubkey path] | verify <dir> [--pubkey path]');
  const names=command==='sign'?await sign(resolve(directory),privateKey,option(rest,'--pubkey',pinnedPublicKey)):await verifyRelease(resolve(directory),await readPinnedKey(option(rest,'--pubkey',pinnedPublicKey)));
  console.log('release_verified '+names.length);
}
if(import.meta.url===pathToFileURL(process.argv[1]??'').href)main().catch(error=>{console.error(error.message);process.exitCode=1;});
