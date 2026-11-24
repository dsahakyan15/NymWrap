import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,readFile,rm,access} from 'node:fs/promises';
import {resolve,join,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {checksums,parseChecksums,parsePublicKey,verifyDetached,verifyRelease,sumsName} from '../release-signature.mjs';
const target=fileURLToPath(new URL('../../target/',import.meta.url));
const tauriCli=fileURLToPath(new URL('../../app/node_modules/@tauri-apps/cli/tauri.js',import.meta.url));
async function fixture(t){
  await mkdir(target,{recursive:true});
  const directory=await mkdtemp(join(target,'release-signature-test-'));
  t.after(async()=>{const path=relative(target,resolve(directory));if(!path||path.startsWith('..')||isAbsolute(path))throw Error('unsafe_test_cleanup');await rm(directory,{recursive:true,force:true});});
  return directory;
}
// The real Tauri signer produces the signatures; the verifier is independent node:crypto code.
function tauri(args){
  const result=spawnSync(process.execPath,[tauriCli,...args],{encoding:'utf8',env:{...process.env,CI:'true',TAURI_SIGNING_PRIVATE_KEY_PASSWORD:'synthetic-test-password'}});
  assert.equal(result.status,0,result.stderr);
}
async function signerAvailable(t){
  try{await access(tauriCli);return true;}catch{
    if(process.env.CI)throw Error('tauri_cli_missing_in_ci');
    t.skip('app/node_modules is not installed');return false;
  }
}
async function signedRelease(t){
  const directory=await fixture(t),keys=join(directory,'keys'),release=join(directory,'release');
  await mkdir(keys);await mkdir(release);
  tauri(['signer','generate','--ci','-p','synthetic-test-password','-w',join(keys,'test.key')]);
  await writeFile(join(release,'nymwrap-synthetic.bin'),'synthetic release payload\n');
  await writeFile(join(release,'sbom.json'),'{"synthetic":true}\n');
  await writeFile(join(release,sumsName),await checksums(release));
  tauri(['signer','sign','-f',join(keys,'test.key'),join(release,sumsName)]);
  return {release,keys,publicKey:await readFile(join(keys,'test.key.pub'),'utf8')};
}

test('a release signed by the Tauri signer verifies against the pinned public key',async t=>{
  if(!await signerAvailable(t))return;
  const {release,publicKey}=await signedRelease(t);
  assert.deepEqual(await verifyRelease(release,publicKey),['nymwrap-synthetic.bin','sbom.json']);
});
test('changed, missing or extra files and a foreign key reject the release',async t=>{
  if(!await signerAvailable(t))return;
  const {release,keys,publicKey}=await signedRelease(t);
  await writeFile(join(release,'nymwrap-synthetic.bin'),'synthetic release payload, changed\n');
  await assert.rejects(verifyRelease(release,publicKey),/release_hash_mismatch/);
  await writeFile(join(release,'nymwrap-synthetic.bin'),'synthetic release payload\n');
  await writeFile(join(release,'unlisted.txt'),'synthetic\n');
  await assert.rejects(verifyRelease(release,publicKey),/release_file_set_mismatch/);
  await rm(join(release,'unlisted.txt'));await rm(join(release,'sbom.json'));
  await assert.rejects(verifyRelease(release,publicKey),/release_file_set_mismatch/);
  tauri(['signer','generate','--ci','-p','synthetic-test-password','-w',join(keys,'other.key')]);
  await assert.rejects(verifyRelease(release,await readFile(join(keys,'other.key.pub'),'utf8')),/signature_key_mismatch/);
});
test('edited checksums, signatures and trusted comments are rejected',async t=>{
  if(!await signerAvailable(t))return;
  const {release,publicKey}=await signedRelease(t);
  const sums=await readFile(join(release,sumsName)),signature=await readFile(join(release,sumsName+'.sig'),'utf8');
  assert.match(verifyDetached(sums,signature,publicKey,sumsName),/file:SHA256SUMS/);
  assert.throws(()=>verifyDetached(Buffer.concat([sums,Buffer.from('x')]),signature,publicKey,sumsName),/signature_invalid/);
  assert.throws(()=>verifyDetached(sums,signature,publicKey,'other-name'),/signature_file_mismatch/);
  const lines=Buffer.from(signature,'base64').toString('utf8').split('\n');
  lines[2]=lines[2].replace('file:SHA256SUMS','file:SHA256SUMS\tforged');
  assert.throws(()=>verifyDetached(sums,lines.join('\n'),publicKey,sumsName),/trusted_comment_invalid/);
  assert.throws(()=>verifyDetached(sums,'not a signature',publicKey,sumsName),/signature_format/);
});
test('checksum and public key parsers fail closed',()=>{
  const hash='a'.repeat(64);
  assert.equal(parseChecksums(`${hash}  app.bin\n`).get('app.bin'),hash);
  assert.throws(()=>parseChecksums(`${hash}  app.bin`),/checksums_format/);
  assert.throws(()=>parseChecksums(`${hash}  ../app.bin\n`),/checksums_format/);
  assert.throws(()=>parseChecksums(`${hash}  app.bin\n${hash}  app.bin\n`),/checksums_format/);
  assert.throws(()=>parsePublicKey('untrusted comment: x\nAAAA'),/public_key_format/);
});
