import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,readFile,symlink} from 'node:fs/promises';
import {join,resolve,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {checksums} from '../release-signature.mjs';
import {releaseNames,compare,validate} from '../release-artifacts.mjs';
const target=fileURLToPath(new URL('../../target/',import.meta.url)),commit='a'.repeat(40);
async function fixture(t){
  await mkdir(target,{recursive:true});const directory=await mkdtemp(join(target,'release-compare-test-'));
  t.after(async()=>{const child=relative(target,resolve(directory));if(!child||child.startsWith('..')||isAbsolute(child))throw Error('unsafe_test_cleanup');await rm(directory,{recursive:true,force:true});});
  const a=join(directory,'a'),b=join(directory,'b'),out=join(directory,'out');
  for(const dir of [a,b]){
    await mkdir(dir);
    for(const name of releaseNames)await writeFile(join(dir,name),name.endsWith('.buildinfo.json')?JSON.stringify({commit,target:'x86_64-unknown-linux-gnu'}):'synthetic '+name+'\n');
    await writeFile(join(dir,'SHA256SUMS'),await checksums(dir));
  }
  return {a,b,out};
}
test('independent matching bytes produce the exact unsigned release',async t=>{
  const {a,b,out}=await fixture(t);const result=await compare(a,b,out,commit);
  assert.equal(result.identical,true);assert.equal(result.algorithm,'SHA-256');
  assert.equal(await readFile(join(out,'SHA256SUMS'),'utf8'),await checksums(a));
});
test('a changed binary archive fails even when its supplied checksums were updated',async t=>{
  const {a,b,out}=await fixture(t);
  await writeFile(join(b,'nymwrap-linux-x86_64.tar.gz'),'synthetic changed executable bytes');
  await assert.rejects(compare(a,b,out,commit),/release_hash_mismatch/);
  await writeFile(join(b,'SHA256SUMS'),await checksums(b));
  await assert.rejects(compare(a,b,out,commit),/release_not_reproducible/);
});
test('missing and extra files, a wrong source revision and populated output fail closed',async t=>{
  const {a,b,out}=await fixture(t);
  await writeFile(join(b,'unexpected.bin'),'synthetic');
  await assert.rejects(compare(a,b,out,commit),/release_file_set_mismatch/);
  await rm(join(b,'unexpected.bin'));
  await assert.rejects(compare(a,b,out,'b'.repeat(40)),/release_revision_mismatch/);
  await mkdir(out);await writeFile(join(out,'stale.bin'),'synthetic');
  await assert.rejects(compare(a,b,out,commit),/release_output_not_empty/);
  await rm(join(b,releaseNames[0]));
  await assert.rejects(compare(a,b,undefined,commit),/release_file_set_mismatch/);
});
test('the SBOM participates in reproducibility and manifest symlinks are rejected',async t=>{
  const {a,b,out}=await fixture(t);
  await writeFile(join(b,'nymwrap-linux-x86_64.cdx.json'),'synthetic changed inventory');
  await writeFile(join(b,'SHA256SUMS'),await checksums(b));
  await assert.rejects(compare(a,b,out,commit),/release_not_reproducible/);
  // File symlinks on Windows need Developer Mode; other platforms must exercise this.
  if(process.platform!=='win32'){
    const sums=await readFile(join(a,'SHA256SUMS'));await rm(join(a,'SHA256SUMS'));
    await mkdir(out);await writeFile(join(out,'sums'),sums);
    await symlink(join(out,'sums'),join(a,'SHA256SUMS'));
    await assert.rejects(validate(a,commit),/release_entry_not_regular_file/);
  }
});
