import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,symlink} from 'node:fs/promises';
import {resolve,join,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {inventory,lockChecksums,sourceDigest} from '../sbom.mjs';
const target=fileURLToPath(new URL('../../target/',import.meta.url));
async function fixture(t){
  const directory=await mkdtemp(join(target,'sbom-test-'));
  t.after(async()=>{const path=relative(target,resolve(directory));if(!path||path.startsWith('..')||isAbsolute(path))throw Error('unsafe_test_cleanup');await rm(directory,{recursive:true,force:true});});return directory;
}
const source='registry+https://github.com/rust-lang/crates.io-index';
const lock=`version = 4\n[[package]]\nname = "synthetic-lib"\nversion = "1.2.3"\nsource = "${source}"\nchecksum = "${'a'.repeat(64)}"\n`;
test('SBOM requires locked checksums and rejects unknown registries',()=>{
  assert.equal(lockChecksums(lock).size,1);
  assert.throws(()=>lockChecksums(lock.replace('a'.repeat(64),'bad')),/unhashed/);
  assert.throws(()=>lockChecksums(lock.replace('github.com/rust-lang/crates.io-index','foreign.example/index')),/unsupported/);
  assert.throws(()=>lockChecksums(lock+lock),/duplicate/);
});
test('SBOM follows normal/build edges, removes dev roots and hides host paths',async t=>{
  const directory=await fixture(t),local=join(directory,'crates/core');await mkdir(local,{recursive:true});await writeFile(join(local,'lib.rs'),'synthetic code');
  const metadata={workspace_members:['core'],packages:[{id:'core',name:'synthetic-core',version:'0.1.0',source:null,manifest_path:join(local,'Cargo.toml'),license:'MIT OR Apache-2.0'},{id:'lib',name:'synthetic-lib',version:'1.2.3',source,license:'MIT'},{id:'dev',name:'synthetic-dev',version:'0.0.1',source,license:'MIT'}],resolve:{nodes:[{id:'core',deps:[{pkg:'lib',dep_kinds:[{kind:'build'}]},{pkg:'dev',dep_kinds:[{kind:'dev'}]}]},{id:'lib',deps:[]},{id:'dev',deps:[]}]}};
  const graph={metadata,checksums:lockChecksums(lock),rootNames:['synthetic-core']};
  const first=await inventory([graph],directory),second=await inventory([graph],directory);
  assert.deepEqual(first,second);assert.equal(first.components.length,2);
  assert.ok(!JSON.stringify(first).includes(directory));assert.ok(!JSON.stringify(first).includes('synthetic-dev'));
  const core=first.components.find(p=>p.name==='synthetic-core');assert.equal(first.dependencies.find(d=>d.ref===core['bom-ref']).dependsOn.length,1);
  await assert.rejects(inventory([{...graph,checksums:new Map()}],directory),/missing_archive_checksum/);
});
test('source digest ignores build output, changes with code, and refuses symlink traversal',async t=>{
  const directory=await fixture(t);await writeFile(join(directory,'lib.rs'),'first');const first=await sourceDigest(directory);
  await mkdir(join(directory,'target'));await writeFile(join(directory,'target','generated'),'excluded');assert.equal(await sourceDigest(directory),first);
  await writeFile(join(directory,'lib.rs'),'second');assert.notEqual(await sourceDigest(directory),first);
  const outside=await fixture(t);await symlink(outside,join(directory,'foreign'),'junction');
  await assert.rejects(sourceDigest(directory),/symlink_not_supported/);
});
