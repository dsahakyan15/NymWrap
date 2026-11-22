import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,writeFile,rm,realpath} from 'node:fs/promises';
import {resolve,join,sep} from 'node:path';
import {pinnedBinary,cachedBinary,artifactHash,verifyEmbeddedCorpus} from '../evaluation-artifacts.mjs';
test('evaluation binaries survive a rebuild and reject changed cached bytes or traversal',async()=>{
  const base=resolve('target/evaluation-artifact-tests');await mkdir(base,{recursive:true});const dir=await mkdtemp(join(base,'fixture-'));
  try{
    const source=join(dir,'source');await writeFile(source,'synthetic-first');const pinned=await pinnedBinary(dir,source,'synthetic');
    const corpus=join(dir,'corpus.json');await writeFile(corpus,'synthetic-first');await verifyEmbeddedCorpus(pinned,corpus);
    await writeFile(corpus,'synthetic-edited');await assert.rejects(verifyEmbeddedCorpus(pinned,corpus),/corpus_mismatch/);
    assert.equal(await cachedBinary(dir,'synthetic',await artifactHash(pinned)),pinned);
    await assert.rejects(cachedBinary(dir,'synthetic','../escape'),/identity/);
    await writeFile(source,'synthetic-rebuilt');const newer=await pinnedBinary(dir,source,'synthetic');assert.notEqual(newer,pinned);assert.equal(await readFile(pinned,'utf8'),'synthetic-first');
    await assert.rejects(pinnedBinary(dir,source,'../escape'),/name/);
    await writeFile(newer,'synthetic-corrupted');await assert.rejects(pinnedBinary(dir,source,'synthetic'),/hash_mismatch/);
  }finally{const actual=await realpath(dir),parent=await realpath(base);if(!actual.toLowerCase().startsWith((parent+sep).toLowerCase()))throw Error('unsafe_artifact_test_cleanup');await rm(dir,{recursive:true,force:true});}
});
