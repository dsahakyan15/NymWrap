import {test} from 'node:test';
import assert from 'node:assert/strict';
import {options,evaluationRange} from '../linkcheck-eval.mjs';
import {embeddingModel,knownEmbedding} from '../linkcheck-embeddings.mjs';
test('only pinned embedding choices can enter a synthetic diagnostic or full run',()=>{
  assert.equal(options([]).embedding,'nomic');
  const model=embeddingModel('qwen3-0.6b-q8_0');
  assert.equal(model.dimension,1024);assert.ok(knownEmbedding(model.sha256,model.recipe_id,1024));
  assert.equal(knownEmbedding(model.sha256,'nomic_v1_5_mean_document_v1',1024),false);
  assert.throws(()=>options(['--embedding','unverified']));
  assert.throws(()=>options(['--embedding','nomic','--embedding','nomic']));
});
test('a diagnostic sample is exactly one named conversation and never a shard or prefix run',()=>{
  const corpus=[{id:'dev_0000'},{id:'dev_0001'},{id:'dev_0002'}];
  assert.deepEqual(evaluationRange(corpus,options(['--sample','dev_0002'])),{start:2,end:3});
  assert.throws(()=>evaluationRange(corpus,options(['--sample','dev_0999'])));
  for(const args of [['--sample'],['--sample','other'],['--sample','dev_0002','--limit','1'],['--sample','dev_0002','--shard','0/2']])assert.throws(()=>options(args));
});
