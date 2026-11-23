import {test} from 'node:test';
import {embeddingModel} from '../linkcheck-embeddings.mjs';
import assert from 'node:assert/strict';
import {shardRange} from '../linkcheck-shards.mjs';
import {mergeShardReports,main} from '../linkcheck-merge.mjs';
import {readFile,mkdtemp,mkdir,writeFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {artifactHash} from '../evaluation-artifacts.mjs';
import {summarizeLinkcheckReport} from '../linkcheck-report.mjs';
const sha='a'.repeat(64);
function fixture(){
  const corpus={version:3,partition:'development',synthetic_only:true,candidates:64,cases:[]};
  const observations=[];
  for(let i=0;i<7;i++){
    const id=`dev_${i}`,language=['en','ru','hy'][i%3],group='linkage_multiturn';
    corpus.cases.push({id,language,group,turns:[{},{}]});
    observations.push({id,language,group,remote_turns:2,local_turns:0,blocked_turns:0,canary_leaks:0,error:false,utility:true,
      attack:{valid:true,top1_correct:false},raw_attack:{valid:true,top1_correct:true},literal_attack:{valid:true,top1_correct:false},raw_literal_attack:{valid:true,top1_correct:true},
      calls:{ner:2,canonicalize:2,generalize:1,embeddings:4,answers:0,errors:0,linkage_ranks:Array.from({length:2},()=>({candidates:65,rank_min:65,rank_max:65,user_score:0,best_decoy_score:1000000,background_score:1000000,risky:false}))},local_reasons:[null,null],elapsed_ms:12});
  }
  const provenance=Object.fromEntries(['corpus_sha256','client_sha256','defender_worker_sha256','attacker_worker_sha256','model_sha256','attacker_model_sha256','embedding_sha256','config_sha256','evaluator_script_sha256','report_script_sha256','statistics_sha256','shard_script_sha256'].map(k=>[k,sha]));
  const embedding=embeddingModel('nomic');
  Object.assign(provenance,{embedding_sha256:embedding.sha256,embedding_recipe_id:embedding.recipe_id,embedding_dimension:embedding.dimension,embedding_catalog_sha256:sha});
  const sources=Array.from({length:3},(_,index)=>{
    const shard=shardRange(7,index,3);
    return {sha256:sha,report:{version:3,status:'complete_shard',partition:'development',case_count:7,shard,provenance:structuredClone(provenance),
      evidence:{workflow_run:'1234',commit:'b'.repeat(40)},scope:{external_requests:false,local_answers_stubbed:false,provider_answers:'real local model, simulated provider'},
      observations:observations.slice(shard.start,shard.end)}};
  });
  return {corpus,sources};
}
test('case shards cover every conversation exactly once, including uneven division',()=>{
  for(const total of [7,384])for(const count of [2,3,7]){
    const indices=Array.from({length:count},(_,index)=>shardRange(total,index,count)).flatMap(({start,end})=>Array.from({length:end-start},(_,i)=>start+i));
    assert.deepEqual(indices,Array.from({length:total},(_,i)=>i));
  }
  for(const args of [[7,-1,2],[7,2,2],[7,0,1],[7,0,8],[384,0,17],[NaN,0,2],[7,.1,2]])assert.throws(()=>shardRange(...args));
});
test('only all compatible complete shards produce a full development report',()=>{
  const {corpus,sources}=fixture();
  const report=mergeShardReports([...sources].reverse(),corpus,sha);
  assert.equal(report.status,'complete');assert.equal(report.observations.length,7);assert.equal(report.shards.length,3);
  assert.deepEqual(report.observations.map(row=>row.id),corpus.cases.map(row=>row.id));
  assert.equal(report.analysis.acceptance,'not_evaluated_requires_frozen_held_out_provenance');
  assert.throws(()=>summarizeLinkcheckReport(sources[0].report,corpus,sha));
});
test('missing, repeated, failed, stale or overlapping shards cannot be counted as a full run',()=>{
  for(const mutate of [
    sources=>sources.pop(),sources=>sources.push(sources[0]),sources=>sources[1]=sources[0],
    sources=>sources[1].report.status='partial',sources=>sources[1].report.status='failed',
    sources=>sources[1].report.shard.start--,sources=>sources[1].report.observations.pop(),
    sources=>sources[1].report.observations[0].id='dev_0',sources=>sources[1].report.provenance.client_sha256='c'.repeat(64),
    sources=>sources[1].report.provenance.config_sha256='c'.repeat(64),sources=>sources[1].report.evidence.workflow_run='5678',
    sources=>sources[1].report.scope.local_answers_stubbed=true,sources=>sources[1].sha256='bad',
    sources=>{for(const source of sources)delete source.report.evidence;},
  ]){const {corpus,sources}=fixture();mutate(sources);assert.throws(()=>mergeShardReports(sources,corpus,sha));}
});

test('file merger reads all 384 records from versioned-model filenames and retains source hashes',async()=>{
  const corpusPath=new URL('../../tests/models/privacy-v3-dev.json',import.meta.url);
  const corpus=JSON.parse(await readFile(corpusPath,'utf8')),corpusHash=await artifactHash(corpusPath);
  const created=await mkdtemp(join(tmpdir(),'nymwrap-linkcheck-merge-')),fixture=await realpath(created),output=join(fixture,'combined.json'),input=join(fixture,'parts');
  const log=console.log;
  try{
    await mkdir(input);
    const source=fixtureSource();
    source.provenance.corpus_sha256=corpusHash;
    for(let index=0;index<2;index++){
      const report=structuredClone(source),shard=shardRange(corpus.cases.length,index,2);
      report.case_count=corpus.cases.length;report.shard=shard;
      report.observations=corpus.cases.slice(shard.start,shard.end).map(c=>({...structuredClone(source.observations[0]),id:c.id,language:c.language,group:c.group,remote_turns:c.turns.length,local_reasons:c.turns.map(()=>null)}));
      await writeFile(join(input,`development-qwen2.5-7b-q4_k_m-${sha}-shard-${index}-of-2.json`),JSON.stringify(report));
    }
    console.log=()=>{};
    await main(['--input',input,'--out',output]);
    const result=JSON.parse(await readFile(output,'utf8'));
    assert.equal(result.observations.length,384);assert.equal(result.status,'complete');
    assert.ok(result.shards.every(s=>/^[a-f0-9]{64}$/.test(s.sha256)));
    await assert.rejects(()=>main(['--input',input,'--out',output]),/already_exists/);
  }finally{
    console.log=log;
    assert.equal(resolve(fixture),fixture);assert.ok(fixture.startsWith((await realpath(tmpdir()))+sep));
    await rm(fixture,{recursive:true,force:true});
  }
});
function fixtureSource(){return fixture().sources[0].report;}
