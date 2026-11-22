import {test} from 'node:test';
import assert from 'node:assert/strict';
import {summarize,compare,renderReport,validateNerReport} from '../privacy-report.mjs';
const observation=(id,decision,attack=null)=>({id,language:'en',group:'linkage',decision,expected_local_only:false,ner_calls:1,ner_rejected:false,model_errors:0,expected_entity_characters:0,hidden_entity_characters:0,unexpected_hidden_characters:0,egress_gold_leak:false,policy_miss:false,task_terms:1,task_terms_retained:decision==='egress_candidate'?1:0,raw_attack:{valid:true,correct:true,abstained:false,unique_literal_link:true},egress_attack:attack,elapsed_ms:1,egress_turns:decision==='egress_candidate'?1:0,local_turns:decision==='local'?1:0,blocked_turns:decision==='blocked'?1:0});
const report=()=>({version:2,status:'complete',case_count:3,scope:{external_requests:false},provenance:{worker_sha256:'a'.repeat(64),client_sha256:'b'.repeat(64),corpus_sha256:'c'.repeat(64),model_sha256:'d'.repeat(64),embedding_sha256:'e'.repeat(64),platform:'win32',model:'smoke'},observations:[observation('blocked','blocked'),observation('local','local'),observation('outbound','egress_candidate',{valid:false,correct:false,abstained:false,unique_literal_link:true})]});
test('a failed or absent attacker answer never becomes evidence of privacy',()=>{
  const result=summarize(report());
  assert.deepEqual(result.outcomes,{egress_candidate:1,local:1,blocked:1});
  assert.equal(result.attacks.raw_all.attempts,3);assert.equal(result.attacks.raw_paired.attempts,1);assert.equal(result.attacks.no_outbound,2);
  assert.deepEqual(result.attacks.outbound_paired,{attempts:1,correct:0,invalid:1,abstained:0,literal_links:1});assert.deepEqual(result.findings,['outbound']);
  const partial=report();partial.observations[2].expected_entity_characters=10;partial.observations[2].hidden_entity_characters=4;assert.equal(summarize(partial).incomplete_pre_rewrite_masks,1);
});
test('diagnostic model reports cannot inject text through a numeric field or hide another model',()=>{
  const expected={model:'smoke',worker_sha256:'a'.repeat(64),model_sha256:'b'.repeat(64),corpus_sha256:'c'.repeat(64)};
  const r={corpus:'synthetic-privacy-v1',cases:16,observations:Array(16).fill({}),provenance:{...expected,client_sha256:'d'.repeat(64),models:[{sha256:expected.model_sha256}]},valid_responses:16,rejected_responses:0,model_errors:0,policy_false_negatives:0,policy_false_positives:0,unsafe_remote_cases:0,expected_entity_characters:20,hidden_entity_characters:17,unexpected_hidden_characters:0};
  assert.equal(validateNerReport(r,expected),r);
  assert.throws(()=>validateNerReport({...r,hidden_entity_characters:'<img src=x onerror=alert(1)>'},expected),/counter/);
  assert.throws(()=>validateNerReport(r,{...expected,model:'other'}),/incompatible/);
});
test('reports reject partial, incompatible, duplicated or impossible measurements',()=>{
  for(const change of [r=>r.status='running',r=>r.case_count++,r=>r.observations[1].id='blocked',r=>r.observations[0].egress_turns=1,r=>r.observations[2].egress_attack.correct=true]){const r=report();change(r);assert.throws(()=>summarize(r));}
  const a=report(),b=report();b.provenance.model='qwen2.5-7b-q4_k_m';b.provenance.model_sha256='f'.repeat(64);assert.equal(compare([a,b]).length,2);
  b.provenance.corpus_sha256='a'.repeat(64);assert.throws(()=>compare([a,b]),/incomparable/);
  assert.ok(renderReport(compare([a])).includes('Невалидные ответы: до 0, после 1'));
  assert.ok(!renderReport(compare([a]),[{browser:'<script>secret</script>',status:'observed',scope:'public'}]).includes('<script>secret</script>'));
});
