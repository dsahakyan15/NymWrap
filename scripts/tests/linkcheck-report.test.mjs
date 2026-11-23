import {test} from 'node:test';
import assert from 'node:assert/strict';
import {summarizeLinkcheckReport,checkDevelopmentReport} from '../linkcheck-report.mjs';
const sha='a'.repeat(64);
function fixture(){
  const corpus={version:3,partition:'development',synthetic_only:true,candidates:64,utility_scope:'integer arithmetic, not general answer quality',cases:[{id:'dev_0000',language:'hy',group:'linkage_multiturn',turns:[{},{}]}]};
  const row={id:'dev_0000',language:'hy',group:'linkage_multiturn',remote_turns:2,local_turns:0,blocked_turns:0,canary_leaks:0,error:false,utility:true,
    attack:{valid:true,top1_correct:false},raw_attack:{valid:true,top1_correct:true},literal_attack:{valid:true,top1_correct:false},raw_literal_attack:{valid:true,top1_correct:true},
    calls:{ner:2,canonicalize:2,generalize:1,embeddings:4,answers:0,errors:0,linkage_ranks:Array.from({length:2},()=>({candidates:65,rank_min:65,rank_max:65,user_score:0,best_decoy_score:1000000,background_score:1000000,risky:false}))},local_reasons:[null,null],elapsed_ms:12};
  const report={version:3,status:'complete',partition:'development',case_count:1,scope:{external_requests:false,local_answers_stubbed:false,provider_answers:'real local model, simulated provider'},
    provenance:Object.fromEntries(['corpus_sha256','client_sha256','defender_worker_sha256','attacker_worker_sha256','model_sha256','attacker_model_sha256','embedding_sha256','config_sha256','evaluator_script_sha256','report_script_sha256','statistics_sha256','shard_script_sha256'].map(k=>[k,sha])),observations:[row]};
  return {corpus,report,row};
}
test('real-answer measurement reports both attackers and never labels development held-out acceptance',()=>{
  const {corpus,report,row}=fixture();
  let result=summarizeLinkcheckReport(report,corpus,sha);
  assert.equal(result.acceptance,'not_evaluated_requires_frozen_held_out_provenance');
  assert.equal(result.attackers.model.all.useful_fraction,1);
  assert.equal(result.attackers.model.all.top1.trials,1);
  row.literal_attack.top1_correct=true;
  result=summarizeLinkcheckReport(report,corpus,sha);
  assert.equal(result.attackers.model.all.chance_gate,'passes_test');
  assert.equal(result.attackers.literal.all.chance_gate,'failed');
  assert.deepEqual(result.review_cases,['dev_0000']);
  assert.deepEqual(result.canary_findings,[]);
});
test('partial progress, missing attacker pairs, stubbed answers and incompatible corpus cannot be counted',()=>{
  for(const change of [
    r=>r.status='partial',r=>r.case_count++,r=>r.partition='held_out',r=>r.scope.local_answers_stubbed=true,
    r=>r.scope.external_requests=true,r=>delete r.provenance.model_sha256,r=>r.observations[0].id='other',
    r=>r.observations[0].local_reasons=[],r=>r.observations[0].calls.errors='<script>',r=>r.observations[0].literal_attack=undefined,
    r=>r.observations[0].remote_turns=3,r=>r.observations[0].calls.linkage_ranks=[],
  ]){
    const {report,corpus}=fixture();change(report);assert.throws(()=>summarizeLinkcheckReport(report,corpus,sha));
  }
  const {report,corpus,row}=fixture();
  row.attack={valid:false,top1_correct:false};
  assert.equal(summarizeLinkcheckReport(report,corpus,sha).attackers.model.all.chance_gate,'invalid_attacker');
  row.remote_turns=0;row.local_turns=2;row.attack=null;row.literal_attack=null;
  assert.equal(summarizeLinkcheckReport(report,corpus,sha).attackers.model.all.chance_gate,'unmeasured');
});
test('development gate needs calibrated attacks in every private group and language, with zero canaries',()=>{
  function complete(){
    const {report,corpus,row}=fixture();
    report.observations=[];corpus.cases=[];report.case_count=360;
    const groups=['public_control','linkage','linkage_multiturn','hard_data','injection'];
    for(let i=0;i<360;i++){
      const id='dev_'+i,language=['en','ru','hy'][i%3],group=groups[Math.floor(i/3)%5];
      const value={...structuredClone(row),id,language,group,remote_turns:1,local_reasons:[null]};
      report.observations.push(value);corpus.cases.push({id,language,group,turns:[{}]});
    }
    return {report,corpus};
  }
  const good=complete();
  assert.equal(checkDevelopmentReport(good.report,good.corpus,sha).acceptance,'not_evaluated_requires_frozen_held_out_provenance');
  for(const change of [
    rows=>rows[0].canary_leaks++,
    rows=>{for(const r of rows)if(r.group==='linkage')r.raw_attack.top1_correct=false;},
    rows=>{for(const r of rows)if(r.language==='hy'&&r.group==='linkage')r.raw_attack.top1_correct=false;},
    rows=>{for(const r of rows)if(r.language==='hy'){r.remote_turns=0;r.local_turns=1;r.attack=null;r.literal_attack=null;}},
  ]){
    const {report,corpus}=complete();change(report.observations);assert.throws(()=>checkDevelopmentReport(report,corpus,sha));
  }
});
