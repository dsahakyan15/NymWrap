import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {completionStats,segmentReceipt,summarizeCampaign,validateSegmentIdentity,SEGMENTS,SEGMENT_SECONDS} from '../fuzz-campaign.mjs';
const hash=value=>createHash('sha256').update(value).digest('hex');
const bytes=value=>JSON.stringify(value)+'\n';
const record=body=>({body,sha256:hash(bytes(body))});
const proof={workflow_run:'12345',attempt:'1',commit:'a'.repeat(40)};
const log=(seconds=14400,runs=123456)=>`Done ${runs} runs in ${seconds} second(s)\nstat::number_of_executed_units: ${runs}\n`;
function fixture(){
  const builds=[],receipts=[];
  for(const target of ['audit_import','ipc_frames','shield_roundtrip']){
    const build=record({version:1,target,evidence:{...proof},binary_sha256:hash(target),source_sha256:hash('sources'),lock_sha256:hash('lock'),
      initial_corpus_sha256:hash(target+'initial'),sanitizer:'address',tool:'cargo-fuzz 0.13.2',toolchain:'nightly-2026-11-20',triple:'x86_64-unknown-linux-gnu',
      preflight:{exit_code:0,requested_seconds:10,engine_seconds:11,wall_seconds:11.1,runs:456}});
    builds.push(build);let before=build.body.initial_corpus_sha256,previousHash=null;
    for(let index=0;index<SEGMENTS;index++){
      const receipt=record(segmentReceipt({build:build.body,buildHash:build.sha256,index,before,after:hash(target+index),previousHash,
        wallSeconds:14401,exitCode:0,log:log(),crashFiles:0}));
      receipts.push(receipt);before=receipt.body.corpus_after_sha256;previousHash=receipt.sha256;
    }
  }
  return {builds,receipts};
}
test('only all eighteen linked executions produce a segmented campaign result',()=>{
  const {builds,receipts}=fixture(),summary=summarizeCampaign(builds,[...receipts].reverse(),proof);
  assert.equal(summary.status,'complete_segmented_campaign');assert.equal(summary.continuous_process,false);
  assert.deepEqual(summary.targets.map(target=>target.requested_seconds),[86400,86400,86400]);
  assert.equal(summary.m6_acceptance,'not_declared_other_checklist_items_required');
  assert.throws(()=>summarizeCampaign(builds,receipts.slice(1),proof));
  assert.throws(()=>summarizeCampaign(builds,[...receipts,receipts[0]],proof));
});
test('a cancelled, early, stale, mismatched or broken-corpus execution never counts as 24h',()=>{
  const changes=[
    r=>r.receipts[4].body.status='failed',r=>r.receipts[3].body.wall_seconds=12,r=>r.receipts[3].body.engine_seconds=12,
    r=>r.receipts[3].body.runs=0,r=>r.receipts[3].body.crash_files=1,r=>r.receipts[3].body.index=2,
    r=>r.receipts[3].body.binary_sha256=hash('another binary'),r=>r.receipts[3].body.build_sha256=hash('another build'),
    r=>r.receipts[3].body.source_sha256=hash('another source'),r=>r.receipts[3].body.previous_receipt_sha256=hash('broken chain'),
    r=>r.receipts[3].body.corpus_before_sha256=hash('dropped corpus'),r=>r.receipts[3].body.evidence.attempt='2',
    r=>r.receipts[3].body.evidence.workflow_run='9999',r=>r.receipts[3].body.evidence.commit='b'.repeat(40),
    r=>r.builds[0].body.preflight.engine_seconds=undefined,r=>r.builds[0].body.preflight.exit_code=1,
    r=>r.builds[0].body.source_sha256=hash('different source'),r=>r.builds[0].body.sanitizer='none',
    r=>r.receipts[3].body.engine_seconds=999999,r=>r.receipts[3].body.runs=Number.MAX_SAFE_INTEGER,
  ];
  for(const change of changes){const data=fixture();change(data);assert.throws(()=>summarizeCampaign(data.builds,data.receipts,proof));}
  const data=fixture();assert.throws(()=>summarizeCampaign(data.builds,data.receipts,{}));
});
test('final engine statistics and independent wall time are both required',()=>{
  assert.deepEqual(completionStats(log()),{runs:123456,seconds:14400});
  assert.equal(completionStats('Done 1 runs in 14400 second(s)'),null);
  assert.equal(completionStats(log().replace('123456\n','999\n')),null);
  assert.equal(completionStats(log(1,0)),null);
  const {builds}=fixture();
  for(const override of [{exitCode:77},{wallSeconds:1},{log:log(1)},{log:''},{crashFiles:1}]){
    const result=segmentReceipt({build:builds[0].body,buildHash:builds[0].sha256,index:0,before:hash('before'),after:hash('after'),previousHash:null,
      wallSeconds:SEGMENT_SECONDS+1,exitCode:0,log:log(),crashFiles:0,...override});
    assert.equal(result.status,'failed');
  }
});
test('reusable workflow identifiers cannot escape artifact directories or skip a segment',()=>{
  for(let i=0;i<SEGMENTS;i++)validateSegmentIdentity('ipc_frames',String(i),i===0?'':String(i-1));
  for(const args of [['../core','0',''],['ipc_frames','6','5'],['ipc_frames','2','0'],['ipc_frames','0','0'],['ipc_frames','00','']])assert.throws(()=>validateSegmentIdentity(...args));
});
