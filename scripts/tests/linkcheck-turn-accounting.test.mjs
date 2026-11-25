import {test} from 'node:test';
import assert from 'node:assert/strict';
import {phaseMetrics} from '../linkcheck-turn-accounting.mjs';
test('disclosure followed by a provider error is one attempted turn, with a refusal and a remaining unstarted turn',()=>{
  const corpus={cases:[{id:'one',language:'ru',turns:[{},{}]}]};
  const report={observations:[{id:'one',language:'ru',remote_turns:1,local_turns:0,blocked_turns:1,local_reasons:[]}]};
  const result=phaseMetrics(report,corpus);
  assert.equal(result.attempted_turns,1);assert.equal(result.unattempted_turns,1);
  assert.equal(result.remote_turns,1);assert.equal(result.refused_turns,1);
  assert.equal(result.disclosed_without_successful_remote_reply,1);
});
test('two completed replies and an exact known-case subset cannot be miscounted by overlapping disclosure counters',()=>{
  const corpus={cases:[{id:'two',language:'en',turns:[{},{}]}]};
  const row={id:'two',language:'en',remote_turns:1,local_turns:1,blocked_turns:0,local_reasons:[null,null]};
  const result=phaseMetrics({observations:[row]},corpus);
  assert.equal(result.unattempted_turns,0);assert.equal(result.successful_reply_turns,2);
  assert.equal(result.successful_remote_reply_turns,1);assert.equal(result.disclosed_without_successful_remote_reply,0);
  for(const bad of [{...row,local_turns:3},{...row,blocked_turns:1},{...row,remote_turns:0}])assert.throws(()=>phaseMetrics({observations:[bad]},corpus));
  assert.throws(()=>phaseMetrics({observations:[row]}, {...corpus,cases:[...corpus.cases,{id:'missing',turns:[]}]}));
});
