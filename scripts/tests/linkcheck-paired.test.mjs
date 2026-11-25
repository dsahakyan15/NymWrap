import {test} from 'node:test';
import assert from 'node:assert/strict';
import {pairedLinkcheck} from '../linkcheck-paired-report.mjs';
test('paired accuracy uses the same outgoing private cases; L0, controls and invalid raw attacks cannot improve it',()=>{
  const row=(id,extra={})=>({id,language:'ru',group:'linkage',remote_turns:1,raw_attack:{valid:true,top1_correct:true},attack:{valid:true,top1_correct:false},raw_literal_attack:{valid:true,top1_correct:true},literal_attack:{valid:true,top1_correct:false},...extra});
  const rows=[row('one'),row('two',{attack:{valid:true,top1_correct:true}}),row('local',{remote_turns:0}),row('public',{group:'public_control'}),row('invalid',{raw_attack:{valid:false,top1_correct:false}})];
  const paired=pairedLinkcheck(rows).model.ru;
  assert.deepEqual(paired.case_ids,['one','two']);assert.equal(paired.unmeasured_pairs,1);
  assert.equal(paired.before.trials,paired.after.trials);assert.equal(paired.before.correct,2);assert.equal(paired.after.correct,1);
  assert.equal(pairedLinkcheck(rows).model.en.paired,0);
});
