import {test} from 'node:test';
import assert from 'node:assert/strict';
import {recoveryPartition} from '../linkcheck-recovery.mjs';
test('host restart never retries any position of a claimed chunk, including its unmeasured suffix',()=>{
  const chunks=[{index:0,start:0,end:3},{index:1,start:3,end:6},{index:2,start:6,end:9}],corpus={cases:Array.from({length:9},(_,i)=>({id:`case-${i}`}))};
  const claimed=new Map([[0,{start:0,end:3,status:'complete',observations:[{},{},{}]}],[1,{start:3,end:6,status:'running',observations:[{}]}]]);
  const plan=recoveryPartition(chunks,claimed,corpus);
  assert.deepEqual(plan.pending,[chunks[2]]);
  assert.deepEqual(plan.unmeasured.map(r=>r.id),['case-4','case-5']);
  assert.ok(plan.unmeasured.every(r=>r.possible_egress==='unknown'));
  claimed.get(1).status='failed';assert.deepEqual(recoveryPartition(chunks,claimed,corpus),plan);
});
test('host restart rejects a complete fragment that would conceal missing observations',()=>{
  assert.throws(()=>recoveryPartition([{index:0,start:0,end:2}],new Map([[0,{start:0,end:2,status:'complete',observations:[{}]}]]),{cases:[{id:'a'},{id:'b'}]}),/restart_fragment_changed/);
});
