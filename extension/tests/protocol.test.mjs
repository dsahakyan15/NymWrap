import {test} from "node:test";
import assert from "node:assert/strict";
import {reply,task} from "../dist/protocol.js";
const action={plan_hash:"a".repeat(64),stage:1,day:1,action_index:0,service:"youtube",text:"synthetic garden ideas"};
test("cover bridge rejects foreign data, malformed fields and oversized tasks",()=>{
  assert.deepEqual(task(action),action);
  for(const value of [{...action,vault:[]},{...action,service:"shell"},{...action,text:"x".repeat(4097)},{...action,day:0},{...action,text:"a\nb"}])assert.throws(()=>task(value));
  for(const result of [{kind:"shadow_history",data:[]},{kind:"tasks",tasks:[action,action]},{kind:"status",paused:false,mode:"extension",ai_web_automation:false,persona:[]},{kind:"error",code:"untrusted content with spaces"}])assert.throws(()=>reply({version:1,id:1,result}));
  assert.throws(()=>reply({version:2,id:1,result:{kind:"ack"}}));
  assert.deepEqual(reply({version:1,id:1,result:{kind:"tasks",tasks:[action]}}).result.tasks,[action]);
});
