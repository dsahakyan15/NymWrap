import {test} from "node:test";
import assert from "node:assert/strict";
import {NativeBridge} from "../dist/native.js";
function setup(){
  const sent=[];let receiver,disconnected,closes=0;
  globalThis.chrome={runtime:{connectNative(name){assert.equal(name,"org.nymwrap.drift");return{postMessage(v){sent.push(v);},disconnect(){closes++;},onMessage:{addListener(fn){receiver=fn;}},onDisconnect:{addListener(fn){disconnected=fn;}}};}}};
  return{sent,receive:v=>receiver(v),disconnect:()=>disconnected(),get closes(){return closes;}};
}
test("native bridge correlates replies and closes on an unrecognized data channel",async()=>{
  const port=setup(),bridge=new NativeBridge();bridge.connect();
  const pending=bridge.request({kind:"status"});
  assert.deepEqual(port.sent,[{version:1,id:1,command:{kind:"status"}}]);
  port.receive({version:1,id:1,result:{kind:"status",paused:false,mode:"assisted",ai_web_automation:false}});
  assert.equal((await pending).kind,"status");
  const rejected=assert.rejects(bridge.request({kind:"tasks"}),/bridge_disconnected/);
  port.receive({version:1,id:2,result:{kind:"vault",data:"synthetic untrusted secret"}});
  await rejected;assert.equal(port.closes,1);await assert.rejects(bridge.request({kind:"status"}),/bridge_disconnected/);
});
test("disconnect rejects every pending call without replaying it",async()=>{
  const port=setup(),bridge=new NativeBridge();bridge.connect();
  const first=assert.rejects(bridge.request({kind:"tasks"}),/bridge_disconnected/);
  const second=assert.rejects(bridge.request({kind:"pause",paused:true}),/bridge_disconnected/);
  port.disconnect();await Promise.all([first,second]);assert.equal(port.sent.length,2);
});
