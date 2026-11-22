import {test} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {Marionette} from './browser/helpers/marionette.mjs';
const frame=value=>{const bytes=Buffer.from(JSON.stringify(value));return Buffer.concat([Buffer.from(bytes.length+':'),bytes]);};
async function fixture(run){
  let peer;const server=net.createServer(socket=>{peer=socket;socket.write(frame({applicationType:'gecko',marionetteProtocol:3}));});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));let client;
  try{client=await Marionette.connect(server.address().port);await run(client,()=>peer);}finally{client?.close();peer?.destroy();await new Promise(r=>server.close(r));}
}
test('Marionette correlates fragmented UTF-8 frames and preserves a null script result',()=>fixture(async(client,peer)=>{
  peer().once('data',()=>{const bytes=frame([1,1,null,{value:'Խեցեգործություն'}]);peer().write(bytes.subarray(0,23));setImmediate(()=>peer().write(bytes.subarray(23)));});
  assert.equal(await client.script('return "synthetic";'),'Խեցեգործություն');
  peer().once('data',()=>peer().write(frame([1,2,null,{value:null}])));assert.equal(await client.script('return null;'),null);
}));
test('wrong replies, oversized frames and a lost command fail without replay',async()=>{
  for(const [reply,error] of [[frame([1,2,null,{}]),/wrong_reply/],[Buffer.from('99999999:'),/oversize/],[null,/command_timeout/]])await fixture(async(client,peer)=>{
    let calls=0;peer().on('data',()=>{calls++;if(reply)peer().write(reply);});
    await assert.rejects(client.call('Synthetic:NoRetry',{},50),error);assert.equal(calls,1);
  });
});
test('a connected endpoint without a Marionette greeting has a bounded lifetime',async()=>{
  let peer;const server=net.createServer(socket=>peer=socket);await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const socket=net.createConnection({host:'127.0.0.1',port:server.address().port}),client=new Marionette(socket,30);
  try{await assert.rejects(client.hello,/greeting_timeout/);}finally{client.close();peer?.destroy();await new Promise(r=>server.close(r));}
});
