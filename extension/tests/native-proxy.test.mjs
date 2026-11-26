import {test} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {once} from 'node:events';
import {startDenyProxy} from './native/deny-proxy.mjs';

test('the native Firefox deny proxy survives peer resets and still refuses CONNECT',{timeout:5000},async()=>{
  const proxy=await startDenyProxy();
  try{
    for(let i=0;i<16;i++){
      const socket=net.createConnection({host:'127.0.0.1',port:proxy.port});
      socket.on('error',()=>{});
      // Wait until the proxy accepted this socket and sent its refusal.
      socket.once('data',()=>socket.resetAndDestroy());
      await new Promise(accept=>socket.once('close',accept));
    }
    const socket=net.createConnection({host:'127.0.0.1',port:proxy.port});
    const closed=once(socket,'close');let response='';
    socket.setEncoding('utf8');socket.on('data',chunk=>{response+=chunk;});
    socket.end('CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n');
    await closed;
    assert.match(response,/^HTTP\/1\.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n$/);
    assert.ok(proxy.resets>0,'the accepted proxy socket must actually observe a peer reset');
  }finally{await proxy.close();}
});

test('deny proxy teardown closes accepted sockets before releasing its listener',{timeout:5000},async()=>{
  const proxy=await startDenyProxy(),socket=net.createConnection({host:'127.0.0.1',port:proxy.port});
  socket.on('error',()=>{});await once(socket,'connect');
  const closed=new Promise(accept=>socket.once('close',accept));socket.resume();
  try{await proxy.close();await closed;}finally{socket.destroy();}
  const next=net.createConnection({host:'127.0.0.1',port:proxy.port});
  try{await assert.rejects(once(next,'connect'),{code:'ECONNREFUSED'});}
  finally{next.destroy();}
});
