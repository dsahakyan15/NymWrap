import {test} from 'node:test';
import assert from 'node:assert/strict';
import {compareProtocol} from '../compare-protocol.mjs';
test('cross-platform protocol evidence needs every actual capture and rejects any byte difference',()=>{
  const data=()=>Object.fromEntries(['Windows','Linux','macOS'].map(os=>[os,{'provider-http.hex':'010203\n','provider-tls.hex':'040506\n'}]));
  assert.equal(compareProtocol(data()).complete,true);
  for(const change of [v=>delete v.Windows,v=>delete v.Linux['provider-http.hex'],v=>v.macOS['provider-tls.hex']='040507\n',v=>v.Windows['provider-tls.hex']='']){
    const value=data();change(value);assert.throws(()=>compareProtocol(value));
  }
});
