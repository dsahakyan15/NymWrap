import {test} from 'node:test';
import assert from 'node:assert/strict';
import {dnsReply} from '../ci/tor-provider.mjs';
function question(name,type=1){
  const header=Buffer.from('123401000001000000000000','hex');
  return Buffer.concat([header,...name.split('.').map(label=>Buffer.concat([Buffer.from([label.length]),Buffer.from(label)])),Buffer.from([0,0,type,0,1])]);
}
test('offline Tor DNS resolves only the synthetic provider, without external DNS',()=>{
  const known=dnsReply(question('api.example.test'));
  assert.equal(known.readUInt16BE(0),0x1234);assert.equal(known.readUInt16BE(6),1);
  assert.equal(known.subarray(-4).toString('hex'),'c0000202');
  const absent=dnsReply(question('unrelated.invalid'));assert.equal(absent.readUInt16BE(2)&15,3);
  const ipv6=dnsReply(question('api.example.test',28));assert.equal(ipv6.readUInt16BE(6),0);assert.equal(ipv6.readUInt16BE(2)&15,0);
  for(const malformed of [Buffer.alloc(0),Buffer.alloc(513),question('api.example.test').subarray(0,15),Buffer.from('123401000002000000000000','hex')])assert.equal(dnsReply(malformed),null);
});
