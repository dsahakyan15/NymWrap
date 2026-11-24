import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {auditCapture,hasCanary} from '../pcap-report.mjs';
function capture(content='Explain pottery.'){
  const bodies=Array.from({length:16},(_,i)=>{
    const text=JSON.stringify({messages:[{role:'user',content}]});return Buffer.from(text.padEnd([2048,4096,8192,16384,32768][i%5]));
  });
  return {pdml:'<pdml>'+bodies.map(body=>`<packet><field name="http.request.method" show="POST"/><field name="http.content_length" show="${body.length}"/><field name="http.file_data" value="${body.toString('hex')}"/></packet>`).join('')+'</pdml>',
    client:'192.0.2.1\t192.0.2.2\t\t\t5000\t\n192.0.2.2\t192.0.2.1\t\t\t49152\t\n',
    provider:{requests:bodies.map(body=>({bytes:body.length,sha256:createHash('sha256').update(body).digest('hex')}))},
    health:{provider_alive_after_stop:true},rust:{complete:true,requests:16,different_circuits:true,transport_stop_failed_closed:true,direct_provider_connection_denied:true}};
}
test('packet evidence needs complete nonempty Tor flows and every byte bucket',()=>{
  const result=auditCapture(capture());assert.equal(result.requests,16);assert.equal(result.canary_leaks,0);
  assert.equal(result.production_daemon_namespace_integration,false);assert.equal(result.full_core_pipeline,false);
  for(const change of [data=>data.client='',data=>data.pdml='<pdml/>',data=>data.rust.complete=false,data=>data.health.provider_alive_after_stop=false,
    data=>data.client+='192.0.2.1\t192.0.2.2\t\t\t443\t\n',data=>data.client+='192.0.2.1\t192.0.2.2\t\t\t\t53\n',
    data=>data.provider.requests[0].sha256='bad',data=>data.pdml=data.pdml.replace('show="2048"','show="2049"')]){
    const data=capture();change(data);assert.throws(()=>auditCapture(data));
  }
});
test('independent packet oracle detects raw, encoded, wrapped and partial path canaries',()=>{
  for(const value of ['SYNTHETIC_PCAP_SSID_62491','synthetic-pcap-path',
    Buffer.from('/home/synthetic-pcap-path/project').toString('base64'),
    [...'SYNTHETIC_PCAP_SSID_62491'].map(c=>'\\u'+c.codePointAt(0).toString(16).padStart(4,'0')).join('')]){
    assert.equal(hasCanary(value),true);assert.throws(()=>auditCapture(capture(value)),/canary_in_os_capture/);
  }
  assert.equal(hasCanary('ordinary public pottery instructions'),false);
});

test('IPv4-only packet evidence rejects kernel IPv6 router solicitations',()=>{
  const data=capture();data.client+='\t\tfe80::1\tff02::2\t\t\n';
  assert.throws(()=>auditCapture(data),/unexpected_ipv6_packet/);
});
