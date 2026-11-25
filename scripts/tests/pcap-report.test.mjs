import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {auditCapture,hasCanary} from '../pcap-report.mjs';
function capture(content='Explain pottery.',count=16){
  const bodies=Array.from({length:count},(_,i)=>{
    const text=JSON.stringify({model:'synthetic',max_tokens:16,temperature:0,stream:false,messages:[{role:'user',content:content+' '+i}]});return Buffer.from(text.padEnd([2048,4096,8192,16384,32768][i%5]));
  });
  return {pdml:'<pdml>'+bodies.map(body=>`<packet><field name="http.request.method" show="POST"/><field name="http.content_length" show="${body.length}"/><field name="http.file_data" value="${body.toString('hex')}"/></packet>`).join('')+'</pdml>',
    client:'192.0.2.1\t192.0.2.2\t\t\t5000\t\n192.0.2.2\t192.0.2.1\t\t\t49152\t\n',
    provider:{requests:bodies.map(body=>({bytes:body.length,sha256:createHash('sha256').update(body).digest('hex')}))},
    health:{provider_alive_after_stop:true},rust:{complete:true,requests:count,different_circuits:true,transport_stop_failed_closed:true,direct_provider_connection_denied:true}};
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

function processCapture(count=16){
  const data=capture('Explain pottery.',count);
  Object.assign(data.rust,{production_launcher:true,authenticated_dispatcher:true,core_socket_denied:true,
    core_namespace:'net:[101]',worker_namespace:'net:[102]',host_namespace:'net:[103]'});
  data.daemon=Object.fromEntries(['complete','actual_production_daemon','separate_namespaces','core_namespace_unreachable','all_threads_dropped',
    'api_inherits_core_namespace','netd_in_transport_namespace','parent_eof_stops_children','invalid_setup_rejected'].map(key=>[key,true]));
  data.circuits=Object.fromEntries(Array.from({length:count},(_,index)=>[index.toString(16).padStart(32,'0'),`circuit-${index}`]));
  return data;
}
test('process pcap requires actual daemon, distinct namespaces, explicit error and observed circuit IDs',()=>{
  const report=auditCapture(processCapture());assert.equal(report.production_daemon_namespace_integration,true);assert.equal(report.full_core_pipeline,false);
  for(const change of [data=>delete data.daemon,data=>data.daemon.all_threads_dropped=false,data=>data.daemon.parent_eof_stops_children=false,
    data=>data.rust.worker_namespace=data.rust.core_namespace,data=>data.rust.core_socket_denied=false,data=>data.rust.authenticated_dispatcher=false,
    data=>delete data.circuits,data=>data.circuits['0'.repeat(31)+'1']=data.circuits['0'.repeat(32)],data=>delete data.circuits['0'.repeat(32)]]){
    const data=processCapture();change(data);assert.throws(()=>auditCapture(data));
  }
});

function coverCapture(){
  const data=processCapture(100);let index=16;
  data.week={version:1,simulated_days:7,production_workspace:true,
    scenarios:[['poisson',3,14],['poisson',5,10],['constant',3,14],['constant',5,10]].map(([mode,max_requests_per_day,max_spend_microusd])=>({
      mode,max_requests_per_day,max_spend_microusd,cost_upper_bound_microusd:3,mean_interval_s:60,
      days:Array.from({length:7},(_,day)=>({day,blocked_probes:2,usage:{day,requests:3,reserved_microusd:9},
        events:Array.from({length:3},(_,slot)=>{
          const packet_index=index++,receipt=data.provider.requests[packet_index];
          return {packet_index,conversation:packet_index.toString(16).padStart(32,'0'),at:day*86400+(slot+1)*60,
            kind:(slot+day)%2===0?'real':'decoy',...receipt,usage:{day,requests:slot+1,reserved_microusd:3*(slot+1)}};
        })}))
    }))};
  return data;
}
test('M3 counts packet-matched real and decoy sends over seven days in both modes and both limits',()=>{
  const report=auditCapture(coverCapture());
  assert.equal(report.requests,100);assert.equal(report.cover.requests,84);
  assert.equal(report.cover.real_requests,44);assert.equal(report.cover.decoy_requests,40);
  assert.equal(report.cover.days.length,28);assert.equal(report.cover.budget_exhaustion_probes,56);
  assert.equal(report.cover.wall_clock_packet_cadence_verified,false);
});
test('M3 rejects missing days, altered caps, extra packets, accounting resets and out-of-slot sends',()=>{
  const changes=[
    data=>data.week.simulated_days=6,data=>data.week.production_workspace=false,data=>data.week.scenarios.pop(),
    data=>data.week.scenarios[0].max_requests_per_day=99,data=>data.week.scenarios[1].max_spend_microusd=99,
    data=>data.week.scenarios[0].days.pop(),data=>data.week.scenarios[0].days[1].day=0,
    data=>data.week.scenarios[0].days[0].blocked_probes=0,data=>data.week.scenarios[0].days[0].events.pop(),
    data=>data.week.scenarios[0].days[0].events[1].usage.requests=1,
    data=>data.week.scenarios[0].days[0].events[1].usage.reserved_microusd=99,
    data=>data.week.scenarios[0].days[0].usage.requests=4,
    data=>data.week.scenarios[0].days[0].events[0].kind='decoy',
    data=>data.week.scenarios[0].days[0].events[0].packet_index=17,
    data=>data.week.scenarios[0].days[0].events[0].sha256='bad',
    data=>data.week.scenarios[0].days[0].events[0].at=-1,
    data=>data.week.scenarios[0].days[0].events[0].at=86400,
    data=>data.week.scenarios[2].days[0].events[1].at=61,
    data=>data.week.scenarios[2].days[0].events[0].at=0,
    data=>data.provider.requests.push(data.provider.requests[0]),
    data=>data.pdml=data.pdml.replace('</pdml>',data.pdml.match(/<packet>[\s\S]*?<\/packet>/)[0]+'</pdml>'),
  ];
  for(const change of changes){const data=coverCapture();change(data);assert.throws(()=>auditCapture(data));}
});
