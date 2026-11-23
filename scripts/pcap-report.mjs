// Packet-derived evidence, kept separate from the Rust assertions it verifies.
import {readFile,writeFile,mkdir,copyFile,lstat,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join,resolve,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {artifactHash} from './evaluation-artifacts.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),buckets=[2048,4096,8192,16384,32768];
const synthetic=JSON.parse(await readFile(new URL('../tests/leak/fixtures/pcap-canaries.json',import.meta.url),'utf8'));
const values=[...Object.values(synthetic.device),...Object.values(synthetic.detectors)];
for(const path of [...values]){const component=/(?:[\\/]Users[\\/]|\/home\/)([^\\/]+)/i.exec(path);if(component)values.push(component[1]);}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const compact=text=>text.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu,'');
export function hasCanary(bytes){
  const text=Buffer.isBuffer(bytes)?bytes.toString('utf8'):bytes;
  const views=[text];
  // Node's independent decoder checks wrapped encodings; literal representations
  // below also cover percent, JSON Unicode and character spacing.
  for(let depth=0,start=0;depth<2;depth++){
    const end=views.length;
    for(const view of views.slice(start,end))for(const token of view.replace(/\s/gu,'').match(/[A-Za-z0-9+/_-]{8,}={0,2}/g)??[]){
      const decoded=Buffer.from(token,'base64').toString('utf8');if(decoded)views.push(decoded);
      if(views.length>32768)throw Error('oversize_pcap_oracle_input');
    }
    start=end;
  }
  for(const view of views){
    const normalized=compact(view);
    for(const value of values){
      const forms=[value,Buffer.from(value).toString('base64'),Buffer.from(value).toString('base64url'),
        [...Buffer.from(value)].map(b=>'%'+b.toString(16).padStart(2,'0')).join(''),
        [...value].map(c=>'\\u'+c.codePointAt(0).toString(16).padStart(4,'0')).join('')];
      if(forms.some(form=>normalized.includes(compact(form))))return true;
    }
  }
  return false;
}
function attributes(tag){
  return Object.fromEntries([...tag.matchAll(/\b([a-z_]+)="([^"<>]*)"/g)].map(match=>[match[1],match[2]]));
}
export function httpBodies(pdml){
  if(typeof pdml!=='string'||Buffer.byteLength(pdml)>32*1024*1024||/<!DOCTYPE|<!ENTITY/i.test(pdml))throw Error('invalid_pcap_dissection');
  const records=[];
  for(const packet of pdml.match(/<packet>[\s\S]*?<\/packet>/g)??[]){
    const fields=[...packet.matchAll(/<field\b[^>]*>/g)].map(match=>attributes(match[0]));
    if(!fields.some(field=>field.name==='http.request.method'&&field.show==='POST'))continue;
    const lengths=fields.filter(field=>field.name==='http.content_length'),data=fields.filter(field=>field.name==='http.file_data');
    if(lengths.length!==1||data.length!==1||!/^\d+$/.test(lengths[0].show)||!/^([a-f0-9]{2})+$/i.test(data[0].value))throw Error('incomplete_captured_http_request');
    const body=Buffer.from(data[0].value,'hex');
    if(body.length!==Number(lengths[0].show)||!buckets.includes(body.length))throw Error('captured_length_outside_buckets');
    records.push(body);
  }
  return records;
}
export function auditCapture({pdml,client,provider,rust,health}){
  if(!rust?.complete||rust.requests!==16||!rust.different_circuits||!rust.transport_stop_failed_closed||!rust.direct_provider_connection_denied)throw Error('incomplete_rust_transport_evidence');
  if(health?.provider_alive_after_stop!==true)throw Error('missing_live_provider_control');
  const bodies=httpBodies(pdml);
  if(bodies.length!==16||provider?.requests?.length!==bodies.length)throw Error('incomplete_packet_capture');
  if(JSON.stringify([...new Set(bodies.map(body=>body.length))].sort((a,b)=>a-b))!==JSON.stringify(buckets))throw Error('missing_captured_bucket');
  for(const [index,body]of bodies.entries()){
    if(provider.requests[index].bytes!==body.length||provider.requests[index].sha256!==sha(body))throw Error('packet_and_provider_receipt_mismatch');
    const parsed=JSON.parse(body.toString('utf8'));
    if(!Array.isArray(parsed.messages)||hasCanary(body)||parsed.messages.some(message=>hasCanary(message.content)))throw Error('canary_in_os_capture');
  }
  let packets=0;
  for(const line of client.trim().split('\n').filter(Boolean)){
    const [source,target,v6source,v6target,tcp,udp]=line.split('\t');
    if(v6source||v6target)throw Error('unexpected_ipv6_packet');
    if(source!=='192.0.2.1')continue;
    const port=Number(tcp);
    if(target!=='192.0.2.2'||!tcp||udp||!Number.isInteger(port)||!(port>=5000&&port<5100||port>=7000&&port<7100))throw Error('packet_outside_tor_ports');
    packets++;
  }
  if(packets===0)throw Error('empty_netd_packet_capture');
  return {complete:true,synthetic_only:true,public_tor_used:false,requests:bodies.length,buckets,canary_leaks:0,
    netd_outbound_packets:packets,direct_provider_packets:0,dns_packets:0,different_circuits:true,transport_stop_failed_closed:true,provider_alive_after_stop:true,
    scope:'production nw-netd Tor::send, TLS and HTTP; test-only authorities and PKI; CI namespace configuration',
    production_daemon_namespace_integration:false,full_core_pipeline:false};
}
async function bounded(path,limit){
  const info=await lstat(path);if(info.isSymbolicLink()||!info.isFile()||info.size>limit)throw Error('unsafe_pcap_evidence_file');
  return readFile(path);
}
export async function main(args=process.argv.slice(2)){
  if(args.length===2&&args[0]==='--binary'){
    const lines=(await bounded(resolve(args[1]),8*1024*1024)).toString('utf8').trim().split('\n').map(line=>JSON.parse(line));
    const bins=lines.filter(value=>value.reason==='compiler-artifact'&&value.target?.name==='nw_netd'&&value.profile?.test&&value.executable);
    if(bins.length!==1||!resolve(bins[0].executable).startsWith(root+sep))throw Error('ambiguous_netd_test_binary');
    process.stdout.write(bins[0].executable);return;
  }
  if(args.length!==4||args[0]!=='--fixture'||args[2]!=='--out'||process.platform!=='linux'||process.env.GITHUB_ACTIONS!=='true')throw Error('isolated_ci_pcap_evidence_required');
  const fixture=await realpath(args[1]),temporary=await realpath(process.env.RUNNER_TEMP),output=resolve(args[3]);
  if((await lstat(args[1])).isSymbolicLink()||!fixture.startsWith(temporary+sep)||!output.startsWith(root+sep))throw Error('unsafe_pcap_evidence_directory');
  const result=auditCapture({pdml:(await bounded(join(fixture,'provider.pdml'),32*1024*1024)).toString('utf8'),
    client:(await bounded(join(fixture,'client.tsv'),8*1024*1024)).toString('utf8'),
    provider:JSON.parse(await bounded(join(fixture,'provider-receipt.json'),1024*1024)),rust:JSON.parse(await bounded(join(fixture,'rust-result.json'),65536)),
    health:JSON.parse(await bounded(join(fixture,'health-after-stop.json'),65536))});
  for(const file of ['client.pcap','provider.pcap'])if(hasCanary(await bounded(join(fixture,file),64*1024*1024)))throw Error('canary_in_raw_os_capture');
  await mkdir(output,{recursive:true});if((await lstat(output)).isSymbolicLink()||!(await realpath(output)).startsWith((await realpath(root))+sep))throw Error('unsafe_pcap_output_directory');
  const files=['client.pcap','provider.pcap','provider.pdml','client.tsv','provider-receipt.json','rust-result.json','health-after-stop.json','provider-ca.pem','tls.keys'];
  const hashes={};
  for(const file of files){await bounded(join(fixture,file),64*1024*1024);hashes[file]=await artifactHash(join(fixture,file));await copyFile(join(fixture,file),join(output,file));}
  const report={version:1,...result,hashes,workflow_run:process.env.GITHUB_RUN_ID,commit:process.env.GITHUB_SHA};
  await writeFile(join(output,'report.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(result));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
