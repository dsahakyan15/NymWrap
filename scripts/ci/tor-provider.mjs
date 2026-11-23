// Synthetic DNS/HTTPS endpoints for an offline, CI-owned Tor network.
import https from 'node:https';
import dgram from 'node:dgram';
import {readFile,writeFile,rename,lstat,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
const buckets=[2048,4096,8192,16384,32768];
export function dnsReply(query){
  if(query.length<12||query.length>512||query.readUInt16BE(4)!==1||(query.readUInt16BE(2)&0xf800)!==0)return null;
  const labels=[];let at=12;
  while(at<query.length&&query[at]){
    const length=query[at++];if(length>63||at+length>=query.length)return null;
    labels.push(query.subarray(at,at+length).toString('ascii'));at+=length;
  }
  if(at+5!==query.length)return null;
  at++;const type=query.readUInt16BE(at),family=query.readUInt16BE(at+2);
  if(family!==1)return null;
  const known=labels.join('.').toLowerCase()==='api.example.test',answer=known&&type===1;
  const header=Buffer.alloc(12);header.writeUInt16BE(query.readUInt16BE(0));header.writeUInt16BE(known?0x8180:0x8183,2);
  header.writeUInt16BE(1,4);header.writeUInt16BE(answer?1:0,6);
  return Buffer.concat([header,query.subarray(12),...(answer?[Buffer.from('c00c000100010000003c0004c0000202','hex')]:[])]);
}
export async function serve(fixture){
  if(process.platform!=='linux'||process.env.GITHUB_ACTIONS!=='true')throw Error('isolated_ci_fixture_required');
  const actual=await realpath(fixture),base=await realpath(process.env.RUNNER_TEMP);
  if((await lstat(fixture)).isSymbolicLink()||!actual.startsWith(base+sep))throw Error('unsafe_tor_provider_fixture');
  const requests=[];let writes=Promise.resolve();
  const save=()=>{const text=JSON.stringify({requests})+'\n';writes=writes.then(async()=>{
    const path=join(actual,'provider-receipt.json');await writeFile(path+'.part',text);await rename(path+'.part',path);
  });return writes;};
  const server=https.createServer({key:await readFile(join(actual,'provider-key.pem')),cert:await readFile(join(actual,'provider-cert.pem')),minVersion:'TLSv1.2'},(request,response)=>{
    const chunks=[];let size=0;
    request.on('data',chunk=>{size+=chunk.length;if(size>32768)request.destroy();else chunks.push(chunk);});
    request.on('error',()=>{});
    request.on('end',async()=>{
      try{
        const body=Buffer.concat(chunks);
        const names=Object.keys(request.headers).sort(),expected=['host','content-type','accept','accept-encoding','connection','authorization','content-length'].sort();
        if(request.method!=='POST'||request.url!=='/v1/chat/completions'||request.headers.host!=='api.example.test'||
          JSON.stringify(names)!==JSON.stringify(expected)||request.headers['content-type']!=='application/json'||
          request.headers['accept-encoding']!=='identity'||request.headers.connection!=='close'||
          Number(request.headers['content-length'])!==body.length||!buckets.includes(body.length))throw Error('invalid_fixture_request');
        const parsed=JSON.parse(body.toString('utf8'));
        if(parsed.stream!==false||parsed.temperature!==0||!Array.isArray(parsed.messages))throw Error('invalid_fixture_body');
        requests.push({bytes:body.length,sha256:createHash('sha256').update(body).digest('hex')});await save();
        const reply=JSON.stringify({choices:[{message:{role:'assistant',content:'synthetic safe answer'}}]});
        response.writeHead(200,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(reply),'Connection':'close'});response.end(reply);
      }catch{response.writeHead(400,{'Connection':'close'});response.end();}
    });
  });
  server.on('tlsClientError',(_error,socket)=>socket.destroy());
  const dns=dgram.createSocket('udp4');dns.on('message',(query,peer)=>{const reply=dnsReply(query);if(reply)dns.send(reply,peer.port,peer.address);});
  await Promise.all([new Promise((accept,reject)=>{server.once('error',reject);server.listen(443,'192.0.2.2',accept);}),
    new Promise((accept,reject)=>{dns.once('error',reject);dns.bind(53,'127.0.0.1',accept);})]);
  await save();await writeFile(join(actual,'provider-ready'),'ready');
  process.once('SIGTERM',()=>{server.closeAllConnections();server.close();dns.close();void writes.finally(()=>process.exit(0));});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length!==3)throw Error('usage_ci_tor_provider_fixture');await serve(resolve(process.argv[2]));
}
