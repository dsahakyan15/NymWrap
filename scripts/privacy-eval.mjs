// Opt-in, offline evaluation of the fixed synthetic corpus. Never opens a workspace.
import {spawn} from 'node:child_process';
import {mkdir,mkdtemp,readFile,writeFile,realpath,lstat,rm} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {artifactHash as hash,pinnedBinary,cachedBinary,verifyEmbeddedCorpus} from './evaluation-artifacts.mjs';
import {resolve,join,sep,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import net from 'node:net';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const args=new Set();let id='smoke';
const raw=process.argv.slice(2);for(let i=0;i<raw.length;i++){
  if(raw[i]==='--model')id=raw[++i];else if(['--release','--root-release','--report-only','--benchmark-worker'].includes(raw[i]))args.add(raw[i]);else throw Error('invalid_privacy_eval_options');
}
const catalog=JSON.parse(await readFile(new URL('./privacy-models.json',import.meta.url),'utf8'));
if(id!=='smoke'&&!Object.hasOwn(catalog,id))throw Error('invalid_privacy_model');
const suffix=process.platform==='win32'?'.exe':'';
const reports=resolve(root,'target/privacy-eval');await mkdir(reports,{recursive:true});
const benchmark=args.has('--benchmark-worker')?JSON.parse(await readFile(join(reports,'pipeline-smoke.json'),'utf8')):null;
const worker=benchmark?await cachedBinary(reports,'nw-llmd',benchmark.provenance?.worker_sha256):await pinnedBinary(reports,resolve(root,args.has('--root-release')?'target/release':args.has('--release')?'app/src-tauri/target/release':'target/debug',`nw-llmd${suffix}`),'nw-llmd');
const client=await pinnedBinary(reports,resolve(root,'target/debug/examples',`privacy_eval${suffix}`),'privacy_eval');
await verifyEmbeddedCorpus(client,resolve(root,'tests/models/privacy-v1.json'));
const fixture=await mkdtemp(join(reports,'run-'));
const endpoint=process.platform==='win32'?`nymwrap-privacy-eval-${process.pid}-${randomBytes(8).toString('hex')}`:join(fixture,'llm.sock');
const models=[
  ['qwen2.5-0.5b-instruct-q4_k_m.gguf','74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db'],
  ['nomic-embed-text-v1.5.Q4_K_M.gguf','d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac'],
];
if(id!=='smoke'){
  const receipt=JSON.parse(await readFile(resolve(root,'target/test-models',id+'.merged.json'),'utf8'));
  if(receipt.file!==catalog[id].output||!/^[a-f0-9]{64}$/.test(receipt.sha256))throw Error('invalid_model_receipt');
  models[0]=[receipt.file,receipt.sha256];
}
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const ready=()=>new Promise(resolve=>{
  const socket=net.createConnection(process.platform==='win32'?`\\\\.\\pipe\\${endpoint}`:endpoint);
  socket.once('connect',()=>{socket.destroy();resolve(true);});socket.once('error',()=>resolve(false));
});
let model,evaluation;
try{
  // The child validates the pinned GGUF hashes before publishing its private endpoint.
  const provenance={model:id,worker_sha256:await hash(worker),client_sha256:await hash(client),corpus_sha256:await hash(resolve(root,'tests/models/privacy-v1.json')),models:models.map(([name,sha256])=>({name,sha256})),platform:process.platform};
  model=spawn(worker,['--socket',endpoint,'--model',resolve(root,'target/test-models',models[0][0]),'--sha256',models[0][1],'--embed-model',resolve(root,'target/test-models',models[1][0]),'--embed-sha256',models[1][1],'--parent-stdio'],{cwd:root,windowsHide:true,stdio:['pipe','ignore','ignore']});
  let workerError=false;model.on('error',()=>{workerError=true;});
  const startupDeadline=Date.now()+120000;
  while(!await ready()){
    if(workerError||model.exitCode!==null||Date.now()>=startupDeadline)throw Error('privacy_worker_start_failed');
    await delay(100);
  }
  const output=await new Promise((accept,reject)=>{
    evaluation=spawn(client,[endpoint],{cwd:root,windowsHide:true,stdio:['ignore','pipe','ignore']});
    let bytes=Buffer.alloc(0);
    const timeout=setTimeout(()=>{evaluation.kill();reject(Error('privacy_evaluation_timeout'));},60*60*1000);
    evaluation.stdout.on('data',chunk=>{
      bytes=Buffer.concat([bytes,chunk]);
      if(bytes.length>256*1024){evaluation.kill();reject(Error('privacy_evaluation_oversize'));}
    });
    evaluation.once('error',error=>{clearTimeout(timeout);reject(error);});
    evaluation.once('exit',code=>{clearTimeout(timeout);if(code!==0)reject(Error('privacy_evaluation_failed'));else accept(bytes.toString('utf8'));});
  });
  const report=JSON.parse(output);
  report.provenance=provenance;
  await writeFile(join(reports,'ner-'+id+'.json'),JSON.stringify(report,null,2)+'\n');
  await writeFile(join(reports,'latest.json'),JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify({report:'target/privacy-eval/latest.json',cases:report.cases,valid:report.valid_responses,rejected:report.rejected_responses,model_errors:report.model_errors,unsafe_remote_cases:report.unsafe_remote_cases,expected_entity_characters:report.expected_entity_characters,hidden_entity_characters:report.hidden_entity_characters,unexpected_hidden_characters:report.unexpected_hidden_characters}));
  if(!args.has('--report-only')&&(report.unsafe_remote_cases||report.model_errors||report.rejected_responses))process.exitCode=1;
}finally{
  if(evaluation&&evaluation.exitCode===null&&!evaluation.killed)evaluation.kill();
  if(model){
    model.stdin.on('error',()=>{});model.stdin.end();
    for(let i=0;i<50&&model.exitCode===null&&!model.killed;i++)await delay(100);
    if(model.exitCode===null&&!model.killed)model.kill();
    if(model.exitCode===null)await new Promise(resolve=>{model.once('exit',resolve);setTimeout(resolve,5000).unref();});
  }
  const actual=await realpath(fixture),base=await realpath(reports),metadata=await lstat(fixture);
  const normalized=value=>process.platform==='win32'?value.toLowerCase():value;
  if(metadata.isSymbolicLink()||!normalized(actual).startsWith(normalized(base+sep)))throw Error('unsafe_privacy_fixture_cleanup');
  await rm(fixture,{recursive:true,force:true});
}
