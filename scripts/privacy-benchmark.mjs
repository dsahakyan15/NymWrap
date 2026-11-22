// Local synthetic benchmark: no workspace, provider credential, Tor or external model request.
import {spawn} from 'node:child_process';
import {mkdir,mkdtemp,readFile,writeFile,rename,realpath,lstat,rm} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {artifactHash as hash,pinnedBinary,verifyEmbeddedCorpus} from './evaluation-artifacts.mjs';
import {resolve,join,sep,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import net from 'node:net';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),args=process.argv.slice(2);
let id='smoke',limit=Infinity,resume=false;
for(let i=0;i<args.length;i++){
  if(args[i]==='--model')id=args[++i];else if(args[i]==='--limit')limit=Number(args[++i]);else if(args[i]==='--resume')resume=true;else throw Error('unknown_benchmark_option');
}
const catalog=JSON.parse(await readFile(new URL('./privacy-models.json',import.meta.url),'utf8'));
if(id!=='smoke'&&!Object.hasOwn(catalog,id)||limit!==Infinity&&(!Number.isSafeInteger(limit)||limit<1||limit>1000))throw Error('invalid_benchmark_options');
const suffix=process.platform==='win32'?'.exe':'';
const reports=resolve(root,'target/privacy-eval');await mkdir(reports,{recursive:true});
const corpusPath=resolve(root,'tests/models/privacy-v2.json'),corpus=JSON.parse(await readFile(corpusPath,'utf8'));
// Cargo checks can replace an example artifact. Run immutable, hashed copies instead.
const worker=await pinnedBinary(reports,resolve(root,'target/release',`nw-llmd${suffix}`),'nw-llmd'),client=await pinnedBinary(reports,resolve(root,'target/debug/examples',`privacy_pipeline${suffix}`),'privacy_pipeline');
await verifyEmbeddedCorpus(client,corpusPath);
const chat=id==='smoke'?{file:'qwen2.5-0.5b-instruct-q4_k_m.gguf',sha256:'74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db'}:
  JSON.parse(await readFile(resolve(root,'target/test-models',id+'.merged.json'),'utf8'));
if(!/^[a-zA-Z0-9_.-]+\.gguf$/.test(chat.file)||!/^[0-9a-f]{64}$/.test(chat.sha256)||id!=='smoke'&&chat.file!==catalog[id].output)throw Error('invalid_model_receipt');
const chatPath=resolve(root,'target/test-models',chat.file),embedPath=resolve(root,'target/test-models/nomic-embed-text-v1.5.Q4_K_M.gguf');
const embedHash='d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac';
const provenance={worker_sha256:await hash(worker),client_sha256:await hash(client),corpus_sha256:await hash(corpusPath),model_sha256:chat.sha256,embedding_sha256:embedHash,model:id,platform:process.platform};
const path=join(reports,'pipeline-'+id+'.json');let observations=[];
if(resume){try{const previous=JSON.parse(await readFile(path,'utf8'));if(JSON.stringify(previous.provenance)!==JSON.stringify(provenance))throw Error('benchmark_provenance_changed');observations=previous.observations;}catch(e){if(e.code!=='ENOENT')throw e;}}
if(!Array.isArray(observations)||observations.some((o,i)=>o.id!==corpus.cases[i]?.id))throw Error('invalid_benchmark_checkpoint');
const start=observations.length,end=Math.min(corpus.cases.length,start+limit);
const fixture=await mkdtemp(join(reports,'pipeline-run-'));
const endpoint=process.platform==='win32'?`nymwrap-privacy-${process.pid}-${randomBytes(8).toString('hex')}`:join(fixture,'llm.sock');
const delay=ms=>new Promise(r=>setTimeout(r,ms));let model,evaluation,status='running',writes=Promise.resolve();
const save=()=>{const data=JSON.stringify({version:2,status,case_count:corpus.cases.length,provenance,scope:{profile:'standard',translation:false,local_answers_stubbed:true,external_requests:false,attacker:'same local model; shuffled eight fictional dossiers; closed-world only'},observations},null,2)+'\n';writes=writes.then(async()=>{await writeFile(path+'.part',data);await rename(path+'.part',path);});return writes;};
const ready=()=>new Promise(r=>{const s=net.createConnection(process.platform==='win32'?`\\\\.\\pipe\\${endpoint}`:endpoint);s.once('connect',()=>{s.destroy();r(true);});s.once('error',()=>r(false));});
try{
  await save();
  if(start<end){
    const m=await lstat(chatPath);if(m.isSymbolicLink()||!m.isFile()||await hash(chatPath)!==chat.sha256)throw Error('evaluation_model_hash_mismatch');
    model=spawn(worker,['--socket',endpoint,'--model',chatPath,'--sha256',chat.sha256,'--embed-model',embedPath,'--embed-sha256',embedHash,'--parent-stdio'],{cwd:root,windowsHide:true,stdio:['pipe','ignore','ignore']});
    let failed=false;model.on('error',()=>{failed=true;});const deadline=Date.now()+180000;
    while(!await ready()){if(failed||model.exitCode!==null||Date.now()>deadline)throw Error('privacy_worker_start_failed');await delay(100);}
    await new Promise((accept,reject)=>{
      evaluation=spawn(client,[endpoint,String(start),String(end-start)],{cwd:root,windowsHide:true,stdio:['ignore','pipe','ignore']});let pending='';
      const timer=setTimeout(()=>{evaluation.kill();reject(Error('benchmark_timeout'));},4*60*60*1000);
      evaluation.stdout.on('data',bytes=>{
        try{
          pending+=bytes.toString('utf8');if(pending.length>256*1024)throw Error('oversize_benchmark_record');
          let newline;while((newline=pending.indexOf('\n'))>=0){const line=pending.slice(0,newline);pending=pending.slice(newline+1);if(!line.trim())continue;const o=JSON.parse(line);if(o.id!==corpus.cases[observations.length]?.id||!['local','blocked','egress_candidate'].includes(o.decision))throw Error('invalid_benchmark_record');observations.push(o);void save().catch(reject);console.log(JSON.stringify({model:id,completed:observations.length,total:corpus.cases.length,id:o.id,decision:o.decision,leak:o.egress_gold_leak,ms:o.elapsed_ms}));}
        }catch(e){evaluation.kill();reject(e);}
      });
      evaluation.once('error',e=>{clearTimeout(timer);reject(e);});evaluation.once('exit',code=>{clearTimeout(timer);if(code!==0||observations.length!==end||pending.trim())reject(Error('benchmark_failed_or_incomplete'));else accept();});
    });
  }
  status=observations.length===corpus.cases.length?'complete':'partial';await save();
}catch(error){
  status='failed';await save();throw error;
}finally{
  if(evaluation&&evaluation.exitCode===null&&!evaluation.killed)evaluation.kill();
  if(model){model.stdin.on('error',()=>{});model.stdin.end();for(let i=0;i<50&&model.exitCode===null&&!model.killed;i++)await delay(100);if(model.exitCode===null&&!model.killed)model.kill();if(model.exitCode===null)await new Promise(r=>{model.once('exit',r);setTimeout(r,5000).unref();});}
  await writes;
  const actual=await realpath(fixture),base=await realpath(reports),m=await lstat(fixture),normal=v=>process.platform==='win32'?v.toLowerCase():v;
  if(m.isSymbolicLink()||!normal(actual).startsWith(normal(base+sep)))throw Error('unsafe_benchmark_cleanup');await rm(fixture,{recursive:true,force:true});
}
