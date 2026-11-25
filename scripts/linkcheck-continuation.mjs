// Infrastructure amendment only: never repeat an initial/in-flight conversation.
import {readFile,writeFile,mkdir,readdir,mkdtemp,rename} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {artifactHash,pinnedBinary} from './evaluation-artifacts.mjs';
import {validateLinkcheckMeasurement} from './linkcheck-report.mjs';
import {verifyFrozenProvenance} from './linkcheck-experiment.mjs';
import {embeddingModel} from './linkcheck-embeddings.mjs';
import {finishEvaluation} from './linkcheck-eval.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const base=join(root,'docs/evaluations/shield-linkcheck-task5'),fragments=join(base,'fragments');
const json=async path=>JSON.parse(await readFile(path,'utf8'));
const digest=value=>createHash('sha256').update(value).digest('hex');
const once=(path,value)=>writeFile(path,JSON.stringify(value,null,2)+'\n',{flag:'wx'});
const corpusPath=join(root,'tests/models/privacy-v3-held-out.json');
const freezePath=join(base,'freeze.json'),amendmentPath=join(base,'infrastructure-amendment.json');
export function continuationPartition(corpus,sources,seenIndices={}){
  const observed=[],unmeasured=[],chunks=[];
  if(sources.length!==8)throw Error('initial_parts_missing');
  const ordered=[...sources].sort((a,b)=>a.shard.index-b.shard.index);
  for(const [index,part]of ordered.entries()){
    const start=index*45,end=start+45;
    if(part.shard.index!==index||part.shard.start!==start||part.shard.end!==end||part.observations.length>45)throw Error('initial_ranges_changed');
    for(const [offset,row]of part.observations.entries()){
      validateLinkcheckMeasurement(row,corpus.cases[start+offset],64);observed.push(row.id);
    }
    const next=start+part.observations.length;
    // Checkpoints and the two pipes may be buffered. Exclude two extra case
    // positions plus every later stage ID seen. Never assume no egress there.
    const begin=next===end?end:Math.min(end,Math.max(next+2,(seenIndices[index]??(next-1))+1));
    for(let i=next;i<begin;i++)unmeasured.push({id:corpus.cases[i].id,reason:'operator_interruption_or_unstarted_buffer_guard',possible_egress:'unknown',initial_shard:index});
    for(let i=begin;i<end;i+=12)chunks.push({index:chunks.length,start:i,end:Math.min(end,i+12),initial_shard:index});
  }
  const pending=chunks.flatMap(c=>corpus.cases.slice(c.start,c.end).map(c=>c.id));
  const all=[...observed,...unmeasured.map(r=>r.id),...pending];
  if(all.length!==360||new Set(all).size!==360||observed.length+pending.length<300)throw Error('continuation_would_repeat_or_measure_too_few');
  return {observed,unmeasured,chunks,pending};
}
async function verifyBase(){
  const frozen=await json(freezePath),freezeHash=await artifactHash(freezePath),manifest=await json(join(root,'tests/models/privacy-v3-held-out.manifest.json'));
  for(const [path,sha]of Object.entries(frozen.scripts))if(await artifactHash(join(root,path))!==sha)throw Error('original_freeze_code_changed');
  if(manifest.freeze_sha256!==freezeHash||await artifactHash(corpusPath)!==manifest.sha256||
    await artifactHash(join(base,'development.json'))!==frozen.development_sha256||digest(JSON.stringify(frozen.policy)+'\n')!==frozen.expected_provenance.config_sha256)throw Error('original_candidate_changed');
  return {frozen,freezeHash,manifest,corpus:await json(corpusPath)};
}
async function prepare(){
  const {frozen,freezeHash,manifest,corpus}=await verifyBase();
  const stop=await json(join(base,'initial-stop.json'));if(stop.roots!==8)throw Error('initial_processes_not_stopped');
  await mkdir(fragments,{recursive:true});
  const reports=join(root,'target/linkcheck-eval'),sources=[],sourceHashes=[],seen={};
  for(const name of await readdir(reports))if(/^held-out-.*-shard-\d+-of-8\.json$/.test(name)){
    const path=join(reports,name),bytes=await readFile(path),part=JSON.parse(bytes);
    if(part.scope?.freeze_sha256!==freezeHash)continue;
    verifyFrozenProvenance(part.provenance,frozen);
    if(!isDeepStrictEqual(part.scope.policy,frozen.policy))throw Error('initial_policy_changed');
    const index=part.shard.index,copy=`initial-${index}.json`;
    await writeFile(join(fragments,copy),bytes,{flag:'wx'});sources.push(part);sourceHashes.push({index,file:copy,sha256:digest(bytes)});
    const log=await readFile(join(root,`target/task5-held-shard-${index}.log`),'utf8');
    const ids=[...log.matchAll(/"id":"held_([0-9]{4})"/g)].map(m=>Number(m[1])).filter(i=>i>=part.shard.start&&i<part.shard.end);
    if(ids.length)seen[index]=Math.max(...ids);
  }
  const plan=continuationPartition(corpus,sources,seen);
  await once(amendmentPath,{version:1,created_utc:new Date().toISOString(),freeze_sha256:freezeHash,corpus_sha256:manifest.sha256,
    reason:'Initial eight-way non-mmap loads caused paging; the inherited four-hour coordinator limit is insufficient. Complete only unstarted conversations in bounded fresh chunks.',
    thresholds_models_and_inference_binaries_unchanged:true,original_protocol_deviation:true,
    outcome_based_selection:false,initial_fragments:sourceHashes.sort((a,b)=>a.index-b.index),
    source_sha256:await artifactHash(fileURLToPath(import.meta.url)),concurrency:2,chunk_deadline_hours:6,
    ...plan});
  console.log(JSON.stringify({initial_observations:plan.observed.length,unmeasured:plan.unmeasured.length,unstarted:plan.pending.length,chunks:plan.chunks.length}));
}
async function identities(frozen){
  const suffix=process.platform==='win32'?'.exe':'',cache=join(root,'target/linkcheck-eval');
  const client=await pinnedBinary(cache,join(root,'target/release/examples/privacy_linkcheck'+suffix),'privacy_linkcheck');
  const worker=await pinnedBinary(cache,join(root,'target/release/nw-llmd'+suffix),'nw-llmd');
  const p=frozen.expected_provenance,embedding=embeddingModel('qwen3-0.6b-q8_0');
  const launch={model_path:join(root,'target/test-models/qwen2.5-7b-instruct-q4_k_m.gguf'),model_sha256:p.model_sha256,embed_path:join(root,'target/test-models',embedding.file),embed_sha256:p.embedding_sha256};
  for(const [path,sha]of [[client,p.client_sha256],[worker,p.defender_worker_sha256],[launch.model_path,launch.model_sha256],[launch.embed_path,launch.embed_sha256]])if(await artifactHash(path)!==sha)throw Error('retained_model_or_binary_changed');
  if(p.model_sha256!==p.attacker_model_sha256||p.defender_worker_sha256!==p.attacker_worker_sha256)throw Error('continuation_requires_original_shared_worker');
  return {client,worker,launch};
}
async function chunkRun(chunk,context){
  const {frozen,freezeHash,manifest,corpus,amendment,amendmentHash,identity}=context;
  const path=join(fragments,`continuation-${chunk.index}.json`),attempt=join(base,'attempts',`continuation-${chunk.index}.json`);
  await once(attempt,{version:1,amendment_sha256:amendmentHash,freeze_sha256:freezeHash,corpus_sha256:manifest.sha256,...chunk,started_utc:new Date().toISOString(),reruns_allowed:false});
  const result={version:1,status:'running',...chunk,amendment_sha256:amendmentHash,attempt_sha256:await artifactHash(attempt),inference_provenance:frozen.expected_provenance,observations:[]};
  await once(path,result);
  let writes=Promise.resolve();
  const save=()=>{const text=JSON.stringify(result,null,2)+'\n';writes=writes.then(async()=>{await writeFile(path+'.part',text);await rename(path+'.part',path);});return writes;};
  const temporary=await mkdtemp(join(root,'target/linkcheck-eval/continuation-'));
  const policyPath=join(temporary,'policy.json');await writeFile(policyPath,JSON.stringify(frozen.policy)+'\n',{flag:'wx'});
  const endpoint=process.platform==='win32'?`nymwrap-task5-${process.pid}-${randomBytes(8).toString('hex')}`:join(temporary,'model.sock');
  let child;
  try{
    await new Promise((accept,reject)=>{
      child=spawn(identity.client,[endpoint,identity.worker,endpoint,identity.worker,corpusPath,manifest.sha256,policyPath,String(chunk.start),String(chunk.end-chunk.start)],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
      child.stdin.on('error',()=>{});child.stdin.end(JSON.stringify({defender:identity.launch,attacker:identity.launch,stop_after_invalid_attacker:false}));
      let pending='';child.stdout.setEncoding('utf8');
      const timer=setTimeout(()=>{child.kill();reject(Error('continuation_chunk_deadline'));},amendment.chunk_deadline_hours*3600000);
      child.stdout.on('data',text=>{
        try{
          pending+=text;if(pending.length>256*1024)throw Error('oversize_continuation_record');
          let newline;while((newline=pending.indexOf('\n'))>=0){const line=pending.slice(0,newline);pending=pending.slice(newline+1);if(!line.trim())continue;
            const row=JSON.parse(line),position=chunk.start+result.observations.length;
            if(position>=chunk.end)throw Error('extra_continuation_observation');
            validateLinkcheckMeasurement(row,corpus.cases[position],64);result.observations.push(row);void save().catch(reject);
            console.log(JSON.stringify({chunk:chunk.index,completed:result.observations.length,total:chunk.end-chunk.start}));
          }
        }catch(error){child.kill();reject(error);}
      });
      // Drain diagnostics without retaining model content. The executable emits
      // only stages, but arbitrary panic text must not enter published evidence.
      child.stderr.resume();
      child.once('error',error=>{clearTimeout(timer);reject(error);});
      child.once('exit',code=>{clearTimeout(timer);if(code!==0||pending.trim()||result.observations.length!==chunk.end-chunk.start)reject(Error('continuation_chunk_incomplete'));else accept();});
    });
    result.status='complete';
  }catch{
    result.status='failed';result.failure_code='continuation_chunk_incomplete';
  }finally{
    await finishEvaluation(child);await writes;result.finished_utc=new Date().toISOString();await save();
  }
}
async function run(){
  const context=await verifyBase(),amendment=await json(amendmentPath),amendmentHash=await artifactHash(amendmentPath);
  if(amendment.source_sha256!==await artifactHash(fileURLToPath(import.meta.url))||amendment.freeze_sha256!==context.freezeHash||amendment.corpus_sha256!==context.manifest.sha256||amendment.concurrency!==2||amendment.chunk_deadline_hours!==6)throw Error('infrastructure_amendment_changed');
  const claim=join(base,'attempts/continuation-coordinator.json');
  await once(claim,{version:1,amendment_sha256:amendmentHash,started_utc:new Date().toISOString(),reruns_allowed:false});
  const identity=await identities(context.frozen);
  const shared={...context,amendment,amendmentHash,identity};let cursor=0;
  await Promise.all(Array.from({length:2},async()=>{while(cursor<amendment.chunks.length){const chunk=amendment.chunks[cursor++];await chunkRun(chunk,shared);}}));
  console.log('one_pass_continuation_finished');
}
export async function main(args=process.argv.slice(2)){
  if(args.length===1&&args[0]==='prepare')return prepare();
  if(args.length===1&&args[0]==='run')return run();
  throw Error('usage_linkcheck_continuation_prepare_or_run');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
