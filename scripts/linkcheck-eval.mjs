// Opt-in, local-only measurement. It never opens the user's app data or accounts.
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,mkdtemp,readFile,writeFile,rename,realpath,lstat,rm} from 'node:fs/promises';
import {randomBytes,createHash} from 'node:crypto';
import {resolve,join,sep,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {StringDecoder} from 'node:string_decoder';
import {artifactHash,pinnedBinary} from './evaluation-artifacts.mjs';
import {summarizeLinkcheckReport} from './linkcheck-report.mjs';
import {shardRange} from './linkcheck-shards.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),execute=promisify(execFile);
const digest=value=>createHash('sha256').update(value).digest('hex');
function options(args){
  const result={model:'smoke',attacker:'qwen2.5-7b-q4_k_m',limit:Infinity,resume:false,failInvalidAttacker:false,shard:null};
  const seen=new Set();
  for(let i=0;i<args.length;i++){
    const key=args[i];if(seen.has(key))throw Error('duplicate_linkcheck_option');seen.add(key);
    if(key==='--resume')result.resume=true;
    else if(key==='--fail-invalid-attacker')result.failInvalidAttacker=true;
    else if(key==='--model')result.model=args[++i];
    else if(key==='--attacker')result.attacker=args[++i];
    else if(key==='--limit')result.limit=Number(args[++i]);
    else if(key==='--shard'){
      const match=/^(0|[1-9][0-9]?)\/([1-9][0-9]?)$/.exec(args[++i]??'');
      if(!match)throw Error('invalid_linkcheck_shard');
      result.shard={index:Number(match[1]),count:Number(match[2])};
    }
    else throw Error('invalid_linkcheck_option');
  }
  if(!['smoke','qwen2.5-7b-q4_k_m'].includes(result.model)||!['smoke','qwen2.5-7b-q4_k_m'].includes(result.attacker)||
    result.limit!==Infinity&&(!Number.isSafeInteger(result.limit)||result.limit<1||result.limit>1024))throw Error('invalid_linkcheck_options');
  return result;
}
async function modelIdentity(id){
  if(id==='smoke')return {file:'qwen2.5-0.5b-instruct-q4_k_m.gguf',sha256:'74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db'};
  const catalog=JSON.parse(await readFile(join(root,'scripts/privacy-models.json'),'utf8'));
  const receipt=JSON.parse(await readFile(join(root,'target/test-models',id+'.merged.json'),'utf8'));
  if(receipt.file!==catalog[id].output||receipt.sha256!==catalog[id].merged_sha256||!/^[a-f0-9]{64}$/.test(receipt.sha256))throw Error('invalid_linkcheck_model_receipt');
  return {file:receipt.file,sha256:receipt.sha256};
}
async function verifyFile(path,sha256){
  const info=await lstat(path);if(info.isSymbolicLink()||!info.isFile()||await artifactHash(path)!==sha256)throw Error('linkcheck_artifact_hash_mismatch');
}
async function cleanup(fixture,reports){
  const [actual,base,info]=await Promise.all([realpath(fixture),realpath(reports),lstat(fixture)]),normal=v=>process.platform==='win32'?v.toLowerCase():v;
  if(info.isSymbolicLink()||!normal(actual).startsWith(normal(base+sep)))throw Error('unsafe_linkcheck_fixture_cleanup');
  await rm(fixture,{recursive:true,force:true});
}
export async function finishEvaluation(child){
  if(!child?.pid||child.exitCode!==null||child.signalCode!==null)return;
  // Allow Rust's normal teardown after a failed record; then stop a stalled
  // child and observe its exit before removing any of its encrypted files.
  const exited=()=>child.exitCode!==null||child.signalCode!==null;
  await new Promise(resolve=>{
    let timer;const done=()=>{clearTimeout(timer);child.off('exit',done);resolve();};
    child.once('exit',done);timer=setTimeout(done,1000);if(exited())done();
  });
  if(exited())return;
  const stopped=new Promise((resolve,reject)=>{
    let timer;const done=()=>{clearTimeout(timer);child.off('exit',done);resolve();};
    child.once('exit',done);timer=setTimeout(()=>{child.off('exit',done);reject(Error('evaluation_child_did_not_stop'));},5000);
    if(exited())done();
  });
  if(!child.killed)child.kill();await stopped;
}
export async function main(args=process.argv.slice(2)){
  const opts=options(args),reports=join(root,'target/linkcheck-eval');await mkdir(reports,{recursive:true});
  if((await lstat(reports)).isSymbolicLink())throw Error('unsafe_linkcheck_report_directory');
  // Held-out generation/evaluation will require a frozen development receipt.
  // This CLI deliberately exposes only development until that protocol exists.
  const corpusPath=join(root,'tests/models/privacy-v3-dev.json'),corpusHash=await artifactHash(corpusPath);
  const manifest=JSON.parse(await readFile(join(root,'tests/models/privacy-v3-dev.manifest.json'),'utf8'));
  if(corpusHash!==manifest.sha256||await artifactHash(join(root,'scripts/generate-linkcheck-corpus.mjs'))!==manifest.generator_sha256)throw Error('invalid_development_corpus_manifest');
  const corpus=JSON.parse(await readFile(corpusPath,'utf8'));
  if(corpus.partition!=='development'||corpus.version!==3||corpus.cases.length!==384)throw Error('invalid_development_corpus');
  const range=opts.shard?shardRange(corpus.cases.length,opts.shard.index,opts.shard.count):{start:0,end:corpus.cases.length};
  const suffix=process.platform==='win32'?'.exe':'',worker=await pinnedBinary(reports,join(root,'target/release','nw-llmd'+suffix),'nw-llmd');
  const client=await pinnedBinary(reports,join(root,'target/release/examples','privacy_linkcheck'+suffix),'privacy_linkcheck');
  const model=await modelIdentity(opts.model),attackerModel=await modelIdentity(opts.attacker);
  const embed={path:join(root,'target/test-models/nomic-embed-text-v1.5.Q4_K_M.gguf'),sha256:'d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac'};
  await verifyFile(join(root,'target/test-models',model.file),model.sha256);
  if(attackerModel.sha256!==model.sha256)await verifyFile(join(root,'target/test-models',attackerModel.file),attackerModel.sha256);
  await verifyFile(embed.path,embed.sha256);
  const configResult=await execute(client,['--evaluation-config'],{cwd:root,windowsHide:true,maxBuffer:1024*1024});
  const config=JSON.parse(configResult.stdout),policy=JSON.stringify(config)+'\n';
  const workerHash=await artifactHash(worker);
  const provenance={client_sha256:await artifactHash(client),defender_worker_sha256:workerHash,attacker_worker_sha256:workerHash,
    corpus_sha256:corpusHash,model_sha256:model.sha256,attacker_model_sha256:attackerModel.sha256,embedding_sha256:embed.sha256,
    config_sha256:digest(policy),evaluator_script_sha256:await artifactHash(fileURLToPath(import.meta.url)),
    report_script_sha256:await artifactHash(join(root,'scripts/linkcheck-report.mjs')),statistics_sha256:await artifactHash(join(root,'scripts/linkcheck-statistics.mjs')),
    shard_script_sha256:await artifactHash(join(root,'scripts/linkcheck-shards.mjs')),
    model:opts.model,attacker_model:opts.attacker,platform:process.platform,arch:process.arch};
  const receiptHash=digest(JSON.stringify(provenance)),path=join(reports,'development-'+opts.model+'-vs-'+opts.attacker+'-'+receiptHash.slice(0,20)+(opts.shard?`-shard-${range.index}-of-${range.count}`:'')+'.json');
  const report={version:3,status:'running',partition:'development',case_count:corpus.cases.length,provenance,
    ...(opts.shard?{shard:range}:{}),evidence:{workflow_run:process.env.GITHUB_RUN_ID??null,commit:process.env.GITHUB_SHA??null},
    scope:{profile:config.profile,policy:config,external_requests:false,local_answers_stubbed:false,provider_answers:'real local model, simulated provider',
      inventory:'synthetic Device records; no host collection',attacker:'real local fact extraction and deterministic 64-dossier ranking plus independent literal matcher; full cumulative provider view',
      utility:corpus.utility_scope,held_out:false},observations:[]};
  if(opts.resume){
    try{const old=JSON.parse(await readFile(path,'utf8'));if(JSON.stringify(old.provenance)!==JSON.stringify(provenance)||JSON.stringify(old.shard)!==JSON.stringify(report.shard)||JSON.stringify(old.evidence)!==JSON.stringify(report.evidence))throw Error('linkcheck_checkpoint_changed');report.observations=old.observations;}
    catch(e){if(e.code!=='ENOENT')throw e;}
  }else{try{await lstat(path);throw Error('linkcheck_report_exists_use_resume');}catch(e){if(e.code!=='ENOENT')throw e;}}
  if(!Array.isArray(report.observations)||report.observations.length>range.end-range.start||report.observations.some((r,i)=>r.id!==corpus.cases[range.start+i].id))throw Error('invalid_linkcheck_checkpoint');
  let writes=Promise.resolve();
  const save=()=>{const text=JSON.stringify(report,null,2)+'\n';writes=writes.then(async()=>{await writeFile(path+'.part',text);await rename(path+'.part',path);});return writes;};
  const start=range.start+report.observations.length,end=Math.min(range.end,start+opts.limit),fixture=await mkdtemp(join(reports,'run-'));
  const endpoint=role=>process.platform==='win32'?`nymwrap-linkcheck-${role}-${process.pid}-${randomBytes(8).toString('hex')}`:join(fixture,role+'.sock');
  const defenderEndpoint=endpoint('defender'),attackerEndpoint=model.sha256===attackerModel.sha256?defenderEndpoint:endpoint('attacker');
  let evaluation;
  try{
    await save();await writeFile(join(fixture,'policy.json'),policy);
    if(start<end){
      await new Promise((accept,reject)=>{
        evaluation=spawn(client,[defenderEndpoint,worker,attackerEndpoint,worker,corpusPath,corpusHash,join(fixture,'policy.json'),String(start),String(end-start)],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
        const plan=identity=>({model_path:join(root,'target/test-models',identity.file),model_sha256:identity.sha256,embed_path:embed.path,embed_sha256:embed.sha256});
        evaluation.stdin.on('error',()=>{});evaluation.stdin.end(JSON.stringify({defender:plan(model),attacker:plan(attackerModel),stop_after_invalid_attacker:opts.failInvalidAttacker}));
        let pending='';const decoder=new StringDecoder('utf8');
        let diagnostic='';evaluation.stderr.setEncoding('utf8');evaluation.stderr.on('data',text=>{
          diagnostic=(diagnostic+text).slice(-4096);let newline;
          while((newline=diagnostic.indexOf('\n'))>=0){const line=diagnostic.slice(0,newline).trim();diagnostic=diagnostic.slice(newline+1);
            if(/^linkcheck_stage:(ner|canonicalize|generalize|embeddings|local_answer|raw_attack|outbound_attack):(started|completed)$/.test(line))console.log(JSON.stringify({id:corpus.cases[range.start+report.observations.length]?.id,stage:line}));
          }
        });
        const timer=setTimeout(()=>{evaluation.kill();reject(Error('linkcheck_evaluation_timeout'));},4*60*60*1000);
        evaluation.stdout.on('data',bytes=>{
          try{
            pending+=decoder.write(bytes);if(pending.length>256*1024)throw Error('oversize_linkcheck_record');
            let newline;while((newline=pending.indexOf('\n'))>=0){
              const line=pending.slice(0,newline);pending=pending.slice(newline+1);if(!line.trim())continue;
              const row=JSON.parse(line);if(range.start+report.observations.length>=end||row.id!==corpus.cases[range.start+report.observations.length].id)throw Error('unexpected_linkcheck_record');
              report.observations.push(row);void save().catch(reject);
              console.log(JSON.stringify({completed:report.observations.length,total:corpus.cases.length,id:row.id,remote:row.remote_turns,local:row.local_turns,blocked:row.blocked_turns,useful:row.utility,leaks:row.canary_leaks,ms:row.elapsed_ms}));
              if(opts.failInvalidAttacker&&(!row.raw_attack?.valid||row.remote_turns>0&&!row.attack?.valid)){
                reject(Error('linkcheck_attacker_failed_measurement_incomplete'));return;
              }
            }
          }catch(e){evaluation.kill();reject(e);}
        });
        evaluation.once('error',e=>{clearTimeout(timer);reject(e);});
        evaluation.once('exit',code=>{clearTimeout(timer);pending+=decoder.end();if(code!==0||range.start+report.observations.length!==end||pending.trim())reject(Error('linkcheck_evaluation_failed_or_incomplete'));else accept();});
      });
    }
    report.status=report.observations.length===range.end-range.start?(opts.shard?'complete_shard':'complete'):'partial';
    if(report.status==='complete')report.analysis=summarizeLinkcheckReport(report,corpus,corpusHash);
    await save();console.log(JSON.stringify({report:path,status:report.status,cases:report.observations.length,total:corpus.cases.length,held_out:false}));
  }catch(e){report.status='failed';await save();throw e;}
  finally{await finishEvaluation(evaluation);try{await writes;}finally{await cleanup(fixture,reports);}}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
