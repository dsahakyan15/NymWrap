// Host-restart recovery: reuse frozen chunk execution, never retry a claim.
import {readFile,writeFile,rename,unlink,access} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash,randomBytes} from 'node:crypto';
import {artifactHash} from './evaluation-artifacts.mjs';
import {validateLinkcheckMeasurement} from './linkcheck-report.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),base=join(root,'docs/evaluations/shield-linkcheck-task5');
const originalPath=join(root,'scripts/linkcheck-continuation.mjs'),planPath=join(base,'host-restart-amendment.json');
const json=async path=>JSON.parse(await readFile(path,'utf8'));
const encoded=value=>JSON.stringify(value,null,2)+'\n';
const digest=value=>createHash('sha256').update(value).digest('hex');
const exists=async path=>{try{await access(path);return true;}catch(error){if(error.code==='ENOENT')return false;throw error;}};
const once=(path,value)=>writeFile(path,encoded(value),{flag:'wx'});
const bridgeSuffix='\nexport { verifyBase, identities, chunkRun };\n';
export function recoveryPartition(chunks,claimed,corpus){
  const pending=[],unmeasured=[];
  for(const chunk of chunks){
    const part=claimed.get(chunk.index);
    if(!part){pending.push(chunk);continue;}
    if(!['running','complete','failed'].includes(part.status)||part.start!==chunk.start||part.end!==chunk.end||part.observations.length>chunk.end-chunk.start||
      (part.status==='complete'&&part.observations.length!==chunk.end-chunk.start))throw Error('restart_fragment_changed');
    for(let i=chunk.start+part.observations.length;i<chunk.end;i++)unmeasured.push({id:corpus.cases[i].id,reason:'host_restart_claim_not_retried',possible_egress:'unknown',chunk:chunk.index});
  }
  return {pending,unmeasured};
}
async function withFrozenChunks(callback){
  const amendment=await json(join(base,'infrastructure-amendment.json')),source=await readFile(originalPath,'utf8');
  if(digest(source)!==amendment.source_sha256)throw Error('frozen_chunk_source_changed');
  // Only append exports. Every byte of execution, inference and deadlines is
  // inherited unchanged; the temporary module stays in the same directory.
  const bytes=source+bridgeSuffix,path=join(root,`scripts/.task5-frozen-chunks-${randomBytes(8).toString('hex')}.mjs`);
  await writeFile(path,bytes,{flag:'wx'});
  try{return await callback(await import(pathToFileURL(path).href),digest(bytes));}
  finally{await unlink(path);}
}
async function prepare(){
  await withFrozenChunks(async(module,bridgeHash)=>{
    const context=await module.verifyBase(),amendment=await json(join(base,'infrastructure-amendment.json'));
    const claimed=new Map(),evidence=[],settlements=[];
    for(const chunk of amendment.chunks){
      const name=`continuation-${chunk.index}.json`,attempt=join(base,'attempts',name),path=join(base,'fragments',name);
      const hasAttempt=await exists(attempt),hasFragment=await exists(path);
      if(hasAttempt!==hasFragment)throw Error('restart_claim_fragment_mismatch');
      if(!hasAttempt)continue;
      const bytes=await readFile(path),part=JSON.parse(bytes);claimed.set(chunk.index,part);
      for(const [offset,row]of part.observations.entries())validateLinkcheckMeasurement(row,context.corpus.cases[chunk.start+offset],64);
      evidence.push({file:name,attempt_sha256:await artifactHash(attempt),fragment_sha256:digest(bytes),status:part.status,observations:part.observations.length});
      if(part.status==='running'){
        const archive=`host-restart-${name}`,settled={...part,status:'failed',failure_code:'host_restart',finished_utc:new Date().toISOString()};
        await writeFile(join(base,'archive',archive),bytes,{flag:'wx'});
        settlements.push({file:name,archive,before_sha256:digest(bytes),after_sha256:digest(encoded(settled)),settled});
      }
    }
    const partition=recoveryPartition(amendment.chunks,claimed,context.corpus);
    const metadata=await json(join(base,'host-restart.json'));
    const plan={version:1,created_utc:new Date().toISOString(),reason:'Host restarted; original coordinator and inference processes no longer exist. Run only never-claimed chunks.',
      restart_evidence_sha256:await artifactHash(join(base,'host-restart.json')),host_boot_utc:metadata.host_boot_utc,
      original_amendment_sha256:await artifactHash(join(base,'infrastructure-amendment.json')),freeze_sha256:context.freezeHash,
      source_sha256:await artifactHash(fileURLToPath(import.meta.url)),frozen_chunk_bridge_sha256:bridgeHash,
      original_coordinator_attempt_sha256:await artifactHash(join(base,'attempts/continuation-coordinator.json')),
      outcome_based_selection:false,inference_thresholds_models_deadlines_unchanged:true,concurrency:2,
      prior_claims:evidence,settlements:settlements.map(({settled,...receipt})=>receipt),...partition};
    await once(planPath,plan);
    for(const item of settlements){const path=join(base,'fragments',item.file);await writeFile(path+'.part',encoded(item.settled));await rename(path+'.part',path);}
    console.log(JSON.stringify({completed_observations:[...claimed.values()].reduce((n,p)=>n+p.observations.length,amendment.observed.length),additional_unknown:partition.unmeasured.length,unclaimed_chunks:partition.pending.length}));
  });
}
async function run(){
  const plan=await json(planPath),amendmentHash=await artifactHash(join(base,'infrastructure-amendment.json'));
  if(plan.source_sha256!==await artifactHash(fileURLToPath(import.meta.url))||plan.original_amendment_sha256!==amendmentHash||plan.concurrency!==2||
    plan.restart_evidence_sha256!==await artifactHash(join(base,'host-restart.json'))||plan.original_coordinator_attempt_sha256!==await artifactHash(join(base,'attempts/continuation-coordinator.json')))throw Error('restart_plan_changed');
  for(const source of plan.prior_claims){
    const settlement=plan.settlements.find(s=>s.file===source.file);
    if(await artifactHash(join(base,'attempts',source.file))!==source.attempt_sha256||await artifactHash(join(base,'fragments',source.file))!==(settlement?.after_sha256??source.fragment_sha256))throw Error('restart_prior_claim_changed');
    if(settlement&&await artifactHash(join(base,'archive',settlement.archive))!==settlement.before_sha256)throw Error('restart_archive_changed');
  }
  await once(join(base,'attempts/host-restart-coordinator.json'),{version:1,plan_sha256:await artifactHash(planPath),started_utc:new Date().toISOString(),reruns_allowed:false});
  await withFrozenChunks(async(module,bridgeHash)=>{
    if(bridgeHash!==plan.frozen_chunk_bridge_sha256)throw Error('restart_chunk_execution_changed');
    const context=await module.verifyBase(),amendment=await json(join(base,'infrastructure-amendment.json'));
    if(plan.freeze_sha256!==context.freezeHash)throw Error('restart_candidate_changed');
    const claimed=new Map();for(const source of plan.prior_claims)claimed.set(Number(source.file.match(/continuation-(\d+)\.json/)[1]),await json(join(base,'fragments',source.file)));
    if(JSON.stringify(recoveryPartition(amendment.chunks,claimed,context.corpus).pending)!==JSON.stringify(plan.pending))throw Error('restart_selection_changed');
    const shared={...context,amendment,amendmentHash,identity:await module.identities(context.frozen)};let cursor=0;
    await Promise.all(Array.from({length:2},async()=>{while(cursor<plan.pending.length)await module.chunkRun(plan.pending[cursor++],shared);}));
    console.log('one_pass_host_restart_continuation_finished');
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length!==3||!['prepare','run'].includes(process.argv[2]))throw Error('usage_linkcheck_recovery_prepare_or_run');
  if(process.argv[2]==='prepare')await prepare();else await run();
}
