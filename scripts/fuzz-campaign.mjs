// Six sequential four-hour executions per target. This is never described as
// one continuous process; all eighteen receipts are required for the campaign.
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir,lstat,realpath,readFile,writeFile,readdir,copyFile,cp,chmod} from 'node:fs/promises';
import {resolve,dirname,join,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {fuzzTargets,prepareFuzzSeeds,prepareFuzzReports} from './fuzz.mjs';
import {sourceDigest} from './sbom.mjs';
import {artifactHash} from './evaluation-artifacts.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const nightly='nightly-2026-11-20',triple='x86_64-unknown-linux-gnu';
export const SEGMENTS=6,SEGMENT_SECONDS=14400;
const digest=value=>createHash('sha256').update(value).digest('hex');
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const integer=value=>Number.isSafeInteger(value)&&value>=0;
const targetNames=Object.keys(fuzzTargets);
function target(name){if(!Object.hasOwn(fuzzTargets,name))throw Error('invalid_fuzz_target');return fuzzTargets[name];}
function evidence(){
  const value={workflow_run:process.env.GITHUB_RUN_ID,attempt:process.env.GITHUB_RUN_ATTEMPT,commit:process.env.GITHUB_SHA};
  if(process.platform!=='linux'||process.arch!=='x64'||process.env.GITHUB_ACTIONS!=='true'||
    !/^[1-9][0-9]{0,23}$/.test(value.workflow_run??'')||!/^[1-9][0-9]{0,5}$/.test(value.attempt??'')||!/^[a-f0-9]{40}$/.test(value.commit??''))throw Error('isolated_ubuntu_ci_required');
  return value;
}
function sameEvidence(a,b){return ['workflow_run','attempt','commit'].every(key=>a?.[key]===b?.[key]);}
function validEvidence(value){return /^[1-9][0-9]{0,23}$/.test(value?.workflow_run??'')&&/^[1-9][0-9]{0,5}$/.test(value?.attempt??'')&&/^[a-f0-9]{40}$/.test(value?.commit??'');}
export function validateSegmentIdentity(name,index,previous){
  target(name);
  if(typeof index!=='string'||typeof previous!=='string'||!/^[0-5]$/.test(index)||previous!==(index==='0'?'':String(Number(index)-1)))throw Error('invalid_fuzz_segment_identity');
}
async function plain(path){
  const info=await lstat(path);
  if(!info.isDirectory()||info.isSymbolicLink()||await realpath(path)!==resolve(path))throw Error('unsafe_fuzz_campaign_directory');
  return path;
}
async function directory(parent,name){
  await plain(parent);if(!/^[a-z0-9_-]+$/.test(name))throw Error('invalid_fuzz_campaign_component');
  const path=join(parent,name);try{await mkdir(path);}catch(error){if(error.code!=='EEXIST')throw error;}
  return plain(path);
}
async function paths(name){
  target(name);await prepareFuzzReports(root);
  const campaign=await directory(join(root,'target/fuzz'),'campaign');
  const base=await directory(campaign,name);
  return {campaign,base,bundle:join(base,'bundle'),state:join(base,'state'),receipts:await directory(campaign,'receipts'),manifests:await directory(campaign,'manifests')};
}
async function file(path,maximum=1024*1024){
  const info=await lstat(path);if(!info.isFile()||info.isSymbolicLink()||info.size>maximum)throw Error('unsafe_fuzz_campaign_file');
  return readFile(path);
}
async function corpusHash(path){
  await plain(path);let bytes=0;
  const entries=await readdir(path,{withFileTypes:true});
  if(!entries.length||entries.length>100000)throw Error('invalid_fuzz_campaign_corpus');
  for(const entry of entries){
    if(!entry.isFile()||entry.isSymbolicLink())throw Error('unsafe_fuzz_campaign_corpus');
    const info=await lstat(join(path,entry.name));if(!info.isFile()||info.isSymbolicLink()||info.size>64*1024*1024)throw Error('unsafe_fuzz_campaign_corpus');
    bytes+=info.size;
  }
  if(bytes>128*1024*1024)throw Error('fuzz_campaign_corpus_artifact_limit');
  return sourceDigest(path);
}
async function sources(){
  const values=await Promise.all(['crates','scripts','vendor','fuzz/fuzz_targets','fuzz/examples','fuzz/seeds','.github/workflows'].map(async name=>[name,await sourceDigest(join(root,name))]));
  for(const name of ['Cargo.toml','Cargo.lock','fuzz/Cargo.toml','fuzz/Cargo.lock','rust-toolchain.toml','.cargo/config.toml'])values.push([name,digest(await file(join(root,name),16*1024*1024))]);
  return digest(JSON.stringify(values));
}
function cargo(args,{capture=false}={}){return new Promise((accept,reject)=>{
  const child=spawn('cargo',args,{cwd:root,env:{...process.env,CARGO_NET_OFFLINE:'true'},windowsHide:true,stdio:['ignore',capture?'pipe':'inherit','inherit']});
  let output='';if(capture)child.stdout.on('data',bytes=>{output+=bytes;if(output.length>1024*1024)child.kill();});
  child.once('error',()=>reject(Error('fuzz_campaign_tool_unavailable')));
  child.once('exit',code=>code===0?accept(output):reject(Error('fuzz_campaign_build_failed')));
});}
export function completionStats(log){
  if(typeof log!=='string')return null;
  const done=[...log.matchAll(/^Done ([0-9]+) runs in ([0-9]+) second\(s\)\s*$/gm)].at(-1);
  const total=[...log.matchAll(/^stat::number_of_executed_units:\s*([0-9]+)\s*$/gm)].at(-1);
  if(!done||!total)return null;
  const runs=Number(done[1]),seconds=Number(done[2]);
  if(!integer(runs)||!runs||!integer(seconds)||runs!==Number(total[1]))return null;
  return {runs,seconds};
}
export function segmentReceipt({build,buildHash,index,before,after,previousHash,wallSeconds,exitCode,log,crashFiles}){
  if(!hash(buildHash)||!hash(before)||!hash(after)||!integer(index)||index>=SEGMENTS||
    previousHash!==null&&!hash(previousHash)||!Number.isFinite(wallSeconds)||wallSeconds<0||!integer(crashFiles))throw Error('invalid_fuzz_segment_metadata');
  const stats=completionStats(log);
  const passed=exitCode===0&&crashFiles===0&&wallSeconds>=SEGMENT_SECONDS&&stats?.seconds>=SEGMENT_SECONDS;
  return {version:1,target:build.target,index,segments:SEGMENTS,status:passed?'passed':'failed',
    evidence:build.evidence,build_sha256:buildHash,binary_sha256:build.binary_sha256,source_sha256:build.source_sha256,
    requested_seconds:SEGMENT_SECONDS,wall_seconds:wallSeconds,engine_seconds:stats?.seconds??null,runs:stats?.runs??null,
    corpus_before_sha256:before,corpus_after_sha256:after,previous_receipt_sha256:previousHash,crash_files:crashFiles};
}
export function summarizeCampaign(builds,receipts,expectedEvidence){
  if(!validEvidence(expectedEvidence)||!Array.isArray(builds)||builds.length!==targetNames.length||!Array.isArray(receipts)||receipts.length!==targetNames.length*SEGMENTS)throw Error('incomplete_fuzz_campaign');
  const summaries=[];let commonSource;
  for(const name of targetNames){
    const candidates=builds.filter(value=>value.body?.target===name);
    if(candidates.length!==1)throw Error('incompatible_fuzz_campaign_build');
    const {body:build,sha256:buildHash}=candidates[0];
    if(build.version!==1||!hash(buildHash)||!hash(build.binary_sha256)||!hash(build.initial_corpus_sha256)||!hash(build.source_sha256)||!hash(build.lock_sha256)||
      build.sanitizer!=='address'||build.tool!=='cargo-fuzz 0.13.2'||build.toolchain!==nightly||build.triple!==triple||
      !sameEvidence(build.evidence,expectedEvidence)||commonSource&&commonSource!==build.source_sha256||
      build.preflight?.exit_code!==0||build.preflight?.requested_seconds!==10||!integer(build.preflight.engine_seconds)||build.preflight.engine_seconds<10||
      !Number.isFinite(build.preflight.wall_seconds)||build.preflight.wall_seconds<10||!integer(build.preflight.runs)||!build.preflight.runs)throw Error('incompatible_fuzz_campaign_build');
    commonSource=build.source_sha256;
    const parts=receipts.filter(value=>value.body?.target===name).sort((a,b)=>a.body.index-b.body.index);
    if(parts.length!==SEGMENTS)throw Error('incomplete_fuzz_target_campaign');
    let previousHash=null,corpus=build.initial_corpus_sha256,seconds=0,runs=0;
    for(const [index,{body:part,sha256}]of parts.entries()){
      if(!hash(sha256)||part.version!==1||part.index!==index||part.segments!==SEGMENTS||part.status!=='passed'||
        part.build_sha256!==buildHash||part.binary_sha256!==build.binary_sha256||part.source_sha256!==build.source_sha256||
        !sameEvidence(part.evidence,expectedEvidence)||part.requested_seconds!==SEGMENT_SECONDS||
        !Number.isFinite(part.wall_seconds)||part.wall_seconds<SEGMENT_SECONDS||!integer(part.engine_seconds)||part.engine_seconds<SEGMENT_SECONDS||
        part.engine_seconds>part.wall_seconds+2||!integer(part.runs)||!part.runs||part.crash_files!==0||part.previous_receipt_sha256!==previousHash||
        part.corpus_before_sha256!==corpus||!hash(part.corpus_after_sha256))throw Error('invalid_or_partial_fuzz_segment');
      previousHash=sha256;corpus=part.corpus_after_sha256;seconds+=part.requested_seconds;runs+=part.runs;
      if(!Number.isSafeInteger(runs))throw Error('invalid_fuzz_campaign_counter');
    }
    summaries.push({target:name,requested_seconds:seconds,runs,segments:SEGMENTS,binary_sha256:build.binary_sha256,final_corpus_sha256:corpus});
  }
  return {version:1,status:'complete_segmented_campaign',evidence:expectedEvidence,source_sha256:commonSource,
    continuous_process:false,seconds_per_segment:SEGMENT_SECONDS,targets:summaries,
    m6_acceptance:'not_declared_other_checklist_items_required'};
}
async function buildTarget(name){
  const proof=evidence(),spec=target(name),p=await paths(name);
  const bundle=await directory(p.base,'bundle');
  if((await readdir(bundle)).length)throw Error('fuzz_campaign_bundle_already_exists');
  const source=await sources(),lock=digest(await file(join(root,'fuzz/Cargo.lock')));
  const tool=(await cargo(['+'+nightly,'fuzz','--version'],{capture:true})).trim();
  if(tool!=='cargo-fuzz 0.13.2')throw Error('unexpected_cargo_fuzz_version');
  const corpora=await prepareFuzzSeeds(join(root,'fuzz'));
  if(name==='audit_import')await cargo(['run','--manifest-path','fuzz/Cargo.toml','--target-dir',join(p.base,'seed-build'),'--locked','--offline','--example','seed_formats','--features','audit']);
  const output=join(p.base,'compiler');
  const args=['+'+nightly,'fuzz','build',name,'--fuzz-dir','fuzz','--target-dir',output,'--target',triple,'--sanitizer','address','--codegen-units','16'];
  if(spec.feature)args.push('--features',spec.feature);
  await cargo(args);
  const binary=join(output,triple,'release',name),info=await lstat(binary);
  if(info.isSymbolicLink()||!info.isFile()||info.size>512*1024*1024)throw Error('unsafe_fuzz_campaign_binary');
  await copyFile(binary,join(bundle,'binary'));await chmod(join(bundle,'binary'),0o700);
  await corpusHash(corpora[name]);await cp(corpora[name],join(bundle,'corpus'),{recursive:true,errorOnExist:true,force:false});
  const crashes=await directory(p.base,'crashes');
  const preflight=await executeFuzzer(join(bundle,'binary'),join(bundle,'corpus'),crashes,spec,10);
  const stats=completionStats(preflight.log);
  await writeFile(join(p.base,'preflight-tail.log'),preflight.log,{flag:'wx'});
  if(preflight.exitCode!==0||!stats||stats.seconds<10||preflight.wallSeconds<10||(await readdir(crashes)).length)throw Error('fuzz_campaign_native_preflight_failed');
  if(await sources()!==source||digest(await file(join(root,'fuzz/Cargo.lock')))!==lock)throw Error('fuzz_campaign_sources_changed');
  const manifest={version:1,target:name,evidence:proof,source_sha256:source,binary_sha256:await artifactHash(join(bundle,'binary')),
    initial_corpus_sha256:await corpusHash(join(bundle,'corpus')),lock_sha256:lock,sanitizer:'address',tool,toolchain:nightly,triple,
    preflight:{exit_code:0,requested_seconds:10,engine_seconds:stats.seconds,wall_seconds:preflight.wallSeconds,runs:stats.runs}};
  const bytes=JSON.stringify(manifest,null,2)+'\n';
  await writeFile(join(bundle,'build.json'),bytes,{flag:'wx'});await writeFile(join(p.manifests,name+'.json'),bytes,{flag:'wx'});
}
async function executeFuzzer(binary,corpus,artifacts,spec,seconds){
  const started=performance.now();let log='';
  const exitCode=await new Promise((accept,reject)=>{
    const child=spawn(binary,[corpus,'-max_total_time='+seconds,'-max_len='+spec.maxInput,'-rss_limit_mb=2048','-timeout=15','-print_final_stats=1','-artifact_prefix='+artifacts+'/'],
      {cwd:root,env:{...process.env,ASAN_OPTIONS:'detect_odr_violation=0:abort_on_error=1:detect_leaks=1:symbolize=0'},windowsHide:true,stdio:['ignore','pipe','pipe']});
    const timer=setTimeout(()=>child.kill('SIGKILL'),(seconds+90)*1000);
    const record=bytes=>{log=(log+bytes.toString('utf8')).slice(-65536);};child.stdout.on('data',record);child.stderr.on('data',record);
    child.once('error',()=>{clearTimeout(timer);reject(Error('fuzz_campaign_binary_failed_to_start'));});
    child.once('exit',code=>{clearTimeout(timer);accept(code);});
  });
  return {exitCode,wallSeconds:(performance.now()-started)/1000,log};
}
async function runSegment(name,index){
  const proof=evidence(),spec=target(name),p=await paths(name);
  if(!integer(index)||index>=SEGMENTS)throw Error('invalid_fuzz_segment_index');
  await plain(p.bundle);const manifestBytes=await file(join(p.bundle,'build.json')),build=JSON.parse(manifestBytes),buildHash=digest(manifestBytes);
  if(build.target!==name||!sameEvidence(build.evidence,proof)||build.source_sha256!==await sources()||
    build.binary_sha256!==await artifactHash(join(p.bundle,'binary'))||build.initial_corpus_sha256!==await corpusHash(join(p.bundle,'corpus')))throw Error('fuzz_campaign_bundle_changed');
  const binary=join(p.bundle,'binary');await file(binary,512*1024*1024);await chmod(binary,0o700);
  const state=await directory(p.base,'state');let previousHash=null;
  if(index===0){
    if((await readdir(state)).length)throw Error('unexpected_previous_fuzz_state');
    await cp(join(p.bundle,'corpus'),join(state,'corpus'),{recursive:true,errorOnExist:true,force:false});
  }else{
    const previousBytes=await file(join(state,'receipt.json')),previous=JSON.parse(previousBytes);
    previousHash=digest(previousBytes);
    if(previous.status!=='passed'||previous.index!==index-1||previous.build_sha256!==buildHash||!sameEvidence(previous.evidence,proof)||
      previous.corpus_after_sha256!==await corpusHash(join(state,'corpus')))throw Error('incomplete_previous_fuzz_segment');
  }
  const corpus=join(state,'corpus'),before=await corpusHash(corpus),artifacts=await directory(p.base,'crashes');
  if((await readdir(artifacts)).length)throw Error('preexisting_fuzz_crash');
  const {exitCode,wallSeconds,log}=await executeFuzzer(binary,corpus,artifacts,spec,SEGMENT_SECONDS);
  const receipt=segmentReceipt({build,buildHash,index,before,after:await corpusHash(corpus),previousHash,
    wallSeconds,exitCode,log,crashFiles:(await readdir(artifacts)).length});
  if(await sources()!==build.source_sha256||await artifactHash(binary)!==build.binary_sha256)receipt.status='failed';
  const bytes=JSON.stringify(receipt,null,2)+'\n';await writeFile(join(state,'receipt.json'),bytes);await writeFile(join(p.receipts,name+'-'+index+'.json'),bytes,{flag:'wx'});
  await writeFile(join(p.base,'fuzzer-tail.log'),log,{flag:'wx'});
  if(receipt.status!=='passed')throw Error('fuzz_campaign_segment_failed_or_incomplete');
}
async function mergeCampaign(){
  const proof=evidence(),p=await paths('audit_import');
  const readRecords=async(directory,pattern)=>{
    await plain(directory);const entries=await readdir(directory,{withFileTypes:true});
    if(entries.length>32)throw Error('unexpected_fuzz_campaign_files');
    return Promise.all(entries.map(async entry=>{
      if(!entry.isFile()||entry.isSymbolicLink()||!pattern.test(entry.name))throw Error('unexpected_fuzz_campaign_file');
      const bytes=await file(join(directory,entry.name));return {body:JSON.parse(bytes),sha256:digest(bytes)};
    }));
  };
  const builds=await readRecords(p.manifests,/^(audit_import|ipc_frames|shield_roundtrip)\.json$/);
  const receipts=await readRecords(p.receipts,/^(audit_import|ipc_frames|shield_roundtrip)-[0-5]\.json$/);
  const summary=summarizeCampaign(builds,receipts,proof);
  if(summary.source_sha256!==await sources())throw Error('fuzz_campaign_sources_changed');
  await writeFile(join(p.campaign,'report.json'),JSON.stringify(summary,null,2)+'\n',{flag:'wx'});
}
export async function main(args=process.argv.slice(2)){
  if(args.length===4&&args[0]==='validate')return validateSegmentIdentity(args[1],args[2],args[3]);
  if(args.length===2&&args[0]==='build')return buildTarget(args[1]);
  if(args.length===3&&args[0]==='run'&&/^[0-5]$/.test(args[2]))return runSegment(args[1],Number(args[2]));
  if(args.length===1&&args[0]==='merge')return mergeCampaign();
  throw Error('invalid_fuzz_campaign_command');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
