// Coverage-guided fuzzing of synthetic inputs only. No application workspace is opened.
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdir,lstat,realpath} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {sourceDigest} from './sbom.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
export const fuzzTargets=Object.freeze({audit_import:{feature:'audit',maxInput:8388609},ipc_frames:{feature:'ipc-core',maxInput:16777220},shield_roundtrip:{maxInput:65536}});
const nightly='nightly-2026-11-20';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export function parseFuzzOptions(args){
  const options={seconds:60};const seen=new Set();
  while(args.length){
    const key=args.shift();if(!['--target','--seconds'].includes(key)||seen.has(key)||!args.length)throw Error('invalid_fuzz_arguments');
    seen.add(key);const value=args.shift();
    if(key==='--target'){if(!Object.hasOwn(fuzzTargets,value))throw Error('invalid_fuzz_target');options.target=value;}
    else {if(!/^[1-9][0-9]*$/.test(value)||!Number.isSafeInteger(Number(value))||Number(value)>86400)throw Error('invalid_fuzz_duration');options.seconds=Number(value);}
  }
  if(!options.target)throw Error('fuzz_target_required');return options;
}
async function plainDirectory(path){
  const info=await lstat(path);const actual=await realpath(path);
  const normalize=value=>process.platform==='win32'?value.toLowerCase():value;
  if(!info.isDirectory()||info.isSymbolicLink()||normalize(actual)!==normalize(resolve(path)))throw Error('unsafe_fuzz_directory');
  return path;
}
async function subdirectory(parent,name){
  await plainDirectory(parent);const path=resolve(parent,name);
  try{await mkdir(path);}catch(error){if(error.code!=='EEXIST')throw error;}
  return plainDirectory(path);
}
export async function prepareFuzzReports(workspace){
  return subdirectory(await subdirectory(await subdirectory(workspace,'target'),'fuzz'),'reports');
}
export async function prepareFuzzSeeds(fuzzDir){
  await plainDirectory(fuzzDir);
  const corpus=await subdirectory(fuzzDir,'corpus');
  const paths={};for(const name of Object.keys(fuzzTargets))paths[name]=await subdirectory(corpus,name);
  const seeds=await plainDirectory(resolve(fuzzDir,'seeds'));
  const write=async(target,name,bytes)=>{
    const path=resolve(paths[target],name);
    try{await writeFile(path,bytes,{flag:'wx'});}catch(error){if(error.code!=='EEXIST')throw error;const info=await lstat(path);if(!info.isFile()||info.isSymbolicLink())throw Error('unsafe_fuzz_seed');}
  };
  const framed=bytes=>{const size=Buffer.alloc(4);size.writeUInt32LE(bytes.length);return Buffer.concat([size,bytes]);};
  for(const name of ['takeout.json','chatgpt.json','claude.json','takeout.html','ipc.json','cover.json','shield.txt']){
    const path=resolve(seeds,name),info=await lstat(path);if(!info.isFile()||info.isSymbolicLink()||info.size>65536)throw Error('unsafe_fuzz_seed');
    const bytes=await readFile(path);
    if(['ipc.json','cover.json'].includes(name)){
      await write('ipc_frames',name,bytes);await write('ipc_frames',name+'.frame',framed(bytes));
    }else if(name==='shield.txt')await write('shield_roundtrip',name,bytes);
    else await write('audit_import',name,bytes);
  }
  for(const [name,body] of Object.entries({packet:{version:1,lane:'cover',request_id:1,body:{kind:'status'}},core:{version:1,lane:'shadow',request_id:1,body:{op:'status'}}})){
    await write('ipc_frames',name+'.frame',framed(Buffer.from(JSON.stringify(body))));
  }
  const task={plan_hash:'a'.repeat(64),stage:1,day:1,action_index:0,service:'google',text:'synthetic garden ideas'};
  for(const kind of ['begin_search','validate_search','finish_search']){
    const command={kind,task,...(kind==='begin_search'?{}:{token:'b'.repeat(64)})};
    await write('ipc_frames',kind+'.frame',framed(Buffer.from(JSON.stringify({version:1,id:1,command}))));
  }
  for(const [name,body]of Object.entries({
    submission:{op:'submit_remote_job',conversation:'new',messages:[{role:'user',content:'synthetic garden ideas'}],max_tokens:32,min_trust:'L3',idempotency_key:'SYNTHETIC_FUZZ_RECEIPT_20391'},
    purge_result:{op:'record_purge_result',hash:'a'.repeat(64),outcome:'no_longer_visible',completed_steps:['history','verify']},
  }))await write('ipc_frames',name+'.frame',framed(Buffer.from(JSON.stringify({version:1,lane:'shadow',request_id:1,body}))));
  // Exercise the success oracle as well as the reserved-placeholder rejection seed.
  await write('shield_roundtrip','synthetic-roundtrip.txt',Buffer.from('Synthetic example: IP:::1, synthetic@example.test, Armenian հայերեն, emoji 🌱.'));
  return paths;
}
function run(args,{quiet=false,capture=false}={}){return new Promise((accept,reject)=>{
  const child=spawn('cargo',args,{cwd:root,env:{...process.env,CARGO_NET_OFFLINE:'true'},windowsHide:true,stdio:['ignore',capture?'pipe':quiet?'ignore':'inherit','inherit']});
  let output='';if(capture)child.stdout.on('data',bytes=>{output+=bytes;if(output.length>1024*1024)child.kill();});
  child.once('error',()=>reject(Error('fuzz_tool_unavailable')));child.once('exit',code=>code===0?accept(output):reject(Error('fuzz_step_failed')));
});}
async function sources(){
  const entries=await Promise.all(['crates','fuzz/fuzz_targets','fuzz/seeds','fuzz/examples'].map(async name=>[name,await sourceDigest(resolve(root,name))]));
  entries.push(['fuzz/Cargo.toml',hash(await readFile(resolve(root,'fuzz/Cargo.toml')))]);
  return Object.fromEntries(entries);
}
export async function runFuzz(options){
  options=parseFuzzOptions(['--target',options.target,'--seconds',String(options.seconds)]);
  const target=fuzzTargets[options.target];if(!target)throw Error('invalid_fuzz_target');
  // cargo-fuzz may only create fuzz/target. A clean checkout has no root target/.
  const reports=await prepareFuzzReports(root);
  const fuzzDir=resolve(root,'fuzz'),lockPath=resolve(fuzzDir,'Cargo.lock');
  const lockBefore=hash(await readFile(lockPath));
  const tool=(await run(['+'+nightly,'fuzz','--version'],{capture:true})).trim();
  if(!/^cargo-fuzz(?:\.exe)? 0\.13\.2$/.test(tool))throw Error('unexpected_cargo_fuzz_version');
  await run(['metadata','--manifest-path','fuzz/Cargo.toml','--all-features','--locked','--offline','--format-version','1'],{quiet:true});
  const corpus=await prepareFuzzSeeds(fuzzDir);
  if(options.target==='audit_import')await run(['run','--manifest-path','fuzz/Cargo.toml','--target-dir',resolve(root,'target'),'--locked','--offline','--example','seed_formats','--features','audit']);
  // Refuse links/special files before libFuzzer recursively reads its corpus.
  await sourceDigest(corpus[options.target]);
  const artifacts=await subdirectory(await subdirectory(fuzzDir,'artifacts'),options.target);
  const build=['+'+nightly,'fuzz','build',options.target,'--fuzz-dir','fuzz','--sanitizer','address','--codegen-units','16'];
  if(target.feature)build.push('--features',target.feature);
  const before=await sources();await run(build);
  if(hash(await readFile(lockPath))!==lockBefore||JSON.stringify(await sources())!==JSON.stringify(before))throw Error('fuzz_sources_changed');
  const command=[...build];command[2]='run';
  const started=new Date();let failure;
  try{
    await run([...command,'--','-max_total_time='+options.seconds,'-max_len='+target.maxInput,'-rss_limit_mb=2048','-timeout=15','-artifact_prefix='+artifacts.replaceAll('\\','/')+'/']);
    if(hash(await readFile(lockPath))!==lockBefore||JSON.stringify(await sources())!==JSON.stringify(before))throw Error('fuzz_sources_changed');
  }catch(error){failure=error;}
  const finished=new Date();
  const report={version:1,target:options.target,status:failure?'failed':'passed',sanitizer:'address',tool,toolchain:nightly,requested_seconds:options.seconds,elapsed_seconds:(finished-started)/1000,started_at:started.toISOString(),finished_at:finished.toISOString(),lock_sha256:lockBefore,sources:before,corpus_sha256:await sourceDigest(corpus[options.target])};
  await writeFile(resolve(reports,options.target+'.json'),JSON.stringify(report,null,2)+'\n');
  if(failure)throw failure;
  process.stdout.write('Fuzz smoke passed: '+options.target+'; report target/fuzz/reports/'+options.target+'.json\n');
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  try{await runFuzz(parseFuzzOptions(process.argv.slice(2)));}catch(error){process.stderr.write(/^[a-z_]+$/.test(error.message)?error.message+'\n':'fuzz_failed\n');process.exitCode=1;}
}
