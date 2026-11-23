// Repository supply-chain check. No application workspace, key store or account is opened.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,readFile,writeFile,rm,lstat,realpath} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {pinnedTool} from './pinned-tools.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),run=promisify(execFile);
export const manifests={root:'Cargo.toml',desktop:'app/src-tauri/Cargo.toml',netd:'daemons/nw-netd/Cargo.toml',fuzz:'fuzz/Cargo.toml'};
export function options(args){
  let scope=null,update=false;
  for(const arg of args){
    if(arg==='--update-imports'&&!update)update=true;
    else if(Object.hasOwn(manifests,arg)&&scope===null)scope=arg;
    else throw Error('invalid_vet_check_option');
  }
  return {scopes:scope?[scope]:Object.keys(manifests),update};
}
export function successfulVet(code,result){
  return code===0&&result?.conclusion==='success'&&!result.error&&!result.failures&&
    Array.isArray(result.vetted_fully)&&Array.isArray(result.vetted_partially)&&result.vetted_partially.length===0&&
    Array.isArray(result.vetted_with_exemptions)&&result.vetted_with_exemptions.length===0;
}
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
export async function main(args=process.argv.slice(2)){
  const opts=options(args),tool=await pinnedTool('cargo-vet');
  const cargo=(await run('rustup',['which','cargo'],{cwd:root,windowsHide:true})).stdout.trim();
  const reports=join(root,'target','vet');await mkdir(reports,{recursive:true});
  const info=await lstat(reports),actual=await realpath(reports),normal=p=>process.platform==='win32'?p.toLowerCase():p;
  if(info.isSymbolicLink()||normal(actual)!==normal(reports))throw Error('unsafe_vet_report_directory');
  let failed=false;
  for(const scope of opts.scopes){
    const report=join(reports,scope+'.json');
    await rm(report,{force:true});
    await rm(join(reports,scope+'.receipt.json'),{force:true});
    const common=['--manifest-path',join(root,manifests[scope]),'--store-path',join(root,'supply-chain',scope),'--no-registry-suggestions'];
    const files={cargo_lock:join(root,manifests[scope].replace('Cargo.toml','Cargo.lock')),
      config:join(root,'supply-chain',scope,'config.toml'),audits:join(root,'supply-chain',scope,'audits.toml'),imports:join(root,'supply-chain',scope,'imports.lock')};
    const hashes=async()=>Object.fromEntries(await Promise.all(Object.entries(files).map(async([key,path])=>[key,digest(await readFile(path))])));
    const before=await hashes();
    let code=0,stderr='';
    const runtime={cwd:root,env:{...process.env,CARGO:cargo},windowsHide:true,maxBuffer:4*1024*1024,timeout:15*60*1000};
    try{
      if(opts.update)stderr+=(await run(tool.path,['vet','regenerate','imports',...common],runtime)).stderr;
      stderr+=(await run(tool.path,['vet','check',...common,'--locked','--output-format','json','--output-file',report],runtime)).stderr;
    }
    catch(error){code=Number.isInteger(error.code)?error.code:1;stderr=error.stderr??error.message;}
    await writeFile(join(reports,scope+'.stderr.log'),stderr);
    let result=null;try{result=JSON.parse(await readFile(report,'utf8'));}catch{}
    const after=await hashes();
    const unchanged=before.cargo_lock===after.cargo_lock&&(opts.update||JSON.stringify(before)===JSON.stringify(after));
    const passed=unchanged&&successfulVet(code,result);failed ||= !passed;
    await writeFile(join(reports,scope+'.receipt.json'),JSON.stringify({version:1,scope,tool_version:tool.version,
      tool_sha256:tool.sha256,archive_sha256:tool.archive_sha256,exit_code:code,locked_imports:true,refreshed_imports:opts.update,
      input_hashes:after,inputs_unchanged:unchanged,status:passed?'check_passed':'failed',
      evidence:{commit:process.env.GITHUB_SHA??null,run:process.env.GITHUB_RUN_ID??null,attempt:process.env.GITHUB_RUN_ATTEMPT??null}},null,2)+'\n');
    console.log(JSON.stringify({scope,status:passed?'check_passed':'failed',exit_code:code,gaps:result?.failures?.length??null}));
  }
  if(failed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
