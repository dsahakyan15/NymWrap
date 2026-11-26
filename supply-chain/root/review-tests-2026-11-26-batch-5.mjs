// Synthetic dependency review only; never opens NymWrap data or a credential store.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const here=path.dirname(fileURLToPath(import.meta.url)),root=path.resolve(here,'../..');
const base=path.join(root,'target','root-review-5-tests');
fs.mkdirSync(base,{recursive:true});
const unreachable=['blocking@1.7.0','event-listener@5.4.2','hermit-abi@0.5.3',
 'nix@0.29.0','openssl@0.10.82','rsqlite-vfs@0.2.0','secret-service@4.0.0',
 'sqlite-wasm-rs@0.6.3','uds_windows@1.2.1','zbus@4.4.0','zbus_macros@4.4.0',
 'zbus_names@3.0.0','zvariant@4.2.0'];
const reachability=[];
for(const spec of unreachable)for(const features of [[],['--all-features']]){
 const args=['tree','--locked','--offline','--target','all','-e','normal,build,dev','-i',spec,...features];
 const r=spawnSync('cargo',args,{cwd:root,encoding:'utf8',windowsHide:true,timeout:60000});
 reachability.push({command:['cargo',...args],exit_code:r.status,stdout:r.stdout??'',stderr:r.stderr??''});
 if(r.status!==0||r.stdout.trim())throw Error('Root non-reachability exception invalid: '+spec);
}
fs.writeFileSync(path.join(base,'reachability.json'),JSON.stringify(reachability,null,2)+'\n');
const source=JSON.stringify(path.join(here,'review-tests-2026-11-26-batch-5.rs').replaceAll('\\','/'));
fs.writeFileSync(path.join(base,'Cargo.toml'),`[package]\nname="root-review-5"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[lib]\npath=${source}\n[dependencies]\nphf_generator={version="=0.14.0",features=["ptrhash"]}\nphf_shared={version="=0.14.0",features=["ptrhash"]}\nphf_codegen="=0.14.0"\n`);
if(!fs.existsSync(path.join(base,'Cargo.lock')))fs.copyFileSync(path.join(root,'Cargo.lock'),path.join(base,'Cargo.lock'));
const results=[];
for(const features of [[],['--release']]){
 const args=['test','--offline','--manifest-path',path.join(base,'Cargo.toml'),'--lib',...features];
 const r=spawnSync('cargo',args,{cwd:root,encoding:'utf8',windowsHide:true,
  env:{...process.env,CARGO_BUILD_JOBS:'4'},timeout:180000,maxBuffer:8*1024*1024});
 const log=path.join(base,features.length?'release.log':'debug.log');
 fs.writeFileSync(log,(r.stdout??'')+(r.stderr??''));
 const result={command:['cargo',...args],exit_code:r.status,error:r.error?.message??null,
  stdout:r.stdout??'',log:path.relative(root,log)};
 results.push(result);console.log(JSON.stringify(result));
 if(r.status!==0)break;
}
fs.writeFileSync(path.join(base,'results.json'),JSON.stringify(results,null,2)+'\n');
console.log(JSON.stringify({non_reachability_checks:reachability.length}));
if(results.some(r=>r.exit_code!==0))process.exitCode=1;
