// Isolated review harness under target/; repository Cargo manifests/lockfiles stay untouched.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'../..'),base=path.join(root,'target','root-review-4-tests');
fs.mkdirSync(base,{recursive:true});
const reachability=[];
for(const name of ['async-broadcast','zvariant_derive'])for(const features of [[],['--all-features']]){
 const args=['tree','--locked','--offline','--target','all','-i',name,'-e','normal,build,dev',...features];
 const r=spawnSync('cargo',args,{cwd:root,encoding:'utf8',windowsHide:true,timeout:60000});
 const result={command:['cargo',...args],exit_code:r.status,stdout:r.stdout??'',stderr:r.stderr??''};
 reachability.push(result);
 // The exemptions are invalid if any active normal/build/dev path is introduced.
 if(r.status!==0||r.stdout.trim())throw Error('root exemption reachability changed: '+name);
}
fs.writeFileSync(path.join(base,'reachability.json'),JSON.stringify(reachability,null,2)+'\n');
const source=JSON.stringify(path.join(here,'review-tests-2026-11-26-batch-4.rs').replaceAll('\\','/'));
fs.writeFileSync(path.join(base,'Cargo.toml'),`[package]\nname="root-review-4"\nversion="0.0.0"\nedition="2021"\n[workspace]\n[lib]\npath=${source}\n[dependencies]\nlibloading="=0.8.9"\nasync-broadcast="=0.7.2"\nzvariant="=4.2.0"\n`);
if(!fs.existsSync(path.join(base,'Cargo.lock')))fs.copyFileSync(path.join(root,'Cargo.lock'),path.join(base,'Cargo.lock'));
const results=[];
for(const extra of [[],['--release']]){
 const args=['test','--offline','--manifest-path',path.join(base,'Cargo.toml'),'--lib',...extra];
 const r=spawnSync('cargo',args,{cwd:root,encoding:'utf8',windowsHide:true,
  env:{...process.env,CARGO_BUILD_JOBS:'4'},timeout:300000,maxBuffer:8*1024*1024});
 const log=path.join(base,extra.length?'release.log':'debug.log');
 fs.writeFileSync(log,(r.stdout??'')+(r.stderr??''));
 const result={command:['cargo',...args],exit_code:r.status,error:r.error?.message??null,
  stdout:r.stdout??'',log:path.relative(root,log)};
 results.push(result);console.log(JSON.stringify(result));
 if(r.status!==0)break;
}
fs.writeFileSync(path.join(base,'results.json'),JSON.stringify(results,null,2)+'\n');
if(results.some(r=>r.exit_code!==0))process.exitCode=1;
