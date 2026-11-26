// Creates only an isolated synthetic Cargo harness below this worktree's target/.
// No application data, downloads, repository manifests or lockfiles are changed.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'../..'),base=path.join(root,'target','root-review-3-tests');
fs.mkdirSync(base,{recursive:true});
const source=path.join(process.env.CARGO_HOME??path.join(os.homedir(),'.cargo'),
 'registry','src','index.crates.io-1949cf8c6b5b557f','web_atoms-0.3.0');
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const entityBytes=fs.readFileSync(path.join(source,'entities.rs'));
const entityText=entityBytes.toString('utf8');
const grammar=/^pub static NAMED_ENTITIES: \[\(&str, u32, u32\); 2231\] = \[\r?\n((?:    \("&[A-Za-z][A-Za-z0-9]*;?", [0-9]+, [0-9]+\),\r?\n)+)\];\r?\n?$/;
if(!grammar.test(entityText))throw Error('entities contain unreviewed Rust syntax');
const entities=[...entityText.matchAll(/\("(&[A-Za-z][A-Za-z0-9]*;?)", ([0-9]+), ([0-9]+)\)/g)];
const scalar=n=>n>0&&n<=0x10ffff&&!(n>=0xd800&&n<=0xdfff);
if(entities.length!==2231||new Set(entities.map(x=>x[1])).size!==2231||
 entities.some(x=>!scalar(Number(x[2]))||Number(x[3])!==0&&!scalar(Number(x[3]))))throw Error('invalid entity data');
const namesBytes=fs.readFileSync(path.join(source,'local_names.txt'));
const names=namesBytes.toString('utf8').trimEnd().split(/\r?\n/);
if(names.some(n=>! /^(?:\*|[A-Za-z_][A-Za-z0-9_.:-]*)$/.test(n)))throw Error('unexpected local-name data');
const dataCheck={method:'Strict full-file grammar, not eval or Rust execution; table mapping semantics not individually compared to the HTML standard',
 entities:entities.length,entities_sha256:digest(entityBytes),local_names:names.length,local_names_sha256:digest(namesBytes)};
fs.writeFileSync(path.join(base,'data-check.json'),JSON.stringify(dataCheck,null,2)+'\n');
console.log(JSON.stringify({data_check:dataCheck}));
const q=s=>JSON.stringify(s.replaceAll('\\','/'));
const runtime={
 'async-recursion':'1.2.0','async-broadcast':'0.7.2','constant_time_eq':'0.6.1',
 'dtoa-short':'0.3.5','memoffset':'0.9.1','rustc-hash':'2.1.3',
 'serde_json':'1.0.154','ordered-stream':'0.2.0','zvariant':'4.2.0',
};
const manifest=`[package]\nname="root-source-review-3"\nversion="0.0.0"\nedition="2021"\nbuild=${q(path.join(here,'review-build-2026-11-26-batch-3.rs'))}\n[workspace]\n[lib]\npath=${q(path.join(here,'review-tests-2026-11-26-batch-3.rs'))}\n[dependencies]\n${Object.entries(runtime).map(([n,v])=>`${n}="=${v}"`).join('\n')}\nenumflags2={version="=0.7.12",features=["serde","std"]}\nphf={version="=0.14.0",features=["macros"]}\n[build-dependencies]\nphf_codegen="=0.14.0"\n[features]\nptrhash=["phf/ptrhash","phf_codegen/ptrhash"]\n`;
fs.writeFileSync(path.join(base,'Cargo.toml'),manifest);
if(!fs.existsSync(path.join(base,'Cargo.lock')))fs.copyFileSync(path.join(root,'Cargo.lock'),path.join(base,'Cargo.lock'));
const command=['test','--offline','--manifest-path',path.join(base,'Cargo.toml'),'--lib'];
const results=[];
for(const extra of [[],['--release'],['--features','ptrhash']]){
 const args=[...command,...extra];
 const result=spawnSync('cargo',args,{cwd:root,encoding:'utf8',windowsHide:true,timeout:300000,maxBuffer:16*1024*1024});
 const id=extra.length?extra.join('-').replaceAll('--',''):'debug';
 fs.writeFileSync(path.join(base,id+'.log'),(result.stdout??'')+(result.stderr??''));
 const summary={command:['cargo',...args],exit_code:result.status,error:result.error?.message??null,stdout:result.stdout??'',log:path.relative(root,path.join(base,id+'.log'))};
 results.push(summary);console.log(JSON.stringify(summary));
 if(result.status!==0)break;
}
fs.writeFileSync(path.join(base,'results.json'),JSON.stringify(results,null,2)+'\n');
if(results.some(x=>x.exit_code!==0))process.exitCode=1;
