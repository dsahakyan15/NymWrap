// Reproduce the provenance comparisons of ADR 0102 batch 6; never builds native code.
// Default: use verified archives already cached in target/root-review-6.
// --fetch-upstream permits HTTPS downloads of the exact recorded upstream artifacts.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const base=path.join(root,'target/root-review-6');fs.mkdirSync(base,{recursive:true});
if(process.argv.slice(2).some(a=>a!=='--fetch-upstream'))throw Error('invalid option');
const fetch=process.argv.includes('--fetch-upstream');
const report=JSON.parse(fs.readFileSync(path.join(root,'supply-chain/root/review-2026-11-26-batch-6.json'),'utf8'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const registry=path.join(process.env.CARGO_HOME??path.join(os.homedir(),'.cargo'),'registry');
const index=fs.readdirSync(path.join(registry,'src')).find(n=>n.startsWith('index.crates.io-'));
function cached(name){
 const record=report.upstream_downloads.find(r=>r.name===name&&r.status==='200');
 if(!record)throw Error(`missing successful artifact: ${name}`);
 const file=path.join(base,name);
 if(!fs.existsSync(file)){
  if(!fetch)throw Error(`missing ${name}; use --fetch-upstream`);
  const status=execFileSync('curl.exe',['-L','--silent','--show-error','--max-time','120','-A','NymWrap-root-supply-chain-review/6 (local educational dependency audit)','-w','%{http_code}','-o',file,record.url],{encoding:'utf8',windowsHide:true});
  if(status!=='200')throw Error(`HTTP ${status}: ${record.url}`);
 }
 if(sha(fs.readFileSync(file))!==record.sha256)throw Error(`artifact checksum mismatch: ${name}`);
 return file;
}
function files(dir,rel=''){
 return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>{
  const r=path.posix.join(rel,e.name);
  if(e.isDirectory())return files(path.join(dir,e.name),r);
  if(e.isFile())return [r];
  throw Error(`special source entry: ${r}`);
 });
}
const mappings=[
 ['openssl-src','openssl.tar.gz','openssl-3.6.3','openssl',2425,0,3],
 ['libdbus-sys','dbus-tag-gitlab.tar.gz','dbus-dbus-1.14.4','vendor/dbus',304,0,0],
 ['libsqlite3-sys','sqlite.zip','sqlite-amalgamation-3540100','sqlite3',3,0,3],
 ['llama-cpp-sys-2','llama.tar.gz','llama.cpp-d81235049384534c167caea52b85a694f6103d14','llama.cpp',1908,0,0],
 ['libtomcrypt','libtomcrypt-release.zip','libtomcrypt-1.18.2/src','sqlcipher/libtomcrypt',425,0,0],
];
const results=[];
for(const [name,archive,prefix,native,wantEqual,wantDifferent,wantAbsent] of mappings){
 const pkg=report.packages.find(p=>p.name===(name==='libtomcrypt'?'sqlcipher-src':name));
 const packaged=path.join(registry,'cache',index,`${pkg.name}-${pkg.version}.crate`);
 if(sha(fs.readFileSync(packaged))!==pkg.archive_sha256)throw Error(`crate checksum mismatch: ${pkg.name}`);
 const local=path.join(registry,'src',index,`${pkg.name}-${pkg.version}`,native);
 const out=path.join(base,'recheck',name);fs.mkdirSync(out,{recursive:true});
 const arc=cached(archive);
 const entries=execFileSync('tar',['-tf',arc],{encoding:'utf8',maxBuffer:16*1024*1024}).trim().split(/\r?\n/);
 if(entries.some(n=>n.startsWith('/')||n.includes('\\')||n.split('/').includes('..')))throw Error('unsafe archive entry');
 // Only this exact, hashed upstream archive is extracted, in a dedicated target directory.
 execFileSync('tar',['-xf',arc,'-C',out],{windowsHide:true});
 const upstream=path.join(out,prefix),equal=[],different=[],absent=[];
 for(const f of files(local)){
  const l=fs.readFileSync(path.join(local,f)),u=path.join(upstream,f);
  if(!fs.existsSync(u)){absent.push(f);continue;}
  if(l.equals(fs.readFileSync(u)))equal.push([f,sha(l)]);else different.push(f);
 }
 const digest=sha(JSON.stringify(equal.sort((a,b)=>a[0].localeCompare(b[0]))));
 const old=report.native_comparisons.find(r=>r.name===name);
 if(equal.length!==wantEqual||different.length!==wantDifferent||absent.length!==wantAbsent)throw Error(`native comparison changed: ${name}`);
 if(name!=='libtomcrypt'&&digest!==old.matched_file_manifest_sha256)throw Error(`native tree digest changed: ${name}`);
 results.push({name,matched_files:equal.length,different,absent,matched_file_manifest_sha256:digest});
 console.log(JSON.stringify(results.at(-1)));
}
const ssl=report.packages.find(p=>p.name==='openssl-src');
for(const [artifact,filename] of [['openssl.clang-format','.clang-format'],['openssl.codespellrc','.codespellrc'],['openssl.pre-commit-config.yaml','.pre-commit-config.yaml']]){
 if(!fs.readFileSync(cached(artifact)).equals(fs.readFileSync(path.join(registry,'src',index,`${ssl.name}-${ssl.version}`,'openssl',filename))))throw Error(`OpenSSL tooling mismatch: ${filename}`);
}
const checksum=fs.readFileSync(cached('openssl.sha256'),'utf8').trim().split(/\s+/)[0];
if(checksum!==sha(fs.readFileSync(cached('openssl.tar.gz'))))throw Error('official OpenSSL checksum mismatch');
fs.writeFileSync(path.join(base,'native-recheck.json'),JSON.stringify({comparisons:results,openssl_tag_dotfiles:3,openssl_release_checksum_matches:true,sqlcipher_amalgamation:'NOT VERIFIED',llama_release_tag:'NOT VERIFIED'},null,2)+'\n');
// SQLCipher generated output and release qualification of llama remain failures to establish provenance.
