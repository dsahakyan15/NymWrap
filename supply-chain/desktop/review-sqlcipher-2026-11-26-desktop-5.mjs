// Partial supplier provenance check; deliberately does not certify native C safety.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'../..');
const out=path.join(root,'target/desktop5/upstream');fs.mkdirSync(out,{recursive:true});
const version='420.0.0+sqlcipher-4.20.0-sqlite-3.54.1-libtomcrypt-1.18.2';
const archiveHash='fd6b5280ed2593d07b2816ec531821c15c306903bcca224716f1fbcc2bbfedfe';
const officialHash='4a93dd9374db45603980efbb96fad7289a26b30ad72d1b54facdd4e1209c5b46';
const tagObject='52252487a5cada9b430e8d4b20025790c5a6ba20';
const commit='355d4db92d3404e71faa8088d071a71d767807f4';
const url=`https://codeload.github.com/sqlcipher/sqlcipher/tar.gz/${tagObject}`;
const sha=b=>createHash('sha256').update(b).digest('hex');
function members(archive){
 const t=gunzipSync(archive),files=new Map();let longName=null;
 for(let off=0;off+512<=t.length;){
  const h=t.subarray(off,off+512);if(h.every(x=>x===0))break;
  const s=(a,b)=>h.subarray(a,b).toString().replace(/\0.*$/s,'');
  const name=longName??((s(345,500)?s(345,500)+'/':'')+s(0,100));
  const len=parseInt(s(124,136).trim()||'0',8),type=s(156,157);
  assert(Number.isSafeInteger(len)&&len>=0&&off+512+len<=t.length);
  const b=t.subarray(off+512,off+512+len);
  if(type==='L')longName=b.toString().replace(/\0.*$/s,'');
  else if(type==='0'||type===''){const relative=name.slice(name.indexOf('/')+1);assert(!relative.split('/').includes('..'));assert(!files.has(relative));files.set(relative,b);longName=null;}
  else assert(['5','g','x'].includes(type),`unexpected member type ${type}`);
  off+=512+Math.ceil(len/512)*512;
 }
 return files;
}
const registry=path.join(process.env.CARGO_HOME??path.join(os.homedir(),'.cargo'),'registry');
const index=fs.readdirSync(path.join(registry,'cache')).find(n=>n.startsWith('index.crates.io-'));
const archive=fs.readFileSync(path.join(registry,'cache',index,`sqlcipher-src-${version}.crate`));
assert.equal(sha(archive),archiveHash);
const published=members(archive),cached=path.join(out,'sqlcipher-official.tar.gz');
if(!fs.existsSync(cached)){
 assert(!process.argv.includes('--offline'),'official archive not cached');
 const r=await fetch(url,{signal:AbortSignal.timeout(60000)});assert(r.ok);
 const bytes=Buffer.from(await r.arrayBuffer());assert.equal(sha(bytes),officialHash);fs.writeFileSync(cached,bytes);
}
const bytes=fs.readFileSync(cached);assert.equal(sha(bytes),officialHash);
const official=members(bytes),amalgamation=published.get('sqlcipher/sqlcipher.c').toString();
const sums=published.get('sqlcipher/SHA256SUMS').toString().trim().split('\n');
for(const l of sums){const [,hash,name]=l.match(/^([0-9a-f]{64})  (.+)$/);assert.equal(sha(published.get('sqlcipher/'+name)),hash);}
// Reverse only the observed amalgamator transformations. These are not C
// equivalence proofs: include state, linkage and the rest of SQLite remain open.
const normalization='Trailing whitespace; known commented #includes and dontcache comments; sqlcipher.h inline section replaced by its original include; generated SQLITE_API prefixes on int/void sqlite3 entry points; section-marker comments.';
function normalize(s){
 return s.replace(/\/\* #include ([^\n]+) \*\//g,'#include $1')
  .replace(/(?:\/\*|\*\*)\s*amalgamator: dontcache\s*(?:\*\/|\*\*)/g,'')
  .replace(/^\/\*\*\*\*\*.*(?:Include sqlcipher.h in the middle|Continuing where we left off).*\*\/\n/gm,'')
  .replace(/^SQLITE_API ((?:int|void) sqlite3(?:pager_|_)[^\n]*)/gm,'$1')
  .split('\n').map(l=>l.trimEnd()).join('\n').trim();
}
const comparisons=[];
for(const [local,upstream] of [['sqlcipher/LICENSE-sqlcipher','LICENSE.md'],['sqlcipher/sqlite3ext.h','src/sqlite3ext.h']]){
 const a=published.get(local),b=official.get(upstream);assert(a&&b);assert(a.equals(b));
 comparisons.push({local,official:upstream,local_sha256:sha(a),official_sha256:sha(b),byte_equal:true});
}
for(const name of ['sqlcipher.c','sqlcipher.h','crypto_cc.c','crypto_libtomcrypt.c','crypto_openssl.c']){
 const a=official.get('src/'+name);assert(a);
 const start=amalgamation.indexOf(' Begin file '+name+' '),begin=amalgamation.indexOf('\n',start)+1;
 const end=amalgamation.indexOf('/************** End of '+name+' ',begin);assert(start>=0&&end>begin);
 const embedded=amalgamation.slice(begin,end);let flattened=embedded;
 if(name==='sqlcipher.c'){
  const hs=flattened.indexOf('/************** Begin file sqlcipher.h ');
  const he=flattened.indexOf('\n',flattened.indexOf('/************** End of sqlcipher.h ',hs));assert(hs>=0&&he>hs);
  flattened=flattened.slice(0,hs)+'#include "sqlcipher.h"\n'+flattened.slice(he+1);
 }
 const na=normalize(a.toString()),nb=normalize(flattened);assert.equal(sha(na),sha(nb),name);
 comparisons.push({official:'src/'+name,official_sha256:sha(a),embedded_sha256:sha(embedded),normalized_sha256:sha(na),normalized_equal:true});
}
const result={tag:'v4.20.0',tag_object:tagObject,commit,official_archive:{url,sha256:officialHash},published_archive_sha256:archiveHash,self_checksums_verified:sums.length,build_script_present:published.has('build.rs'),build_false_in_manifest:published.get('Cargo.toml').toString().includes('build = false'),normalization,generator_sha256:sha(official.get('tool/mksqlite3c.tcl')),comparisons,complete_amalgamation_match_confirmed:false,native_c_audited_line_by_line:false,signature_verified:false,decision:'требует человеческого решения; no safe-to-deploy audit',limits:'Only the five SQLCipher-specific embedded components plus two unchanged files were compared with the official release. Full SQLite amalgamation regeneration, libtomcrypt supplier equivalence, signature chain, all compiler/include/linkage effects and native C safety remain unverified.'};
fs.writeFileSync(path.join(root,'target/desktop5/sqlcipher-evidence.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({byte_equal:2,normalized_components:5,self_checksums_verified:sums.length,safe_to_deploy:false}));
