// Synthetic, local-only checks for ADR 0102 batch 6. Never opens application data.
// Uses already cached, checksum-verified packages; writes only below target/.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const base=path.join(root,'target/root-review-6-tests');fs.mkdirSync(base,{recursive:true});
const registry=path.join(process.env.CARGO_HOME??path.join(os.homedir(),'.cargo'),'registry');
const index=fs.readdirSync(path.join(registry,'src')).find(n=>n.startsWith('index.crates.io-'));
const source=(n,v)=>path.join(registry,'src',index,`${n}-${v}`);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const expected={errno:['0.3.15',''],siphasher:['1.0.4','']};
const report=JSON.parse(fs.readFileSync(path.join(root,'supply-chain/root/review-2026-11-26-batch-6.json'),'utf8'));
for(const [n,p] of Object.entries(expected)){
 const r=report.packages.find(r=>r.name===n),archive=path.join(registry,'cache',index,`${n}-${p[0]}.crate`);
 if(sha(fs.readFileSync(archive))!==r.archive_sha256)throw Error(`archive mismatch: ${n}`);
 // Check every packaged file in the source directory used to compile tests.
 for(const f of r.rust_files){if(sha(fs.readFileSync(path.join(source(n,p[0]),f.path)))!==f.sha256)throw Error(`source mismatch: ${n}/${f.path}`);}
}
const rustPath=s=>s.replaceAll('\\','/');
fs.writeFileSync(path.join(base,'Cargo.toml'),`[package]
name = "nymwrap-root-review-6-tests"
version = "0.0.0"
edition = "2021"
publish = false
[workspace]
[dependencies]
errno = { path = ${JSON.stringify(rustPath(source('errno','0.3.15')))} }
siphasher = { path = ${JSON.stringify(rustPath(source('siphasher','1.0.4')))}, features = ["serde"] }
serde_json = "=1.0.154"
`);
fs.mkdirSync(path.join(base,'src'),{recursive:true});
fs.writeFileSync(path.join(base,'build.rs'),'fn main() { println!("cargo:rustc-cfg=ossl300"); println!("cargo:rustc-check-cfg=cfg(ossl300)"); }\n');
const ssl=source('openssl-sys','0.9.118');
// Include the actual reviewed implementation, rather than restating its formula.
for(const f of ['src/err.rs','src/macros.rs']){const r=report.packages.find(p=>p.name==='openssl-sys').rust_files.find(r=>r.path===f);if(sha(fs.readFileSync(path.join(ssl,f)))!==r.sha256)throw Error('openssl-sys source mismatch');}
fs.writeFileSync(path.join(base,'src/lib.rs'),String.raw`
#![allow(dead_code, non_snake_case)]
#[macro_use]
#[path = "${rustPath(path.join(ssl,'src/macros.rs'))}"]
mod ssl_macros;
#[path = "${rustPath(path.join(ssl,'src/err.rs'))}"]
mod ssl_err;

#[cfg(test)] mod tests {
 use std::hash::Hasher;
 use siphasher::{sip, sip128::{self, Hasher128}};
 #[test] fn errno_round_trip_and_unknown_error_formatting() {
  let saved=errno::errno();
  for code in [0,1,13,87, i32::MAX, i32::MIN, -1] {
   errno::set_errno(errno::Errno(code)); assert_eq!(errno::errno().0,code);
   assert!(!errno::Errno(code).to_string().is_empty());
   assert!(!format!("{:?}",errno::Errno(code)).is_empty());
  }
  errno::set_errno(saved);
 }
 macro_rules! split64 { ($t:ty) => {{
  let bytes:Vec<u8>=(0..257).map(|n|(n*73) as u8).collect();
  for len in 0..=256 { let input=&bytes[..len];
   let full=<$t>::new_with_keys(0x0123456789abcdef,0xfedcba9876543210).hash(input);
   for at in 0..=len { let mut h=<$t>::new_with_keys(0x0123456789abcdef,0xfedcba9876543210);
    h.write(&input[..at]); h.write(&[]); h.write(&input[at..]);
    assert_eq!(h.finish(),full,"length={len} split={at}"); assert_eq!(h.clone().finish(),full);
   }
  }
 }}; }
 macro_rules! split128 { ($t:ty) => {{
  let bytes:Vec<u8>=(0..257).map(|n|(n*73) as u8).collect();
  for len in 0..=256 { let input=&bytes[..len];
   let full=<$t>::new_with_keys(0x0123456789abcdef,0xfedcba9876543210).hash(input);
   for at in 0..=len { let mut h=<$t>::new_with_keys(0x0123456789abcdef,0xfedcba9876543210);
    h.write(&input[..at]); h.write(&[]); h.write(&input[at..]);
    assert_eq!(h.finish128(),full,"length={len} split={at}"); assert_eq!(h.clone().finish128(),full);
   }
  }
 }}; }
 #[test] fn sip64_streaming_all_tail_boundaries() {split64!(sip::SipHasher);split64!(sip::SipHasher13);split64!(sip::SipHasher24);}
 #[test] fn sip128_streaming_all_tail_boundaries() {split128!(sip128::SipHasher);split128!(sip128::SipHasher13);split128!(sip128::SipHasher24);}
 #[test] fn integer_writes_match_native_endian_bytes() {
  for prefix in 0..8 { for value in [0u64,1,u64::MAX,0x0123456789abcdef] {
   let head=vec![0xa5;prefix];let mut a=sip::SipHasher24::new();let mut b=a;
   a.write(&head);b.write(&head);a.write_u64(value);b.write(&value.to_ne_bytes());assert_eq!(a.finish(),b.finish());
   let mut a=sip128::SipHasher13::new();let mut b=a;
   a.write(&head);b.write(&head);a.write_u64(value);b.write(&value.to_ne_bytes());assert_eq!(a.finish128(),b.finish128());
  }}
 }
 #[test] fn serde_valid_state_round_trips_but_untrusted_state_is_not_validated() {
  let mut a=sip::SipHasher24::new_with_keys(1,2);a.write(b"abc");
  let mut value=serde_json::to_value(a).unwrap();
  let mut b:sip::SipHasher24=serde_json::from_value(value.clone()).unwrap();a.write(b"tail");b.write(b"tail");assert_eq!(a.finish(),b.finish());
  value["hasher"]["ntail"]=serde_json::json!(8);
  let mut invalid:sip::SipHasher24=serde_json::from_value(value).unwrap();
  let result=std::panic::catch_unwind(move || invalid.write_u8(1));
  if cfg!(debug_assertions) { assert!(result.is_err(),"malformed state must reproduce the debug panic"); }
  // Release masks the shift; it still does not validate the deserialized state.
 }
 #[test] fn openssl_sys_system_reason_disagrees_with_official_openssl_3_6_3() {
  let code=super::ssl_err::ERR_SYSTEM_FLAG|13;
  assert_eq!(super::ssl_err::ERR_GET_LIB(code),2);
  assert_eq!(super::ssl_err::ERR_GET_REASON(code),2);
  assert_ne!(super::ssl_err::ERR_GET_REASON(code),13);
  // OpenSSL's verified include/openssl/err.h.in returns code & ERR_SYSTEM_MASK, i.e. 13.
 }
}
`);
const results=[];
function run(name,exe,args,env={}){
 const r=spawnSync(exe,args,{cwd:root,env:{...process.env,...env},encoding:'utf8',windowsHide:true,maxBuffer:8*1024*1024});
 fs.writeFileSync(path.join(base,`${name}.log`),(r.stdout??'')+(r.stderr??''));
 const result={name,command:[exe,...args],exit_code:r.status,error:r.error?.message??null,stdout:r.stdout,log:`target/root-review-6-tests/${name}.log`};results.push(result);
 fs.writeFileSync(path.join(base,'results.json'),JSON.stringify(results,null,2)+'\n');
 console.log(JSON.stringify({name,exit_code:r.status,summary:r.stdout?.match(/test result:.*|running \d+ tests/g)}));if(r.status!==0)throw Error(`${name} failed`);
}
const cargo=execFileSync('rustup',['which','cargo'],{encoding:'utf8',windowsHide:true}).trim();
const rustc=execFileSync('rustup',['which','rustc'],{encoding:'utf8',windowsHide:true}).trim();
const toolchainEnv={RUSTC:rustc,RUSTDOC:path.join(path.dirname(rustc),process.platform==='win32'?'rustdoc.exe':'rustdoc')};
for(const release of [false,true]){
 const mode=release?'release':'debug',exe=path.join(base,`siphasher-upstream-${mode}${process.platform==='win32'?'.exe':''}`);
 run(`siphasher-upstream-compile-${mode}`,rustc,['--test','--edition=2018','--cfg','feature="std"',...(release?['-O']:[]),path.join(source('siphasher','1.0.4'),'src/lib.rs'),'-o',exe]);
 run(`siphasher-upstream-${mode}`,exe,[]);
 run(`review-${mode}`,cargo,['test','--offline','--manifest-path',path.join(base,'Cargo.toml'),'--lib',...(release?['--release']:[])],toolchainEnv);
}
