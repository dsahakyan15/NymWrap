// Synthetic source-review probes only; no NymWrap data, accounts or network.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import vm from 'node:vm';
const root=resolve(import.meta.dirname,'../..'),base=join(root,'target/desktop5/probes');
mkdirSync(join(base,'src'),{recursive:true});
writeFileSync(join(base,'Cargo.toml'),`[package]
name = "desktop5-source-probes"
version = "0.0.0"
edition = "2021"
[workspace]
[dependencies]
serialize-to-javascript = "=0.1.2"
serde_json = { version = "=1.0.154", features = ["raw_value"] }
recvmsg = "=1.0.0"
`);
writeFileSync(join(base,'src/main.rs'),String.raw`
use recvmsg::{MsgBuf, msgbuf::{OwnedBuf, OwnedBufRawParts}};
use serialize_to_javascript::{Options, Serialized, Template};
use std::{ptr::NonNull, sync::atomic::{AtomicUsize, Ordering}};

// The allocation is deliberately leaked. Drop records ownership releases without
// freeing or inspecting it, so even duplicate releases do not execute UAF/double-free.
static RELEASES: AtomicUsize = AtomicUsize::new(0);
struct LedgerOwner(OwnedBufRawParts);
unsafe impl OwnedBuf for LedgerOwner {
    unsafe fn from_raw_parts(raw: OwnedBufRawParts) -> Self { Self(raw) }
    fn as_raw_parts(&self) -> OwnedBufRawParts { self.0 }
    fn grow(&mut self, _: usize) { panic!("not used in this probe") }
}
impl Drop for LedgerOwner {
    fn drop(&mut self) { if self.0.cap > 0 { RELEASES.fetch_add(1, Ordering::SeqCst); } }
}
#[derive(Template)]
struct Pair<'a> { a: &'a str, b: &'a str }

fn main() {
    let allocation = Box::leak(vec![0x42u8; 32].into_boxed_slice());
    let owner = LedgerOwner(OwnedBufRawParts {
        ptr: NonNull::new(allocation.as_mut_ptr()).unwrap(), cap: 32, init: 32,
    });
    let buf = MsgBuf::from(owner);
    let moved = match buf.try_extend_lifetime() { Ok(b) => b, Err(_) => panic!("owned") };
    let premature = RELEASES.load(Ordering::SeqCst);
    drop(moved);
    println!("{}",serde_json::json!({"kind":"recvmsg_ownership","premature_releases":premature,"total_releases":RELEASES.load(Ordering::SeqCst)}));

    let mut values = vec![serde_json::json!(null),serde_json::json!(true),serde_json::json!(42),serde_json::json!({"value":"'\\\";globalThis.canary=1;//</script>\u{2028}\u{2029}"})];
    for text in ["", "'", "\\", "\\'", "\0\r\n", "__TEMPLATE_b__", "</script><script>", "😀e\u{301}"] { values.push(serde_json::json!(text)); }
    // Every Unicode scalar, in one synthetic string, covers all UTF-8 widths and boundaries.
    let unicode:String=(0..=0x10ffff).filter_map(char::from_u32).collect();
    values.push(serde_json::json!(unicode));
    for value in values {
        let raw=serde_json::value::to_raw_value(&value).unwrap();
        for freeze in [false,true] {
            let expression=Serialized::new(&raw,&Options{freeze,buf:17}).into_string();
            println!("{}",serde_json::json!({"kind":"escape","value":value,"expression":expression,"freeze":freeze}));
        }
    }
    let ordinary=Pair{a:"first",b:"second"}.render("[__TEMPLATE_a__,__TEMPLATE_b__]",&Options::default()).unwrap().into_string();
    let collision=Pair{a:"__TEMPLATE_b__",b:"second"}.render("[__TEMPLATE_a__,__TEMPLATE_b__]",&Options::default()).unwrap().into_string();
    println!("{}",serde_json::json!({"kind":"template","ordinary":ordinary,"collision":collision}));
}
`);
const run=(args)=>execFileSync('cargo',args,{cwd:base,windowsHide:true,encoding:'utf8',maxBuffer:64*1024*1024});
run(['generate-lockfile','--offline']);
const records=run(['run','--locked','--offline','--quiet']).trim().split('\n').map(line=>JSON.parse(line));
let escapeChecks=0;
for(const r of records){
 if(r.kind==='escape'){
  const context=vm.createContext({});
  const actual=vm.runInContext(r.expression,context,{timeout:5000});
  assert.equal(JSON.stringify(actual),JSON.stringify(r.value));
  assert.equal(context.canary,undefined);
  if(r.freeze&&actual&&typeof actual==='object')assert.equal(Object.isFrozen(actual),true);
  escapeChecks++;
 }
}
const template=records.find(r=>r.kind==='template');
assert.equal(JSON.stringify(vm.runInNewContext(template.ordinary)),JSON.stringify(['first','second']));
assert.throws(()=>new vm.Script(template.collision),SyntaxError);
const ownership=records.find(r=>r.kind==='recvmsg_ownership');
assert.equal(ownership.premature_releases,1);
assert.equal(ownership.total_releases,2);
const result={escape_checks:escapeChecks,unicode_scalars:1112064,template_collision:{...template,result:'SyntaxError; no code-execution claim'},recvmsg_ownership:ownership,limits:'Windows x86_64, synthetic inputs only. No real D-Bus/registry access, no native SQLCipher execution, no Miri or sanitizer run. The custom owner intentionally leaks 32 bytes to avoid executing undefined behavior.'};
writeFileSync(join(base,'result.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result));
