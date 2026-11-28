// Opt-in: exercises the real OS key store and pinned local GGUFs. Synthetic data only.
// `nymwrap rpc` is disabled by authorized RPC sessions (ADR 0076), so the flow is
// driven from Rust through the same Client::spawn_daemon path as the desktop UI:
// crates/nw-core/tests/desktop_flow.rs. Close a running desktop first.
import {spawnSync} from 'node:child_process';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
if(!process.argv.includes('--with-os-keystore'))throw Error('explicit_os_keystore_test_flag_required');
for(const flag of process.argv.slice(2))if(!['--with-os-keystore','--model-7b'].includes(flag))throw Error('unsupported_e2e_flag');
const env={...process.env,NYMWRAP_E2E_OS_KEYSTORE:'1'};
// --model-7b: the prepared merged 7B GGUF (target/test-models/qwen2.5-7b-q4_k_m.merged.json).
if(process.argv.includes('--model-7b'))env.NYMWRAP_E2E_CHAT_MODEL='7b';else delete env.NYMWRAP_E2E_CHAT_MODEL;
const cargo=(args)=>{const run=spawnSync('cargo',args,{cwd:root,env,stdio:'inherit',windowsHide:true});if(run.status!==0)process.exit(run.status??1);};
cargo(['build','--workspace','--bins','--locked']);
cargo(['test','-p','nw-core','--test','desktop_flow','--locked','--','--ignored','--nocapture']);
