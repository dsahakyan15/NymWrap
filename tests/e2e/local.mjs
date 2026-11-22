// Opt-in: exercises the real OS key store and pinned local GGUFs. Synthetic data only.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtempSync,mkdirSync,readFileSync,readdirSync,statSync} from 'node:fs';
import {resolve,dirname,join,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import http from 'node:http';
import net from 'node:net';
import {createHash} from 'node:crypto';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
if(!process.argv.includes('--with-os-keystore'))throw Error('explicit_os_keystore_test_flag_required');
const executable=name=>resolve(root,process.argv.includes('--release')?'app/src-tauri/target/release':'target/debug',name+(process.platform==='win32'?'.exe':''));
const chat=process.argv.includes('--model-7b')?JSON.parse(readFileSync(resolve(root,'target/test-models/qwen2.5-7b-q4_k_m.merged.json'),'utf8')):{file:'qwen2.5-0.5b-instruct-q4_k_m.gguf',sha256:'74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db'};
if(!/^[a-zA-Z0-9_.-]+\.gguf$/.test(chat.file)||!/^[0-9a-f]{64}$/.test(chat.sha256)||process.argv.includes('--model-7b')&&chat.file!=='qwen2.5-7b-instruct-q4_k_m.gguf')throw Error('invalid_e2e_chat_model');
const fixture=mkdtempSync(resolve(root,'target/e2e-'));
const env={...process.env,LOCALAPPDATA:fixture,XDG_DATA_HOME:fixture,XDG_RUNTIME_DIR:join(fixture,'runtime')};
mkdirSync(env.XDG_RUNTIME_DIR,{recursive:true,mode:0o700});
const children=[];
const start=(name,args=[])=>{const child=spawn(executable(name),args,{cwd:root,env,stdio:['ignore','ignore','pipe'],windowsHide:true});children.push(child);let codes='';child.stderr.on('data',b=>{codes+=b.toString().slice(0,100);});child.on('error',()=>{});return child;};
function rpc(command){return new Promise((accept,reject)=>{
  const child=spawn(executable('nymwrap'),['rpc'],{cwd:root,env,stdio:['pipe','pipe','pipe'],windowsHide:true});
  const timer=setTimeout(()=>{child.kill();reject(Error('rpc_timeout'));},240_000);let output='',error='';
  child.stdout.on('data',b=>{output+=b;if(output.length>16*1024*1024)child.kill();});child.stderr.on('data',b=>{error+=b;});
  child.once('error',reject);child.once('exit',code=>{clearTimeout(timer);if(code!==0)reject(Error(command.op+': '+(error.trim()||'rpc_failed')));else{try{accept(JSON.parse(output));}catch{reject(Error('invalid_rpc_json'));}}});
  child.stdin.end(JSON.stringify(command));
});}
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function api(endpoint,body,path='/v1/chat/completions',method='POST',headers={}){return new Promise((accept,reject)=>{
  const text=body===undefined?'':JSON.stringify(body);
  const agent=new http.Agent();agent.createConnection=()=>net.createConnection(process.platform==='win32'&&!endpoint.startsWith('\\\\')?'\\\\.\\pipe\\'+endpoint:endpoint);
  const request=http.request({host:'localhost',path,method,agent,headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(text),...headers}},response=>{
    let data='';response.on('data',b=>data+=b);response.once('end',()=>{agent.destroy();try{accept({status:response.statusCode,headers:response.headers,body:data?JSON.parse(data):null});}catch{reject(Error('invalid_api_response'));}});
  });request.setTimeout(180_000,()=>request.destroy(Error('api_timeout')));request.on('error',reject);request.end(text);
});}
async function endpointGone(endpoint){return new Promise(accept=>{
  const socket=net.createConnection(process.platform==='win32'&&!endpoint.startsWith('\\\\')?'\\\\.\\pipe\\'+endpoint:endpoint);
  socket.once('connect',()=>{socket.destroy();accept(false);});socket.once('error',()=>accept(true));
});}
async function nativeCall(command,id=17){return new Promise((accept,reject)=>{
  const host=spawn(executable('nw-drift-host'),[],{cwd:root,env,stdio:['pipe','pipe','ignore'],windowsHide:true});let output=Buffer.alloc(0);
  const timer=setTimeout(()=>{host.kill();reject(Error('native_timeout'));},10_000);host.stdout.on('data',b=>{output=Buffer.concat([output,b]);if(output.length>256*1024)host.kill();});host.once('error',reject);host.once('exit',code=>{clearTimeout(timer);if(code!==0)return reject(Error('native_failed'));try{assert.equal(output.readUInt32LE(0),output.length-4);const reply=JSON.parse(output.subarray(4));assert.equal(reply.id,id);assert.equal(reply.version,1);accept(reply.result);}catch{reject(Error('invalid_native_response'));}});
  const packet=Buffer.from(JSON.stringify({version:1,id,command}));const size=Buffer.alloc(4);size.writeUInt32LE(packet.length);host.stdin.end(Buffer.concat([size,packet]));
});}
let created=false,store;
try{
  // Never connect this test to a previously running user's daemon.
  let existing=false;try{await rpc({op:'status'});existing=true;}catch{}
  if(existing)throw Error('daemon_already_running_close_it_before_test');
  let daemon=start('nymwrapd');
  for(let attempt=0;attempt<100;attempt++){try{await rpc({op:'status'});break;}catch{if(daemon.exitCode!==null||attempt===99)throw Error('daemon_start_failed');await delay(100);}}
  const opened=await rpc({op:'open_workspace',password:'',create:true,profile:'standard'});created=true;store=opened.path;
  assert.equal(opened.unlocked,true);assert.ok(resolve(store).startsWith(resolve(fixture)+sep));
  const imported=await rpc({op:'audit_import',content:Buffer.from('[{"title":"Synthetic <script>data</script>","titleUrl":"https://example.test/lesson","time":"2026-01-01T12:00:00Z"}]').toString('base64'),format:'takeout',encoding:'base64'});
  assert.equal(imported.records,1);assert.equal(imported.titles[0],'Synthetic <script>data</script>');
  const purgeBatch={service:'google',record_ids:[createHash('sha256').update(imported.titles[0]).digest('hex')]};
  const purgeHash=await rpc({op:'purge_hash',batch:purgeBatch});
  await assert.rejects(rpc({op:'record_purge_result',hash:purgeHash,outcome:'still_visible',completed_steps:[]}),/plan_approval_required/);
  await rpc({op:'approve_purge',batch:purgeBatch,hash:purgeHash});
  const purgeGuide=await rpc({op:'purge_guide',service:'google'});assert.ok(purgeGuide.steps.some(s=>s.id==='verify'));
  await rpc({op:'record_purge_result',hash:purgeHash,outcome:'no_longer_visible',completed_steps:['history','verify']});
  assert.equal((await rpc({op:'load_purge_batches'}))[0].review.outcome,'no_longer_visible');
  const keys=await rpc({op:'add_provider_key',key:'synthetic-e2e-provider-token-only'});assert.equal(keys.length,1);assert.equal(keys[0].state,'available');
  await rpc({op:'save_secrets',secrets:[{kind:'PERSON',value:'Synthetic Tester',local_only:false}]});
  const config=await rpc({op:'load_config'});
  Object.assign(config.llm,{model_path:resolve(root,'target/test-models',chat.file),model_sha256:'0'.repeat(64),embed_path:resolve(root,'target/test-models/nomic-embed-text-v1.5.Q4_K_M.gguf'),embed_sha256:'d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac'});
  await rpc({op:'save_config',config});await assert.rejects(rpc({op:'start_model'}),/model_start_failed/);
  config.llm.model_sha256=chat.sha256;await rpc({op:'save_config',config});
  assert.equal((await rpc({op:'start_model'})).model_managed,true);
  const apiEndpoint=config.llm.endpoint.replace(/llm(?=(?:\.sock)?$)/,'api');
  const apiProcess=start('nw-api');
  for(let attempt=0;attempt<50;attempt++){if(!await endpointGone(apiEndpoint))break;if(apiProcess.exitCode!==null||attempt===49)throw Error('api_start_failed');await delay(100);}
  const vectors=await rpc({op:'embeddings',texts:['Synthetic pottery lesson']});
  assert.equal(vectors[0].length,768);
  const reviewConfig=structuredClone(config);reviewConfig.shield.show_diff_before_send=true;
  reviewConfig.net={transport:'tor',provider_host:'example.com',provider_path:'/',provider_model:'synthetic-test-only',credential_ref:'keyring:pool',max_request_cost_microusd:1};
  await rpc({op:'save_config',config:reviewConfig});
  const asyncInput={model:'nw/remote/default',messages:[{role:'user',content:'Explain pottery for Synthetic Tester.'}],max_tokens:32};
  assert.equal((await api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs')).body.error.code,'approval_required');
  const review=await rpc({op:'review_remote',conversation:'new',messages:[{role:'user',content:'Explain pottery for Synthetic Tester.'}],max_tokens:32});
  assert.equal(review.status,'review');assert.equal(review.provider_host,'example.com');assert.ok(!review.review.transcript.includes('Synthetic Tester'));
  assert.equal((await rpc({op:'load_network_usage'})).requests,0);
  await rpc({op:'cancel_remote',approval_id:review.review.approval_id});
  await assert.rejects(rpc({op:'approve_remote',approval_id:review.review.approval_id,hash:review.review.hash}),/approval_required/);
  assert.equal((await rpc({op:'load_network_usage'})).requests,0);
  const queueConfig=structuredClone(reviewConfig);queueConfig.shield.show_diff_before_send=false;
  Object.assign(queueConfig.cover,{enabled:true,mode:'constant',mean_interval_s:3600});
  await rpc({op:'save_config',config:queueConfig});
  const denied=await api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs','POST',{'x-nymwrap-min-trust':'L1'});
  assert.equal(denied.status,403);assert.equal(denied.body.error.code,'trust_policy_violation');
  const idempotency={'idempotency-key':'SYNTHETIC_E2E_IDEMPOTENCY_KEY_0113'};
  const localIdempotency={'idempotency-key':'SYNTHETIC_E2E_LOCAL_RECEIPT_0113'};
  const queued=await api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs','POST',idempotency);
  assert.equal(queued.status,202);assert.equal(queued.body.object,'nymwrap.job');assert.equal(queued.body.status,'queued');
  assert.ok(!JSON.stringify(queued.body).includes('Synthetic Tester'));
  assert.ok(!JSON.stringify(queued).includes(idempotency['idempotency-key']));
  const countBeforeReplay=(await rpc({op:'load_remote_jobs'})).length;
  const replays=await Promise.all([api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs','POST',idempotency),api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs','POST',idempotency)]);
  for(const replay of replays){assert.equal(replay.status,202);assert.equal(replay.body.id,queued.body.id);}
  assert.equal((await rpc({op:'load_remote_jobs'})).length,countBeforeReplay);
  const conflict=await api(apiEndpoint,{...asyncInput,max_tokens:31},'/v1/nymwrap/chat/jobs','POST',idempotency);
  assert.equal(conflict.status,409);assert.equal(conflict.body.error.code,'idempotency_conflict');
  assert.equal((await api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs','POST',{...idempotency,'x-nymwrap-min-trust':'L0'})).status,409);
  assert.equal((await api(apiEndpoint,undefined,queued.body.poll_url,'GET')).body.status,'queued');
  assert.equal((await api(apiEndpoint,undefined,queued.body.poll_url,'DELETE')).status,204);
  assert.equal((await api(apiEndpoint,undefined,queued.body.poll_url,'GET')).body.status,'cancelled');
  assert.equal((await api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs','POST',idempotency)).body.status,'cancelled');
  const sensitiveInput={...asyncInput,messages:[{role:'user',content:'Explain a medical diagnosis.'}]};
  const sensitive=await api(apiEndpoint,sensitiveInput,'/v1/nymwrap/chat/jobs','POST',localIdempotency);
  assert.equal(sensitive.status,200);assert.equal(sensitive.body.nymwrap.trust,'L0');
  assert.deepEqual((await api(apiEndpoint,sensitiveInput,'/v1/nymwrap/chat/jobs','POST',localIdempotency)).body,sensitive.body);
  const disclosureCanary='Synthetic Qeravina Zoltessa';
  const disclosure=await api(apiEndpoint,{...asyncInput,messages:[{role:'user',content:`My name is ${disclosureCanary}. Explain pottery.`}]},'/v1/nymwrap/chat/jobs');
  assert.equal(disclosure.status,200);assert.equal(disclosure.body.nymwrap.trust,'L0');
  assert.equal((await rpc({op:'load_network_usage'})).requests,0);
  await rpc({op:'save_config',config});
  const priorJobs=(await rpc({op:'load_remote_jobs'})).length;
  console.log('PASS: async private HTTP honors human review and min trust; queued canary is cancelled without network; sensitive input stays L0');
  console.log('PASS: real CPU model review is private, cancellable and spends no network budget');
  console.log('PASS: an unknown personal-disclosure canary stays L0 through the actual CPU/HTTP path without a network reservation');
  if(process.argv.includes('--with-tor')){
    config.net={transport:'tor',provider_host:'example.com',provider_path:'/',provider_model:'synthetic-test-only',credential_ref:'keyring:pool',max_request_cost_microusd:1};
    await rpc({op:'save_config',config});
    const firstReview=await rpc({op:'review_remote',conversation:'new',messages:[{role:'user',content:'Explain pottery.'}],max_tokens:32});assert.equal(firstReview.status,'review');
    let firstJob=await rpc({op:'start_remote_job',approval_id:firstReview.review.approval_id,hash:firstReview.review.hash});
    for(let attempt=0;attempt<700&&['queued','sending'].includes(firstJob.info.state);attempt++){await delay(500);firstJob=await rpc({op:'load_remote_job',id:firstJob.info.id});}
    assert.equal(firstJob.info.state,'uncertain');assert.equal(firstJob.info.code,'remote_transport_unavailable');
    await assert.rejects(rpc({op:'start_remote_job',approval_id:firstReview.review.approval_id,hash:firstReview.review.hash}),/approval_required/);
    const usage=await rpc({op:'load_network_usage'});assert.equal(usage.requests,1);assert.equal(usage.reserved_microusd,1);
    console.log('PASS: actual Tor HTTPS rejection is terminal and its single attempt is durably reserved');
    await rpc({op:'add_provider_key',key:'synthetic-e2e-second-provider-token-only'});
    const secondReview=await rpc({op:'review_remote',conversation:'new',messages:[{role:'user',content:'Explain clay.'}],max_tokens:32});assert.equal(secondReview.status,'review');
    const interrupted=await rpc({op:'start_remote_job',approval_id:secondReview.review.approval_id,hash:secondReview.review.hash});
    let reserved=false;for(let attempt=0;attempt<200;attempt++){const usage=await rpc({op:'load_network_usage'});if(usage.requests===2){reserved=true;break;}await delay(100);}
    assert.equal(reserved,true);daemon.kill();
    const endpoint=config.llm.endpoint.replace(/llm(?=(?:\.sock)?$)/,'net');
    let stopped=false;for(let attempt=0;attempt<100;attempt++){if(await endpointGone(endpoint)){stopped=true;break;}await delay(50);}assert.equal(stopped,true);
    daemon=start('nymwrapd');for(let attempt=0;attempt<50;attempt++){try{await rpc({op:'status'});break;}catch{if(attempt===49)throw Error('crash_restart_failed');await delay(100);}}
    await rpc({op:'open_workspace',password:'',create:false,profile:'standard'});assert.equal((await rpc({op:'load_network_usage'})).requests,2);await rpc({op:'start_model'});
    const recovered=await rpc({op:'load_remote_job',id:interrupted.info.id});assert.equal(recovered.info.state,'uncertain');assert.equal(recovered.info.code,'previous_session_ended');
    assert.equal((await rpc({op:'load_remote_job_input',id:interrupted.info.id})).at(-1).content,'Explain clay.');assert.equal((await rpc({op:'load_remote_jobs'})).length,priorJobs+2);
    console.log('PASS: killing core stops the egress child and preserves the uncertain attempt without replay');
  }
  let response;
  for(let attempt=0;attempt<50;attempt++){try{response=await api(apiEndpoint,{model:'nw/local/default',messages:[{role:'user',content:'Tell Synthetic Tester what 2 + 2 equals. Answer briefly.'}],max_tokens:32});break;}catch{if(apiProcess.exitCode!==null||attempt===49)throw Error('api_start_failed');await delay(100);}}
  assert.equal(response.status,200);assert.equal(response.body.nymwrap.trust,'L0');
  const conversation=response.headers['x-nymwrap-conversation'];assert.match(conversation,/^[a-f0-9]{32}$/);
  const history=await rpc({op:'load_history',conversation});assert.equal(history.length,2);assert.ok(history[1].content.length>0);
  await rpc({op:'lock'});
  for(let attempt=0;attempt<50&&daemon.exitCode===null;attempt++)await delay(50);
  assert.notEqual(daemon.exitCode,null);daemon=start('nymwrapd');
  for(let attempt=0;attempt<50;attempt++){try{await rpc({op:'status'});break;}catch{if(attempt===49)throw Error('daemon_restart_failed');await delay(100);}}
  await rpc({op:'open_workspace',password:'',create:false,profile:'standard'});
  assert.equal((await rpc({op:'start_model'})).model_managed,true);
  const resumedReceipt=await api(apiEndpoint,asyncInput,'/v1/nymwrap/chat/jobs','POST',idempotency);
  assert.equal(resumedReceipt.body.id,queued.body.id);assert.equal(resumedReceipt.body.status,'cancelled');
  assert.deepEqual((await api(apiEndpoint,sensitiveInput,'/v1/nymwrap/chat/jobs','POST',localIdempotency)).body,sensitive.body);
  console.log('PASS: durable HTTP idempotency reuses queued/cancelled and L0 results across restart; conflicting payloads and trust headers never send');
  assert.equal((await rpc({op:'load_purge_batches'}))[0].review.outcome,'no_longer_visible');
  console.log('PASS: offline service-specific Purge instructions and explicitly approved batch observations survive real core restart');
  assert.deepEqual(await rpc({op:'load_history',conversation}),history);
  const continuation=await rpc({op:'chat',conversation,messages:[...history,{role:'user',content:'Repeat only the resulting number.'}],max_tokens:16});
  assert.equal(continuation.conversation,conversation);assert.equal(continuation.trust,'L0');
  assert.equal((await nativeCall({kind:'status'})).kind,'status');
  const stop={kind:'safety_stop',event_id:'a'.repeat(32),reason:'captcha'};
  assert.equal((await nativeCall(stop,18)).kind,'ack');
  assert.equal((await nativeCall(stop,19)).kind,'ack');
  assert.equal((await nativeCall({kind:'status'},20)).paused,true);
  const stoppedOverview=(await rpc({op:'workspace_status'})).overview;
  assert.equal(stoppedOverview.metrics.challenge_rate,1);
  assert.equal(stoppedOverview.metrics.cover_ratio,null);
  assert.equal((await nativeCall({kind:'pause',paused:false},21)).kind,'ack');
  console.log('PASS: cover safety stop pauses real core, carries no page text and updates observed Mirror metrics');
  // Close SQLCipher handles for a consistent at-rest scan; restart for cleanup.
  await rpc({op:'lock'});
  for(let attempt=0;attempt<50&&daemon.exitCode===null;attempt++)await delay(50);
  for(const file of readdirSync(store)){const path=join(store,file);if(statSync(path).isFile()){const bytes=readFileSync(path);for(const marker of ['Synthetic Tester',disclosureCanary,'Synthetic <script>','resulting number',idempotency['idempotency-key'],localIdempotency['idempotency-key']])assert.ok(!bytes.includes(Buffer.from(marker)),'plaintext_persisted');}}
  console.log('PASS: daemon + isolated import protocol + CPU model + private HTTP API + encrypted resume + cover native host');
  daemon=start('nymwrapd');for(let attempt=0;attempt<50;attempt++){try{await rpc({op:'status'});break;}catch{if(attempt===49)throw Error('cleanup_daemon_failed');await delay(100);}}
}finally{
  if(created){try{const status=await rpc({op:'workspace_status'});if(resolve(status.path)===resolve(store)){if(!status.unlocked)await rpc({op:'open_workspace',password:'',create:false,profile:'standard'});await rpc({op:'destroy_data',confirmation:'СТЕРЕТЬ ВСЁ'});}}catch{console.error('synthetic_fixture_cleanup_failed');process.exitCode=1;}}
  for(const child of children.reverse())child.kill();
}
