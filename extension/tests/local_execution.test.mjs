import {test} from 'node:test';
import assert from 'node:assert/strict';
import {LocalExecutor} from '../dist/local_execution.js';
import {localTarget,localPageStep} from '../dist/local_page.js';
const task={plan_hash:'a'.repeat(64),stage:1,day:1,action_index:0,service:'chatgpt',text:'<script>synthetic garden</script>'};
const target=service=>`https://127.0.0.1:4443/drift-fixtures/${service}/`;
function fixture(){
  const f={clock:0,mode:'assisted',ai:false,paused:false,permission:true,claimed:false,commands:[],created:[],steps:[],navigated:[],closed:[]};
  f.hooks={
    bridge:()=>({close(){},async request(command){f.commands.push(command);
      if(command.kind==='status')return {kind:'status',mode:f.mode,ai_web_automation:f.ai,paused:f.paused};
      if(command.kind==='begin_search'){if(f.claimed)throw Error('already_attempted');f.claimed=true;return {kind:'execution',token:'b'.repeat(64)};}
      return {kind:'ack'};
    }}),
    permitted:async()=>f.permission,create:async url=>{f.created.push(url);return 7;},navigate:async(id,url)=>{f.navigated.push(url);},close:async id=>{f.closed.push(id);},
    step:async(id,step)=>{f.steps.push(step);return {state:'ready',video:'synthetic-video',position:f.clock/1000};},
    wait:async(ms,signal)=>{if(signal.aborted)throw Error('execution_interrupted');f.clock+=ms;},now:()=>f.clock,random:()=>0,eventId:()=>'c'.repeat(32),
  };
  f.executor=new LocalExecutor(f.hooks);return f;
}
test('local adapters require extension mode, an explicit AI opt-in and permission before claiming or creating a tab',async()=>{
  for(const service of ['youtube','chatgpt','claude','gemini']){
    const f=fixture();await assert.rejects(f.executor.run({...task,service},target(service)));assert.equal(f.claimed,false);
    f.mode='extension';if(service!=='youtube'){await assert.rejects(f.executor.run({...task,service},target(service)));assert.equal(f.claimed,false);}
    f.ai=true;f.permission=false;await assert.rejects(f.executor.run({...task,service},target(service)));assert.equal(f.created.length,0);
  }
});
test('no adapter reads a nonlocal DOM or accepts credentials, query, fragment, wrong service or HTTP',async()=>{
  for(const url of ['https://chatgpt.com/','http://127.0.0.1/drift-fixtures/chatgpt/','https://localhost/drift-fixtures/chatgpt/','https://127.0.0.1.evil.test/drift-fixtures/chatgpt/','https://x@127.0.0.1/drift-fixtures/chatgpt/',target('claude'),target('chatgpt')+'?x=1',target('chatgpt')+'#x']){
    const f=fixture();await assert.rejects(f.executor.run(task,url));assert.equal(f.commands.length,0);
  }
  assert.equal(localTarget(target('chatgpt'),'chatgpt'),'https://127.0.0.1:4443');
  const previous={location:globalThis.location,document:globalThis.document};
  try{globalThis.location={href:'https://chatgpt.com/'};globalThis.document=new Proxy({},{get(){throw Error('foreign_dom_read');}});
    assert.deepEqual(localPageStep({service:'chatgpt',origin:'https://127.0.0.1:4443',phase:'compose',expected:''}),{state:'unsupported'});
  }finally{Object.assign(globalThis,previous);}
});
test('all local services type only approved text; AI submits once and video uses a canonical local watch URL',async()=>{
  for(const service of ['youtube','chatgpt','claude','gemini']){
    const f=fixture();f.mode='extension';f.ai=true;await f.executor.run({...task,service},target(service));
    assert.deepEqual(f.created,[target(service)]);assert.equal(f.steps.filter(s=>s.letter!==undefined).map(s=>s.letter).join(''),task.text);
    assert.equal(f.steps.filter(s=>s.phase==='submit').length,service==='youtube'?0:1);
    assert.equal(f.steps.filter(s=>s.phase==='play').length,service==='youtube'?1:0);
    assert.equal(f.commands.at(-1).kind,'finish_search');assert.ok(f.clock>=20000+60*task.text.length);
    assert.ok(f.navigated.every(url=>new URL(url).origin==='https://127.0.0.1:4443'));
  }
});
test('CAPTCHA, login, revoked opt-in, permission or pause stop during reading without completing',async()=>{
  for(const service of ['youtube','chatgpt','claude','gemini'])for(const reason of ['challenge','login','opt_in','permission','paused','lost_reply']){
    const f=fixture();f.mode='extension';f.ai=true;const original=f.hooks.step;
    f.hooks.step=async(id,step)=>{
      const reply=await original(id,step);
      if(['watch','sent'].includes(step.phase)){
        if(['challenge','login'].includes(reason))return {state:reason};
        if(reason==='lost_reply')return {state:'unsupported'};
        if(reason==='opt_in'){if(service==='youtube')f.mode='assisted';else f.ai=false;}
        if(reason==='permission')f.permission=false;if(reason==='paused')f.paused=true;
      }return reply;
    };
    await assert.rejects(f.executor.run({...task,service},target(service)));
    assert.ok(!f.commands.some(c=>c.kind==='finish_search'));
    assert.deepEqual(f.commands.at(-1),{kind:'pause',paused:true});
    if(['challenge','login'].includes(reason))assert.deepEqual(f.commands.find(c=>c.kind==='safety_stop'),{kind:'safety_stop',event_id:'c'.repeat(32),reason:reason==='challenge'?'captcha':'login'});
    assert.equal(f.steps.filter(s=>s.phase==='submit').length,service==='youtube'?0:1);
  }
});
test('a frozen video or lost submission reply never reports success or replays',async()=>{
  for(const service of ['youtube','chatgpt']){
    const f=fixture();f.mode='extension';f.ai=true;
    f.hooks.step=async(id,step)=>{f.steps.push(step);return {state:step.phase==='submit'?'unsupported':'ready',video:'synthetic-video',position:0};};
    await assert.rejects(f.executor.run({...task,service},target(service)));
    await assert.rejects(f.executor.run({...task,service},target(service)),/already_attempted/);
    assert.equal(f.created.length,1);assert.ok(!f.commands.some(c=>c.kind==='finish_search'));
  }
});
test('loss of scripting access closes only the executor-created video tab so playback cannot continue',async()=>{
  const f=fixture();f.mode='extension';const original=f.hooks.step;
  f.hooks.step=async(id,step)=>{if(step.phase==='watch'||step.phase==='stop')throw Error('permission_revoked');return original(id,step);};
  await assert.rejects(f.executor.run({...task,service:'youtube'},target('youtube')));
  assert.deepEqual(f.closed,[7]);assert.ok(!f.commands.some(c=>c.kind==='finish_search'));
});
