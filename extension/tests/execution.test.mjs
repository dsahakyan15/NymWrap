import {test} from 'node:test';
import assert from 'node:assert/strict';
import {SearchExecutor,searchOrigins} from '../dist/execution.js';
import {searchPageStep} from '../dist/search_page.js';
const task={plan_hash:'a'.repeat(64),stage:1,day:1,action_index:0,service:'google',text:'synthetic pottery & gardens'};
function fixture(){
  const f={clock:0,mode:'extension',paused:false,permission:true,commands:[],created:[],navigated:[],steps:[],waits:[],closed:0,claimed:false};
  f.hooks={
    bridge:()=>({close(){++f.closed;},async request(command){
      f.commands.push(command);
      if(command.kind==='status')return {kind:'status',paused:f.paused,mode:f.mode,ai_web_automation:false};
      if(command.kind==='begin_search'){if(f.claimed)throw Error('already_attempted');f.claimed=true;return {kind:'execution',token:'b'.repeat(64)};}
      return {kind:'ack'};
    }}),
    permitted:async()=>f.permission,
    create:async url=>{f.created.push(url);return 7;},
    navigate:async(id,url)=>{f.navigated.push(url);},
    step:async(id,step)=>{f.steps.push(step);return 'ready';},
    wait:async(ms,signal)=>{if(signal.aborted)throw Error('execution_interrupted');f.waits.push(ms);f.clock+=ms;},
    now:()=>f.clock,random:()=>0.5,eventId:()=>'c'.repeat(32),
  };
  f.executor=new SearchExecutor(f.hooks);return f;
}
test('explicit search uses a one-shot grant, bounded typing and reading, checked URL and repeated policy validation',async()=>{
  for(const service of ['google','youtube']){
    const f=fixture();await f.executor.run({...task,service});
    assert.deepEqual(f.created,[service==='google'?'https://www.google.com/':'https://www.youtube.com/']);
    const url=new URL(f.navigated[0]);assert.equal(url.searchParams.get(service==='google'?'q':'search_query'),task.text);
    const letters=f.steps.filter(s=>s.letter!==undefined);assert.equal(letters.map(s=>s.letter).join(''),task.text);
    let prefix='';for(const step of letters){assert.equal(step.expected,prefix);prefix+=step.letter;}
    assert.ok(f.waits.slice(0,letters.length).every(ms=>ms>=60&&ms<=180));
    assert.ok(f.clock>=20000+60*letters.length&&f.clock<=90000+180*letters.length);
    assert.equal(f.commands.filter(c=>c.kind==='begin_search').length,1);
    assert.ok(f.commands.filter(c=>c.kind==='validate_search').length>letters.length);
    assert.equal(f.commands.at(-1).kind,'finish_search');assert.equal(f.commands.at(-1).token,'b'.repeat(64));assert.equal(f.closed,1);
  }
});
test('assisted mode, missing permission, AI and long actions cannot create a browser side effect',async()=>{
  for(const mode of ['assisted','permission']){
    const f=fixture();if(mode==='assisted')f.mode=mode;else f.permission=false;
    await assert.rejects(f.executor.run(task));assert.equal(f.claimed,false);assert.equal(f.created.length,0);
  }
  const f=fixture();await assert.rejects(f.executor.run({...task,service:'chatgpt'}));await assert.rejects(f.executor.run({...task,text:'x'.repeat(513)}));assert.equal(f.commands.length,0);
  assert.throws(()=>searchOrigins('gemini'));
});
test('CAPTCHA/login during reading stop and pause without completing or reporting page data',async()=>{
  for(const state of ['challenge','login']){
    const f=fixture();f.hooks.step=async(id,step)=>step.results?state:'ready';
    await assert.rejects(f.executor.run(task));assert.equal(f.commands.some(c=>c.kind==='finish_search'),false);
    assert.deepEqual(f.commands.find(c=>c.kind==='safety_stop'),{kind:'safety_stop',event_id:'c'.repeat(32),reason:state==='challenge'?'captcha':'login'});
    assert.deepEqual(f.commands.at(-1),{kind:'pause',paused:true});assert.equal(f.closed,1);
  }
});
test('cancellation, a changed input or revoked permission cannot replay a claimed action',async()=>{
  for(const reason of ['cancel','changed','permission']){
    const f=fixture();let calls=0;
    f.hooks.step=async(id,step)=>{
      if(step.letter!==undefined&&++calls===2){if(reason==='cancel')f.executor.cancel();if(reason==='permission')f.permission=false;if(reason==='changed')return 'unsupported';}
      return 'ready';
    };
    await assert.rejects(f.executor.run(task));assert.equal(f.navigated.length,0);assert.equal(f.commands.some(c=>c.kind==='finish_search'),false);
    f.executor=new SearchExecutor(f.hooks);f.permission=true;await assert.rejects(f.executor.run(task),/already_attempted/);assert.equal(f.created.length,1);
  }
});
test('only one action runs per background instance',async()=>{
  const f=fixture();let release,waiting;
  const gate=new Promise(resolve=>release=resolve),started=new Promise(resolve=>waiting=resolve);
  f.hooks.wait=async()=>{waiting();await gate;};
  const work=assert.rejects(f.executor.run(task));await started;
  await assert.rejects(f.executor.run(task),/request_in_progress/);f.executor.cancel();release();await work;
  assert.equal(f.created.length,1);
});
test('fixed page adapter preserves task text as data and stops before modifying existing or challenged input',()=>{
  const old={document:globalThis.document,location:globalThis.location,InputEvent:globalThis.InputEvent};
  try{
    let challenge=false,password=false;
    const input={tagName:'TEXTAREA',disabled:false,readOnly:false,value:'',focus(){},dispatchEvent(event){assert.equal(event.type,'input');}};
    globalThis.InputEvent=class{constructor(type){this.type=type;}};
    globalThis.location={href:'https://www.google.com/'};
    globalThis.document={title:'Home',body:{innerText:'SYNTHETIC_PAGE_CANARY_31457'},visibilityState:'visible',readyState:'complete',querySelector(selector){if(selector.includes('iframe'))return challenge?{}:null;if(selector.includes('password'))return password?{}:null;return input;}};
    assert.equal(searchPageStep({service:'google',expected:'',letter:'<',results:false}),'ready');assert.equal(input.value,'<');
    assert.equal(searchPageStep({service:'google',expected:'',letter:'X',results:false}),'unsupported');assert.equal(input.value,'<');
    challenge=true;assert.equal(searchPageStep({service:'google',expected:'<',letter:'X',results:false}),'challenge');assert.equal(input.value,'<');
    challenge=false;password=true;assert.equal(searchPageStep({service:'google',expected:'<',results:false}),'login');
    globalThis.location.href='https://evil.test/';globalThis.document=new Proxy({},{get(){throw Error('unapproved_dom_read');}});
    assert.equal(searchPageStep({service:'google',expected:'',results:false}),'unsupported');
  }finally{Object.assign(globalThis,old);}
});
