import {test} from 'node:test';
import assert from 'node:assert/strict';
import {MirrorScheduler,scheduleState,youtubeHome} from '../dist/mirror_schedule.js';
import {readMirrorPage} from '../dist/capture.js';

const ready=()=>({signals:{url:'https://www.youtube.com/',title:'Home',text:'SYNTHETIC_PAGE_BODY_CANARY_19053',hasPassword:false,hasChallenge:false},titles:['<script>synthetic title data</script>']});
function fixture(){
  const f={at:1_000_020,stored:undefined,writes:[],commands:[],captures:0,connections:0,closed:0,permission:true,paused:false,locked:false,tabs:[{id:7,url:'https://www.youtube.com/'}],page:ready()};
  f.hooks={
    load:async()=>f.stored,
    save:async state=>{f.stored=structuredClone(state);f.writes.push(f.stored);},
    permitted:async()=>f.permission,
    bridge:()=>{++f.connections;return {close(){++f.closed;},async request(command){
      f.commands.push(command);
      if(f.locked)throw Error('workspace_locked');
      if(command.kind==='status')return {kind:'status',paused:f.paused,mode:'assisted',ai_web_automation:false};
      if(command.kind==='snapshot'&&f.lostAck)throw Error('bridge_disconnected');
      return {kind:'ack'};
    }};},
    tabs:async()=>f.tabs,
    capture:async()=>{++f.captures;return f.page;},
    now:()=>f.at,
    eventId:()=>'a'.repeat(32),
  };
  f.scheduler=new MirrorScheduler(f.hooks);
  return f;
}
const snapshots=f=>f.commands.filter(c=>c.kind==='snapshot');
test('periodic collection requires an explicit opt-in, permission, ready core and a supported open tab',async()=>{
  const f=fixture();await f.scheduler.tick();assert.equal(f.connections,0);assert.equal(f.captures,0);
  f.permission=false;await assert.rejects(f.scheduler.configure(true),/permission/);await f.scheduler.tick();assert.equal(f.connections,0);
  f.permission=true;await f.scheduler.configure(true);
  f.paused=true;await f.scheduler.tick();assert.equal(f.captures,0);assert.equal((await f.scheduler.status()).code,'paused');
  f.paused=false;f.locked=true;await f.scheduler.tick();assert.equal(f.captures,0);assert.equal((await f.scheduler.status()).code,'locked');
  f.locked=false;f.tabs=[{id:2,url:'https://www.youtube.com/',incognito:true},{id:3,url:'https://www.youtube.com/results?search_query=private'}];
  await f.scheduler.tick();assert.equal(f.captures,0);assert.equal((await f.scheduler.status()).code,'no_tab');
  f.tabs=[{id:7,url:'https://www.youtube.com/'}];await f.scheduler.tick();assert.equal(snapshots(f).length,1);assert.equal(f.connections,f.closed);
});
test('one bounded daily snapshot survives worker restarts, clock rollback and missed days without catch-up',async()=>{
  const f=fixture();f.page.titles=Array(45).fill('<script>synthetic title data</script>');
  await f.scheduler.configure(true);await Promise.all([f.scheduler.tick(),f.scheduler.tick()]);
  assert.equal(f.captures,1);assert.equal(snapshots(f).length,1);
  assert.equal(snapshots(f)[0].snapshot.items.length,30);
  assert.equal(snapshots(f)[0].snapshot.items[0],'<script>synthetic title data</script>');
  assert.ok(!JSON.stringify(f.writes).includes('synthetic title'));
  assert.ok(!JSON.stringify(f.commands).includes('SYNTHETIC_PAGE_BODY_CANARY_19053'));
  for(const state of f.writes)assert.deepEqual(Object.keys(state).sort(),['code','enabled','last_attempt','last_saved']);
  f.scheduler=new MirrorScheduler(f.hooks);f.at+=86340;await f.scheduler.tick();assert.equal(f.captures,1);
  f.at-=86400;await f.scheduler.tick();assert.equal(f.captures,1);
  f.at+=86400*5;await f.scheduler.tick();assert.equal(f.captures,2);await f.scheduler.tick();assert.equal(f.captures,2);
});
test('a lost acknowledgement reserves the day across restart instead of replaying collection',async()=>{
  const f=fixture();f.lostAck=true;await f.scheduler.configure(true);await f.scheduler.tick();assert.equal(f.captures,1);
  f.scheduler=new MirrorScheduler(f.hooks);f.at+=3600;await f.scheduler.tick();assert.equal(f.captures,1);
  assert.equal((await f.scheduler.status()).last_saved,0);assert.equal((await f.scheduler.status()).code,'unavailable');
});
test('challenge and login disable the schedule and report only an opaque stop even if core disconnects',async()=>{
  for(const reason of ['captcha','login']){
    const f=fixture();f.page.signals[reason==='captcha'?'hasChallenge':'hasPassword']=true;
    await f.scheduler.configure(true);await f.scheduler.tick();
    assert.equal((await f.scheduler.status()).enabled,false);assert.equal((await f.scheduler.status()).code,reason);
    assert.deepEqual(f.commands.at(-1),{kind:'safety_stop',event_id:'a'.repeat(32),reason});assert.equal(snapshots(f).length,0);
    f.scheduler=new MirrorScheduler(f.hooks);f.at+=86400;await f.scheduler.tick();assert.equal(f.captures,1);
    assert.ok(!JSON.stringify(f.commands).includes('SYNTHETIC_PAGE_BODY_CANARY_19053'));
  }
});
test('disabling or revoking permission during DOM capture prevents submission and stale settings writes',async()=>{
  for(const disable of [true,false]){
    const f=fixture();let release,started;
    const pending=new Promise(resolve=>release=resolve),reading=new Promise(resolve=>started=resolve);
    f.hooks.capture=async()=>{++f.captures;started();await pending;return f.page;};
    await f.scheduler.configure(true);const work=f.scheduler.tick();await reading;
    if(disable)await f.scheduler.configure(false);else f.permission=false;
    release();await work;assert.equal(snapshots(f).length,0);
    if(disable)assert.equal(f.stored.enabled,false);
  }
  const f=fixture();await f.scheduler.configure(true);f.permission=false;await f.scheduler.tick();
  assert.equal(f.captures,0);assert.equal((await f.scheduler.status()).code,'permission_required');assert.equal(f.stored.enabled,false);
});
test('navigation to unsupported pages and malformed stored settings cannot enable collection',async()=>{
  for(const url of ['https://evil.test/','https://www.youtube.com.evil.test/','http://www.youtube.com/','https://u:p@www.youtube.com/','https://www.youtube.com:444/','https://www.youtube.com/watch?v=1'])assert.equal(youtubeHome(url),false);
  assert.equal(youtubeHome('https://www.youtube.com/'),true);
  assert.equal(scheduleState({enabled:true,code:'ready',last_attempt:0,last_saved:0,shadow:'canary'}).enabled,false);
  const f=fixture();f.page.signals.url='https://evil.test/';await f.scheduler.configure(true);await f.scheduler.tick();assert.equal(snapshots(f).length,0);
});
test('fixed DOM reader does not read an unapproved origin and bounds page strings',()=>{
  const oldDocument=globalThis.document,oldLocation=globalThis.location;
  try{
    globalThis.document=new Proxy({},{get(){throw Error('unexpected_dom_read');}});
    for(const href of ['https://evil.test/','https://myadcenter.google.com/']){globalThis.location={href};assert.deepEqual(readMirrorPage().titles,[]);}
    globalThis.location.href='https://www.youtube.com/';
    globalThis.document={title:'x'.repeat(5000),body:{innerText:'y'.repeat(20000)},querySelector:()=>null,querySelectorAll:()=>Array(40).fill({textContent:'synthetic card'})};
    const result=readMirrorPage();assert.equal(result.signals.title.length,1024);assert.equal(result.signals.text.length,12000);assert.equal(result.titles.length,30);
  }finally{globalThis.document=oldDocument;globalThis.location=oldLocation;}
});
