import {test} from 'node:test';
import assert from 'node:assert/strict';
const tick=()=>new Promise(resolve=>setImmediate(resolve));
test('background configuration accepts only the extension popup and persists event metadata',async()=>{
  const previous=globalThis.chrome;let stored={},message;const alarms=new Map();
  const event=()=>({addListener(){}});
  globalThis.chrome={
    runtime:{id:'synthetic-extension',getURL:p=>'chrome-extension://synthetic-extension/'+p,onStartup:event(),onInstalled:event(),onMessage:{addListener:fn=>message=fn}},
    alarms:{async get(name){return alarms.get(name);},async create(name,value){alarms.set(name,value);},async clear(name){return alarms.delete(name);},onAlarm:event()},
    storage:{local:{async get(){return stored;},async set(value){stored={...stored,...structuredClone(value)};}}},
    permissions:{async contains(){return true;},onRemoved:event()},
  };
  try{
    await import('../dist/background.js');await tick();
    const sender={id:'synthetic-extension',url:'chrome-extension://synthetic-extension/popup.html'};
    assert.equal(message({kind:'mirror_configure',enabled:true},{id:sender.id,url:'https://www.youtube.com/'},()=>{throw Error('response_to_page');}),false);
    assert.equal(message({kind:'mirror_configure',enabled:true},{...sender,id:'other'},()=>{}),false);
    assert.equal(message({kind:'mirror_configure',enabled:true,shadow:'canary'},sender,()=>{}),false);
    const call=command=>new Promise(resolve=>{assert.equal(message(command,sender,resolve),true);});
    assert.equal((await call({kind:'mirror_status'})).enabled,false);
    assert.equal((await call({kind:'mirror_configure',enabled:true})).enabled,true);assert.equal(alarms.size,1);
    assert.equal((await call({kind:'mirror_configure',enabled:false})).enabled,false);assert.equal(alarms.size,0);
    assert.deepEqual(Object.keys(stored['mirror-schedule-v1']).sort(),['code','enabled','last_attempt','last_saved']);
  }finally{globalThis.chrome=previous;}
});
