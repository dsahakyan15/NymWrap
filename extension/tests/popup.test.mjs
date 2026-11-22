import {test} from "node:test";
import assert from "node:assert/strict";
const tick=()=>new Promise(resolve=>setImmediate(resolve));
class Element {
  listeners=new Map();children=[];hidden=false;disabled=false;textContent="";
  addEventListener(name,callback){this.listeners.set(name,callback);}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
  click(){if(!this.disabled)return this.listeners.get("click")?.();}
}
test("CAPTCHA capture stays local; explicit safety report pauses Drift and sends only an opaque id",async()=>{
  const ids=["status","titles","bridge-status","tasks-list","connect","tasks","pause","save-snapshot","capture","report-stop","periodic-status","periodic-mirror","execution-status","stop-execution"];
  const elements=Object.fromEntries(ids.map(id=>[id,new Element()]));
  const sent=[];let receive;
  const previousDocument=globalThis.document,previousChrome=globalThis.chrome;
  globalThis.document={querySelector:selector=>elements[selector.slice(1)],createElement:()=>new Element()};
  globalThis.chrome={
    runtime:{connectNative(){return {postMessage:m=>sent.push(m),disconnect(){},onMessage:{addListener:callback=>receive=callback},onDisconnect:{addListener(){}}};}},
    tabs:{async query(){return [{id:7,url:"https://www.youtube.com/"}];}},
    scripting:{async executeScript(){return [{result:{signals:{url:"https://www.youtube.com/",title:"CAPTCHA",text:"SYNTHETIC_PAGE_CANARY_51206",hasPassword:false,hasChallenge:true},titles:[]}}];}},
  };
  try {
    await import("../dist/popup.js");
    await elements.capture.click();
    assert.equal(sent.length,0);
    assert.equal(elements["report-stop"].hidden,false);
    assert.equal(elements["report-stop"].disabled,true);
    elements.connect.click();
    receive({version:1,id:1,result:{kind:"status",paused:false,mode:"assisted",ai_web_automation:false}});
    await tick();
    assert.equal(elements["report-stop"].disabled,false);
    elements["report-stop"].click();
    assert.equal(sent.length,2);
    assert.deepEqual(Object.keys(sent[1].command).sort(),["event_id","kind","reason"]);
    assert.match(sent[1].command.event_id,/^[a-f0-9]{32}$/);
    assert.equal(sent[1].command.kind,"safety_stop");
    assert.equal(sent[1].command.reason,"captcha");
    assert.ok(!JSON.stringify(sent).includes("SYNTHETIC_PAGE_CANARY_51206"));
    elements["report-stop"].click();assert.equal(sent.length,2);
    receive({version:1,id:2,result:{kind:"ack"}});await tick();
    assert.equal(elements.pause.textContent,"Продолжить");
    assert.match(elements["bridge-status"].textContent,/Drift на паузе/);
    assert.equal(elements["tasks-list"].children.length,0);
  } finally {globalThis.document=previousDocument;globalThis.chrome=previousChrome;}
});
