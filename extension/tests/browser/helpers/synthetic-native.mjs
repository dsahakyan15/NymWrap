export function syntheticNativeHost(task){
  globalThis.syntheticCore={commands:[],events:[],tasks:[task],paused:false,claimed:false,completed:false,snapshots:[]};
  const scripting=chrome.scripting.executeScript;
  chrome.scripting.executeScript=async options=>{
    try{
      const result=await scripting.call(chrome.scripting,options),core=globalThis.syntheticCore;
      core.events.push({kind:'script',func:options.func.name,phase:options.args?.[0]?.phase,args:options.args?.length,result:['searchPageStep','localPageStep'].includes(options.func.name)?result:'capture'});
      if(core.dropNextInput&&options.args?.[0]?.letter!==undefined){core.dropNextInput=false;return [{frameId:0,result:null}];}
      return result;
    }
    catch(error){globalThis.syntheticCore.events.push({kind:'script_error',error:String(error)});throw error;}
  };
  const dispatch=command=>{
    const core=globalThis.syntheticCore;command=structuredClone(command);core.commands.push(command);
    let result={kind:'ack'};
    if(command.kind==='status')result={kind:'status',paused:core.paused,mode:core.mode??'extension',ai_web_automation:core.ai??false};
    else if(command.kind==='tasks')result={kind:'tasks',tasks:core.completed?[]:core.tasks};
    else if(command.kind==='begin_search'){
      if(core.claimed)result={kind:'error',code:'already_attempted'};
      else if(!core.tasks.some(t=>JSON.stringify(t)===JSON.stringify(command.task)))result={kind:'error',code:'invalid_request'};
      else {core.claimed=true;result={kind:'execution',token:'b'.repeat(64)};}
    }else if(command.kind==='validate_search'){
      if(!core.claimed||core.paused||command.token!=='b'.repeat(64))result={kind:'error',code:'invalid_request'};
    }else if(command.kind==='finish_search'){core.completed=true;}
    else if(command.kind==='pause')core.paused=command.paused;
    else if(command.kind==='safety_stop')core.paused=true;
    else if(command.kind==='snapshot')core.snapshots.push(command.snapshot);
    return result;
  };
  chrome.runtime.onMessage.addListener((message,sender,respond)=>{
    if(message?.kind==='synthetic_control'&&sender.id===chrome.runtime.id&&['probe.html','popup.html'].some(p=>sender.url===chrome.runtime.getURL(p))){
      const core=globalThis.syntheticCore;
      if(message.op==='state'){respond(structuredClone(core));return false;}
      if(message.op==='task'){core.tasks=[message.task];core.completed=false;core.claimed=false;core.paused=false;core.mode=message.mode??'extension';core.ai=message.ai??false;core.commands=[];core.events=[];respond(true);return false;}
      if(message.op==='alarm'){Promise.resolve(chrome.alarms.create('nymwrap-mirror-hourly-v1',{when:Date.now()+100})).then(()=>respond(true));return true;}
      if(message.op==='storage'){chrome.storage.local.get(null).then(respond);return true;}
      return false;
    }
    if(message?.kind!=='synthetic_native_bridge'||sender.id!==chrome.runtime.id)return false;
    respond(dispatch(message.command));return false;
  });
  chrome.runtime.connectNative=()=>{
    let live=true;const receivers=[],disconnects=[];
    return {
      onMessage:{addListener:fn=>receivers.push(fn)},onDisconnect:{addListener:fn=>disconnects.push(fn)},
      disconnect(){if(live){live=false;for(const fn of disconnects)fn();}},
      postMessage(packet){
        const result=dispatch(packet.command);
        queueMicrotask(()=>{if(live)for(const fn of receivers)fn({version:1,id:packet.id,result});});
      },
    };
  };
  // Deterministic lower-end delays still use real timers and real DOM input events.
  crypto.getRandomValues=array=>{array.fill(0);return array;};
}
