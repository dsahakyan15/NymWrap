import {test} from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import vm from "node:vm";

const source=await readFile(new URL("../src/main.ts",import.meta.url),"utf8");
const built=await readFile(new URL("../dist/main.js",import.meta.url),"utf8");
const functionText=name=>built.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`,"m"))[0];
const handlerText=id=>built.match(new RegExp(`on\\("${id}", (async \\(\\) => \\{[^]*?^\\})\\);`,"m"))[1];
function run(text,context={}){
  const sandbox=vm.createContext(context);
  vm.runInContext(text,sandbox);
  return sandbox;
}

// Split a built invoke's arguments/properties at the outer nesting level.
// String bodies (including template text) are data and never evaluated here.
function splitOuter(text,stopAtClose=false){
  const parts=[];let start=0,depth=0,quote=null;
  for(let i=0;i<text.length;i++){
    const c=text[i];
    if(quote){if(c==="\\")i++;else if(c===quote)quote=null;continue;}
    if(c==='"'||c==="'"||c==='`'){quote=c;continue;}
    if("({[".includes(c))depth++;
    if(")}]".includes(c)){
      if(depth===0&&stopAtClose){parts.push(text.slice(start,i).trim());return parts;}
      depth--;
    }
    if(c===","&&depth===0){parts.push(text.slice(start,i).trim());start=i+1;}
  }
  parts.push(text.slice(start).trim());return parts.filter(Boolean);
}

test("every UI invoke is registered in Tauri, forwards to core, and uses Tauri's camelCase arguments",async()=>{
  const rust=await readFile(new URL("../src-tauri/src/main.rs",import.meta.url),"utf8");
  const core=await readFile(new URL("../../crates/nw-core/src/service/mod.rs",import.meta.url),"utf8");
  const handlers=new Map();
  const camel=name=>name.replace(/_([a-z])/g,(_,letter)=>letter.toUpperCase());
  for(const [,name,variant,fields]of rust.matchAll(/command!\((\w+),\s*(\w+),\s*\{([^}]*)\}\)/g)){
    const args=[...fields.matchAll(/(\w+)\s*:(?!:)\s*(Option<)?/g)].map(([,field,optional])=>({name:camel(field),optional:!!optional}));
    handlers.set(name,args);
    assert.match(core,new RegExp(`\\b${variant}\\s*\\{`),`${name} must forward to a real core command`);
  }
  for(const [,name,parameters]of rust.matchAll(/#\[tauri::command\]\s*async fn (\w+)\(([\s\S]*?)\) ->/g)){
    handlers.set(name,[...parameters.matchAll(/(\w+)\s*:(?!:)\s*(Option<)?/g)].filter(([,field])=>field!=="state").map(([,field,optional])=>({name:camel(field),optional:!!optional})));
  }
  const registered=rust.match(/generate_handler!\[([\s\S]*?)\]/)[1];
  const seen=new Set();
  for(const match of built.matchAll(/\binvoke\("([a-z_]+)"/g)){
    const name=match[1];
    seen.add(name);
    assert.ok(handlers.has(name),`unknown Tauri command ${name}`);
    assert.match(registered,new RegExp(`\\b${name}\\b`),`${name} must be registered`);
    const argument=splitOuter(built.slice(match.index+"invoke(".length),true)[1];
    let keys=[];
    if(argument){
      if(argument.startsWith("{"))keys=splitOuter(argument.slice(1,-1)).map(property=>property.split(":")[0].trim());
      else {
        assert.equal(argument,"preparedPurge","review new nonliteral invoke payloads");
        const declaration=source.match(/let preparedPurge:\{([^}]+)\}/)[1];
        keys=[...declaration.matchAll(/(\w+):/g)].map(match=>match[1]);
      }
    }
    const expected=handlers.get(name);
    for(const key of keys)assert.ok(expected.some(field=>field.name===key),`${name}: unexpected ${key}`);
    for(const field of expected.filter(field=>!field.optional))assert.ok(keys.includes(field.name),`${name}: missing ${field.name}`);
  }
  assert.ok(seen.size>40,"audit the complete desktop command surface");
});

test("real model/runtime failures and unknown untrusted errors have human messages",()=>{
  const {friendly}=run(functionText("friendly"));
  for(const code of ["model_sandbox_unavailable","model_component_missing","model_start_timeout","invalid_model_aliases","runtime_component_missing","ipc_unavailable","ipc_timeout","plan_checks_failed"]){
    const message=friendly(code);
    assert.equal(typeof message,"string");assert.match(message,/[А-Яа-я]/);assert.ok(!message.includes(code));
  }
  for(const code of ["future_backend_error","constructor","toString","__proto__","<script>synthetic_error</script>"]){
    assert.equal(typeof friendly(code),"string");assert.ok(!friendly(code).includes(code));
  }
});

test("saving model settings refreshes the runtime status after core unloads the model",async()=>{
  const fields={"settings-socket":"pipe","settings-model":"default","settings-embed":"nomic-embed-text","history-days":"30","net-transport":"local","traffic-mode":"poisson","traffic-interval":"600","net-daily-count":"60","net-daily-budget":"0.5"};
  const elements=new Map();const element=id=>{if(!elements.has(id))elements.set(id,{value:fields[id]??"",checked:false});return elements.get(id);};
  const order=[];
  const context=run(functionText("saveSettings"),{
    config:{llm:{model_path:"old.gguf"},shield:{},drift:{},cover:{}},
    value:id=>element(id).value,$:element,modelFileFields:[["model_path","chat-model-file"]],driftMode:{value:"assisted"},aiWebConsent:{checked:false},
    invoke:async command=>{assert.equal(command,"save_config");order.push("core-unloaded");},resetChat:()=>{},
    refreshOverview:async()=>order.push("status-refreshed"),notify:()=>order.push("notice")
  });
  await context.saveSettings();
  assert.deepEqual(order,["core-unloaded","status-refreshed","notice"]);
});

test("background traffic failures use the same human explanations as chat",()=>{
  const nodes=[];
  const createElement=()=>{const node={textContent:"",append(){},replaceChildren(){}};nodes.push(node);return node;};
  const context=run(functionText("friendly")+"\n"+functionText("renderTraffic"),{
    $:createElement,document:{createElement},config:{cover:{mode:"poisson"}}
  });
  context.renderTraffic({enabled:false,jobs:[{created_at:0,purpose:"decoy",state:"blocked",code:"network_budget_exhausted"}]});
  const text=nodes.map(node=>node.textContent).join("\n");
  assert.match(text,/Достигнут дневной лимит/);assert.ok(!text.includes("network_budget_exhausted"));
});

test("editing either input invalidates the preview, including a response that arrives after editing",async()=>{
  for(const id of ["prompt","secrets"]){
    const elements=new Map(),listeners=new Map();
    const element=id=>{if(!elements.has(id))elements.set(id,{hidden:false,textContent:"old preview",addEventListener(event,handler){listeners.set(id+":"+event,handler);}});return elements.get(id);};
    let resolvePreview;
    const reply=new Promise(resolve=>{resolvePreview=resolve;});
    const bindings=built.match(/for \(const id of \["prompt", "secrets"\]\)[^;]+;/)[0];
    const context=run(functionText("clearPreview")+"\n"+bindings+`\nvar preview=${handlerText("preview")};`,{
      previewEpoch:0,$:element,value:()=>"synthetic prompt",secrets:()=>[],invoke:async()=>reply
    });
    const pending=context.preview();
    listeners.get(id+":input")();
    resolvePreview({minimized:"stale synthetic preview",replacements:1,sensitivity:"remote_ok"});
    await pending;
    assert.equal(element("preview-box").hidden,true);
    assert.equal(element("preview-result").textContent,"Ожидает вашего текста");
  }
});

test("a deterministic preview does not promise that core has approved remote sending",async()=>{
  const elements=new Map();const element=id=>{if(!elements.has(id))elements.set(id,{});return elements.get(id);};
  const context=run(`var preview=${handlerText("preview")};`,{
    previewEpoch:0,$:element,value:()=>"synthetic prompt",secrets:()=>[],
    invoke:async()=>({minimized:"synthetic",replacements:0,sensitivity:"remote_ok",remote_enabled:false})
  });
  await context.preview();assert.match(element("preview-info").textContent,/предварительная/);
  assert.match(element("preview-info").textContent,/маршрут проверяется/);
  assert.doesNotMatch(element("preview-info").textContent,/можно отправить/);
});

test("refreshing the device secret inventory also invalidates an existing preview",async()=>{
  let invalidated=0;const element={};
  const context=run(`var probe=${handlerText("run-device-probe")};`,{
    $:()=>element,invoke:async command=>command==="load_secrets"?[{value:"synthetic-device"}]:{},
    renderDeviceProbe(){},renderHygiene(){},deviceInventoryReady:()=>false,updateChatButtons(){},notify(){},clearPreview(){invalidated++;}
  });
  await context.probe();assert.equal(invalidated,1);assert.equal(element.value,"synthetic-device");
});

test("rejecting all researched traits stays on the traits step",async()=>{
  for(const accepted of [false,true]){
    const steps=[],notices=[];
    const persona={traits:[{id:"synthetic",confirmed:accepted}]};
    const context=run(`var confirmPersona=${handlerText("confirm-persona")};`,{
      persona,document:{querySelectorAll:()=>[{dataset:{trait:"synthetic"},checked:accepted}]},
      invoke:async(command,args)=>{assert.equal(command,"confirm_traits");assert.equal(args.choices[0][1],accepted);return persona;},
      renderPersona:()=>{},refreshOverview:async()=>{},driftStep:step=>steps.push(step),notify:message=>notices.push(message)
    });
    await context.confirmPersona();assert.deepEqual(steps,[accepted?3:2]);
    if(!accepted)assert.match(notices[0],/хотя бы одну/);
  }
});

test("lock clears sensitive fields and restores the valid account counter for the next unlock",()=>{
  const elements=new Map();
  const element=id=>{if(!elements.has(id))elements.set(id,{value:"synthetic-sensitive",replaceChildren(){}});return elements.get(id);};
  const counter=element("account-count"),prompt=element("prompt");
  const context=run(functionText("clearSensitiveUi"),{
    $:element,document:{querySelectorAll:()=>[counter,prompt]},
    renderDeviceProbe(){},renderHygiene(){},sessionTimingLabel(){return "";},historySelect:{replaceChildren(){}},
    resetChat(){},setDailyOpen(){},renderDay(){}
  });
  context.clearSensitiveUi();
  assert.equal(prompt.value,"");assert.equal(counter.value,"1");
});
