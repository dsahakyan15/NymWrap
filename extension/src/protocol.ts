// This protocol has no operation for reading Shield, vault, imports or persona.
export const HOST="org.nymwrap.drift";
export interface Task {plan_hash:string;stage:number;day:number;action_index:number;service:"google"|"youtube"|"chatgpt"|"claude"|"gemini";text:string}
export type Command={kind:"status"}|{kind:"tasks"}|{kind:"complete";task:Task}|{kind:"begin_search";task:Task}|{kind:"validate_search";task:Task;token:string}|{kind:"finish_search";task:Task;token:string}|{kind:"pause";paused:boolean}|{kind:"safety_stop";event_id:string;reason:"captcha"|"login"}|{kind:"snapshot";snapshot:{kind:"youtube_feed"|"ad_topics"|"search_suggestions"|"ai_memory";items:string[];captured_at:number}};
export type Result={kind:"ack"}|{kind:"execution";token:string}|{kind:"error";code:string}|{kind:"status";paused:boolean;mode:"assisted"|"extension";ai_web_automation:boolean}|{kind:"tasks";tasks:Task[]};
export interface Reply {version:1;id:number;result:Result}
const bytes=(s:string)=>new TextEncoder().encode(s).length;
function object(v:unknown):Record<string,unknown>{if(typeof v!=="object"||v===null||Array.isArray(v))throw Error("invalid_bridge_reply");return v as Record<string,unknown>;}
function keys(v:Record<string,unknown>,expected:string[]){if(Object.keys(v).length!==expected.length||!expected.every(k=>Object.hasOwn(v,k)))throw Error("invalid_bridge_reply");}
function integer(v:unknown,min:number,max:number):v is number{return typeof v==="number"&&Number.isSafeInteger(v)&&v>=min&&v<=max;}
export function task(value:unknown):Task{
  const v=object(value);keys(v,["plan_hash","stage","day","action_index","service","text"]);
  if(typeof v.plan_hash!=="string"||!/^[0-9a-f]{64}$/.test(v.plan_hash)||!integer(v.stage,1,30)||!integer(v.day,1,30)||!integer(v.action_index,0,9)||!["google","youtube","chatgpt","claude","gemini"].includes(String(v.service))||typeof v.text!=="string"||!v.text.trim()||bytes(v.text)>4096||/[\u0000-\u001f\u007f]/.test(v.text))throw Error("invalid_cover_task");
  return {plan_hash:v.plan_hash,stage:v.stage,day:v.day,action_index:v.action_index,service:v.service as Task["service"],text:v.text};
}
export function reply(value:unknown):Reply{
  const v=object(value);keys(v,["version","id","result"]);if(v.version!==1||!integer(v.id,1,4294967295))throw Error("invalid_bridge_reply");
  const r=object(v.result);let result:Result;
  switch(r.kind){
    case "ack":keys(r,["kind"]);result={kind:"ack"};break;
    case "execution":keys(r,["kind","token"]);if(typeof r.token!=="string"||!/^[0-9a-f]{64}$/.test(r.token))throw Error("invalid_bridge_reply");result={kind:"execution",token:r.token};break;
    case "error":keys(r,["kind","code"]);if(typeof r.code!=="string"||!/^[a-z_]{1,64}$/.test(r.code))throw Error("invalid_bridge_reply");result={kind:"error",code:r.code};break;
    case "status":keys(r,["kind","paused","mode","ai_web_automation"]);if(typeof r.paused!=="boolean"||typeof r.ai_web_automation!=="boolean"||!['assisted','extension'].includes(String(r.mode)))throw Error("invalid_bridge_reply");result={kind:"status",paused:r.paused,mode:r.mode as "assisted"|"extension",ai_web_automation:r.ai_web_automation};break;
    case "tasks":keys(r,["kind","tasks"]);if(!Array.isArray(r.tasks)||r.tasks.length>10)throw Error("invalid_bridge_reply");result={kind:"tasks",tasks:r.tasks.map(task)};if(new Set(result.tasks.map(t=>t.action_index)).size!==result.tasks.length)throw Error("invalid_bridge_reply");break;
    default:throw Error("invalid_bridge_reply");
  }
  return {version:1,id:v.id,result};
}
