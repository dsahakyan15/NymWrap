import { task as validateTask, type Task, type Command, type Result } from "./protocol.js";
import { coverUrl } from "./safety.js";
import type { SearchPageState, SearchStep } from "./search_page.js";
interface Bridge { request(command:Command):Promise<Result>;close():void }
export interface ExecutionHooks {
  bridge():Bridge;
  permitted(service:"google"|"youtube"):Promise<boolean>;
  create(url:string):Promise<number>;
  navigate(id:number,url:string):Promise<void>;
  step(id:number,step:SearchStep):Promise<SearchPageState>;
  wait(ms:number,signal:AbortSignal):Promise<void>;
  now():number;
  random():number;
  eventId():string;
}
export const searchOrigins=(service:string)=>{
  if(service==="google")return ["https://www.google.com/*"];
  if(service==="youtube")return ["https://www.youtube.com/*"];
  throw Error("ai_web_automation_disabled");
};
export class SearchExecutor {
  private controller:AbortController|undefined;
  constructor(private hooks:ExecutionHooks){}
  get running(){return !!this.controller;}
  cancel(){this.controller?.abort();}
  async run(value:unknown):Promise<void>{
    const task:Task=validateTask(value);
    if(this.running)throw Error("request_in_progress");
    if((task.service!=="google"&&task.service!=="youtube")||Array.from(task.text).length>512)throw Error("manual_action_required");
    const service=task.service;
    const controller=new AbortController();this.controller=controller;
    let bridge:Bridge|undefined,granted=false;
    let token:string|undefined;
    const started=this.hooks.now();
    const active=()=>{if(controller.signal.aborted||this.hooks.now()-started>300000)throw Error("execution_interrupted");};
    const ready=async()=>{
      active();if(!await this.hooks.permitted(service))throw Error("permission_required");active();
      const status=await bridge!.request({kind:"status"});active();
      if(status.kind!=="status")throw Error("invalid_bridge_reply");
      if(status.paused)throw Error("paused");
      if(status.mode!=="extension")throw Error("manual_action_required");
      if(token){const permit=await bridge!.request({kind:"validate_search",task,token});active();if(permit.kind!=="ack")throw Error("invalid_bridge_reply");}
    };
    const delay=async(ms:number)=>{await this.hooks.wait(ms,controller.signal);active();};
    const random=(min:number,max:number)=>{const n=this.hooks.random();if(!Number.isFinite(n)||n<0||n>=1)throw Error("invalid_random");return min+Math.floor(n*(max-min+1));};
    try{
      bridge=this.hooks.bridge();await ready();
      const grant=await bridge.request({kind:"begin_search",task});
      if(grant.kind!=="execution")throw Error("invalid_bridge_reply");
      token=grant.token;granted=true;active();
      await ready();
      const id=await this.hooks.create(service==="google"?"https://www.google.com/":"https://www.youtube.com/");
      const inspect=async(step:SearchStep,loading=false)=>{
        for(let i=0;i<50;++i){
          await ready();const state=await this.hooks.step(id,step);active();
          if(state==="challenge"||state==="login"){
            await bridge!.request({kind:"safety_stop",event_id:this.hooks.eventId(),reason:state==="challenge"?"captcha":"login"});
            throw Error(state==="challenge"?"captcha":"login");
          }
          if(state==="ready")return;
          if(state!=="loading"||!loading)throw Error("execution_interrupted");
          await delay(200);
        }
        throw Error("execution_interrupted");
      };
      await inspect({service,expected:"",results:false},true);
      let prefix="";
      for(const letter of task.text){
        await delay(random(60,180));await inspect({service,expected:prefix,letter,results:false});prefix+=letter;
      }
      await inspect({service,expected:prefix,results:false});await ready();
      // Deterministic allowlisted navigation; no form, page link or model-selected URL is followed.
      await this.hooks.navigate(id,coverUrl(service,task.text));
      await inspect({service,expected:prefix,results:true},true);
      let remaining=random(20000,90000);
      while(remaining>0){const ms=Math.min(1000,remaining);await delay(ms);await inspect({service,expected:prefix,results:true});remaining-=ms;}
      await ready();
      const result=await bridge.request({kind:"finish_search",task,token:grant.token});
      if(result.kind!=="ack")throw Error("invalid_bridge_reply");
    }catch(error){
      // Any uncertain side effect pauses automation. The durable permit never authorizes replay.
      if(granted&&bridge)try{await bridge.request({kind:"pause",paused:true});}catch{/* disconnected: stop locally */}
      throw error;
    }finally{bridge?.close();this.controller=undefined;}
  }
}
