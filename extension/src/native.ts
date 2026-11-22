import {HOST,reply,type Command,type Result} from "./protocol.js";
interface Port {postMessage(message:unknown):void;disconnect():void;onMessage:{addListener(callback:(message:unknown)=>void):void};onDisconnect:{addListener(callback:()=>void):void}}
declare const chrome:{runtime:{connectNative(host:string):Port;lastError?:{message?:string}}};
export class NativeBridge{
  private port:Port|undefined;
  private seq=0;
  private pending=new Map<number,{resolve:(r:Result)=>void;reject:(e:Error)=>void;timer:ReturnType<typeof setTimeout>}>();
  connect(){
    if(this.port)return;
    const port=chrome.runtime.connectNative(HOST);this.port=port;
    port.onDisconnect.addListener(()=>{void chrome.runtime.lastError;this.close();});
    port.onMessage.addListener(message=>{
      try{const response=reply(message);const pending=this.pending.get(response.id);if(!pending)throw Error("unexpected_bridge_reply");clearTimeout(pending.timer);this.pending.delete(response.id);if(response.result.kind==="error")pending.reject(Error(response.result.code));else pending.resolve(response.result);}
      catch{this.close();}
    });
  }
  async request(command:Command):Promise<Result>{
    if(!this.port)throw Error("bridge_disconnected");if(this.pending.size>=4)throw Error("bridge_busy");
    this.seq=this.seq>=4294967295?1:this.seq+1;const id=this.seq;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending.delete(id);reject(Error("bridge_timeout"));},130000);
      this.pending.set(id,{resolve,reject,timer});
      try{this.port!.postMessage({version:1,id,command});}catch{this.close();}
    });
  }
  close(){
    const port=this.port;this.port=undefined;
    for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(Error("bridge_disconnected"));}this.pending.clear();
    if(port)try{port.disconnect();}catch{/* already disconnected */}
  }
}
