// Small sequential client for Mozilla's documented Marionette protocol. Test profiles only.
import net from 'node:net';
export class Marionette {
  constructor(socket,greetingTimeout=10000){
    this.socket=socket;this.buffer=Buffer.alloc(0);this.id=0;this.pending=null;
    this.hello=new Promise((accept,reject)=>{this.greeting={accept,reject};});
    this.greetingTimer=setTimeout(()=>{this.fail(Error('marionette_greeting_timeout'));socket.destroy();},greetingTimeout);
    socket.on('data',chunk=>{
      try{
        this.buffer=Buffer.concat([this.buffer,chunk]);if(this.buffer.length>4*1024*1024)throw Error('marionette_oversize');
        for(;;){const colon=this.buffer.indexOf(58);if(colon<0)break;const lengthText=this.buffer.toString('ascii',0,colon);if(!/^[0-9]{1,8}$/.test(lengthText))throw Error('marionette_invalid_frame');const length=Number(lengthText);if(length<1||length>4*1024*1024)throw Error('marionette_oversize');if(this.buffer.length<colon+1+length)break;const value=JSON.parse(this.buffer.toString('utf8',colon+1,colon+1+length));this.buffer=this.buffer.subarray(colon+1+length);
          if(this.greeting){if(value.applicationType!=='gecko'||value.marionetteProtocol!==3)throw Error('marionette_invalid_greeting');clearTimeout(this.greetingTimer);this.greeting.accept(value);this.greeting=null;continue;}
          const pending=this.pending;if(!pending||!Array.isArray(value)||value[0]!==1||value[1]!==pending.id)throw Error('marionette_wrong_reply');this.pending=null;clearTimeout(pending.timer);if(value[2])pending.reject(Error('marionette_'+pending.command+'_'+value[2].error));else pending.accept(value[3]);
        }
      }catch(e){this.fail(e);socket.destroy();}
    });
    socket.on('error',e=>this.fail(e));socket.on('close',()=>this.fail(Error('marionette_closed')));
  }
  fail(error){clearTimeout(this.greetingTimer);this.greeting?.reject(error);this.greeting=null;if(this.pending){clearTimeout(this.pending.timer);this.pending.reject(error);this.pending=null;}}
  static async connect(port,timeout=30000){
    const deadline=Date.now()+timeout;let socket;
    while(!socket){try{socket=await new Promise((accept,reject)=>{const candidate=net.createConnection({host:'127.0.0.1',port});candidate.once('connect',()=>accept(candidate));candidate.once('error',reject);});}catch{if(Date.now()>deadline)throw Error('marionette_connect_timeout');await new Promise(r=>setTimeout(r,100));}}
    const client=new Marionette(socket);await client.hello;return client;
  }
  call(command,parameters={},timeout=30000){
    if(this.pending)throw Error('marionette_request_in_progress');const id=++this.id;
    return new Promise((accept,reject)=>{const timer=setTimeout(()=>{this.pending=null;reject(Error('marionette_command_timeout'));this.socket.destroy();},timeout);this.pending={id,command,accept,reject,timer};const payload=Buffer.from(JSON.stringify([0,id,command,parameters]));this.socket.write(Buffer.concat([Buffer.from(payload.length+':'),payload]));});
  }
  async script(script,args=[]){const value=await this.call('WebDriver:ExecuteScript',{script,args,newSandbox:false,sandbox:null});return value&&Object.hasOwn(value,'value')?value.value:value;}
  async asyncScript(script,args=[]){const value=await this.call('WebDriver:ExecuteAsyncScript',{script,args,newSandbox:false,sandbox:null});return value&&Object.hasOwn(value,'value')?value.value:value;}
  close(){this.socket.destroy();}
}
