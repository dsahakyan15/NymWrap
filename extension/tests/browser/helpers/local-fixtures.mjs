// Original, unbranded synthetic pages. No service assets or real accounts.
export function localFixtures(){
  const state={block:'',after:'',inputs:[],sent:[],media:[],requests:[],hostileLink:false};
  const signals=kind=>kind==='captcha'?'<div id="captcha">Verify you are human</div>':kind==='login'?'<form action="login"><input autocomplete="username"></form>':'';
  const handler=(req,res)=>{
    if(!/^127\.0\.0\.1(?::\d+)?$/.test(req.headers.host??''))return false;
    const url=new URL(req.url,'https://'+req.headers.host);state.requests.push(url.pathname);
    if(url.pathname.endsWith('/event')&&req.method==='POST'){
      let body='';req.on('data',b=>{body+=b;if(body.length>8192)req.destroy();});req.on('end',()=>{const data=JSON.parse(body);state[data.kind==='input'?'inputs':data.kind==='sent'?'sent':'media'].push(data);res.writeHead(204);res.end();});return true;
    }
    const service=url.pathname.split('/')[2],base=`/drift-fixtures/${service}/`;
    let body=signals(state.block);
    if(!body){
      if(url.pathname.endsWith('/results'))body=`<ytd-app><ytd-search><div id="contents"><ytd-item-section-renderer><ytd-video-renderer><a id="video-title" href="${state.hostileLink?'https://example.invalid/watch?v=bad':base+'watch?v=synthetic-video'}">Synthetic growing lesson</a></ytd-video-renderer></ytd-item-section-renderer></div></ytd-search></ytd-app>`;
      else if(url.pathname.endsWith('/watch'))body='<ytd-app><ytd-page-manager><ytd-watch-flexy><div id="player"><video class="html5-main-video" muted width="128" height="72"></video></div></ytd-watch-flexy></ytd-page-manager></ytd-app>';
      else if(service==='youtube')body='<input name="search_query">';
      else if(service==='chatgpt')body='<main><form><div class="composer"><div id="prompt-textarea" class="ProseMirror" contenteditable="true" role="textbox"></div><button type="button" data-testid="send-button">Send</button></div></form></main>';
      else if(service==='claude')body='<main><fieldset><div class="ProseMirror" contenteditable="true" role="textbox"></div><div class="composer-actions"><button type="button" aria-label="Send message">Send</button></div></fieldset></main>';
      else body='<main><form><rich-textarea><div class="ql-editor" contenteditable="true" role="textbox"></div></rich-textarea><button type="button" aria-label="Send">Send</button></form></main>';
    }
    body+='<p>SYNTHETIC_LOCAL_BODY_CANARY_49731</p>';
    const after=JSON.stringify(signals(state.after));
    body+=`<script>
      // Generated moving pixels only: no camera, microphone, display capture or downloaded media.
      const video=document.querySelector('video');
      if(video){
        const canvas=document.createElement('canvas');canvas.width=128;canvas.height=72;
        const context=canvas.getContext('2d');let frame=0;
        const draw=()=>{context.fillStyle='#173e29';context.fillRect(0,0,128,72);context.fillStyle='#b5d68a';context.fillRect((frame++*8)%112,24,16,24);};
        draw();const stream=canvas.captureStream(2);video.srcObject=stream;const timer=setInterval(draw,500);
        const stop=()=>{clearInterval(timer);stream.getTracks().forEach(track=>track.stop());};
        video.addEventListener('pause',stop,{once:true});addEventListener('pagehide',stop,{once:true});
      }
      const field=document.querySelector('input:not([autocomplete]),[contenteditable]');
      const send=(kind,text)=>fetch('${base}event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind,service:'${service}',text,trusted:false})});
      field?.addEventListener('input',()=>send('input',field.value??field.textContent));
      document.querySelector('button')?.addEventListener('click',()=>{
        const value=field.value??field.textContent;send('sent',value);field.textContent='';
        const message=document.createElement('${service==='gemini'?'user-query':'div'}');
        ${service==='chatgpt'?`message.setAttribute('data-message-author-role','user');`:service==='claude'?`message.setAttribute('data-testid','user-message');`:''}
        const text=document.createElement('span');text.className='query-text';text.textContent=value;message.append(text);document.body.append(message);
        if(${after})setTimeout(()=>document.body.insertAdjacentHTML('afterbegin',${after}),100);
      });
      document.querySelector('video')?.addEventListener('playing',()=>{send('playing','');if(${after})setTimeout(()=>document.body.insertAdjacentHTML('afterbegin',${after}),100);},{once:true});
      document.querySelector('video')?.addEventListener('pause',()=>send('paused',''));
    </script>`;
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end('<!doctype html><meta charset="utf-8"><title>Synthetic local fixture</title>'+body);return true;
  };
  return {state,handler};
}

export async function localScenarios({scenario,control,execute,until,origin,fixture,status}){
  const send=execute;execute=async(...args)=>{await until(status,s=>s.running===false,15000);return send(...args);};
  const action={plan_hash:'a'.repeat(64),stage:1,day:1,action_index:0,service:'chatgpt',text:'<script>synthetic garden</script>'};
  const target=service=>`${origin}/drift-fixtures/${service}/`;
  await scenario('local video and three AI DOM layouts require opt-in and complete only after actual watch/send',async()=>{
    for(const service of ['youtube','chatgpt','claude','gemini']){
      await control('task',{task:{...action,service},mode:'extension',ai:true});
      assertStarted(await execute({...action,service},target(service)));
      const core=await until(()=>control('state'),s=>s.completed||s.paused,45000);
      if(!core.completed)throw Error('local_execution_failed '+JSON.stringify(core.events));
      await until(status,s=>s.running===false,15000);
      if(service==='youtube')await until(async()=>fixture.media.at(-1)?.kind,s=>s==='paused',5000);
      if(JSON.stringify(core.commands).includes('SYNTHETIC_LOCAL_BODY_CANARY_49731'))throw Error('local_page_content_leaked');
      if(core.commands.filter(c=>c.kind==='finish_search').length!==1)throw Error('duplicate_completion');
      if(service!=='youtube'&&fixture.sent.filter(s=>s.service===service&&s.text===action.text).length!==1)throw Error('missing_or_duplicate_send');
    }
  });
  await scenario('assisted and default-disabled AI never claim a task or send text',async()=>{
    for(const [mode,ai] of [['assisted',true],['extension',false]]){
      await control('task',{task:action,mode,ai});assertStarted(await execute(action,target('chatgpt')));
      await until(async()=>{const c=await control('state');return c.commands.some(v=>v.kind==='status')?c:undefined;},Boolean);
      const core=await control('state');if(core.claimed||core.completed)throw Error('implicit_ai_automation');
    }
  });
  await scenario('local CAPTCHA and passwordless login pages stop every adapter before typing',async()=>{
    for(const service of ['youtube','chatgpt','claude','gemini'])for(const reason of ['captcha','login']){
      fixture.block=reason;fixture.after='';const before=fixture.inputs.length;
      await control('task',{task:{...action,service},mode:'extension',ai:true});assertStarted(await execute({...action,service},target(service)));
      const core=await until(()=>control('state'),s=>s.paused,10000);
      if(fixture.inputs.length!==before||core.completed||!core.commands.some(c=>c.kind==='safety_stop'&&c.reason===reason))throw Error('challenge_not_stopped');
    }
    fixture.block='';
  });
  await scenario('late CAPTCHA/login stop video playback and AI reading without replay or success',async()=>{
    for(const service of ['youtube','chatgpt','claude','gemini'])for(const reason of ['captcha','login']){
      fixture.after=reason;
      await control('task',{task:{...action,service},mode:'extension',ai:true});assertStarted(await execute({...action,service},target(service)));
      const core=await until(()=>control('state'),s=>s.paused,10000);
      if(core.completed||!core.commands.some(c=>c.kind==='safety_stop'&&c.reason===reason))throw Error('late_challenge_not_stopped');
      await until(status,s=>s.running===false,15000);
      if(service==='youtube')await until(async()=>fixture.media.at(-1)?.kind,s=>s==='paused',5000);
      const stop=core.commands.find(c=>c.kind==='safety_stop');if(Object.keys(stop).sort().join(',')!=='event_id,kind,reason')throw Error('page_data_in_stop');
    }
    fixture.after='';
  });
  await scenario('a video link outside loopback is rejected before navigation',async()=>{
    fixture.hostileLink=true;const task={...action,service:'youtube'};
    await control('task',{task,mode:'extension',ai:true});assertStarted(await execute(task,target('youtube')));
    const core=await until(()=>control('state'),s=>s.paused,10000);if(core.completed)throw Error('hostile_video_followed');fixture.hostileLink=false;
  });
}
function assertStarted(result){if(result?.started!==true)throw Error('local_start_rejected');}
