import {syntheticNativeHost} from './helpers/synthetic-native.mjs';
import {fixtureCertificate} from './helpers/certificate.mjs';
import {extensionDigest} from './helpers/artifact.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,readFile,readdir,writeFile,copyFile,realpath,lstat,rm} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createServer} from 'node:https';
import {resolve,join,sep,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../..');
const browserRoot=resolve(root,'target/browser-tests');
process.env.PLAYWRIGHT_BROWSERS_PATH=resolve(root,'target/tools/playwright');
const {chromium}=await import('playwright');
const action={plan_hash:'a'.repeat(64),stage:1,day:1,action_index:0,service:'google',text:'synthetic garden'};
const BODY_CANARY='SYNTHETIC_PAGE_BODY_ONLY_51379';
const XSS='<script>window.syntheticXssExecuted=true</script>';
const escape=value=>value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
async function until(read,accept,timeout=10000){
  const end=Date.now()+timeout;
  while(Date.now()<end){const value=await read();if(accept(value))return value;await new Promise(r=>setTimeout(r,100));}
  throw Error('browser_condition_timeout');
}
// Runs only in the isolated test worker. Production code and manifest remain unchanged.

test('actual Chromium MV3 runs cover search, periodic Mirror and CAPTCHA stop on synthetic pages',{timeout:120000},async t=>{
  await mkdir(browserRoot,{recursive:true});
  const fixture=await mkdtemp(join(browserRoot,'mv3-'));
  const extension=join(fixture,'extension'),profile=join(fixture,'profile');
  let context,server;
  let passed=0;const scenario=(name,run)=>t.test(name,async()=>{await run();passed++;});
  const reportPath=join(browserRoot,'reports/chromium.json');await mkdir(dirname(reportPath),{recursive:true});await writeFile(reportPath,JSON.stringify({status:'running',browser:'Chromium',scope:'isolated synthetic integration'}));
  try{
    await mkdir(extension);
    const source=resolve(root,'extension/dist');
    const artifact=await extensionDigest(source);
    for(const entry of await readdir(source,{withFileTypes:true})){
      if(!entry.isFile()||entry.isSymbolicLink())throw Error('unsafe_extension_fixture');
      await copyFile(join(source,entry.name),join(extension,entry.name));
    }
    const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8'));
    const originalCsp=structuredClone(manifest.content_security_policy);
    // Test origin permissions are pre-granted; permission/refusal branches have separate unit tests.
    manifest.host_permissions=manifest.optional_host_permissions.slice();
    await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));
    assert.deepEqual(manifest.content_security_policy,originalCsp);
    for(const entry of await readdir(source))if(entry.endsWith('.js')){
      assert.equal(createHash('sha256').update(await readFile(join(source,entry))).digest('hex'),createHash('sha256').update(await readFile(join(extension,entry))).digest('hex'));
    }
    const requests=[],inputs=[],scriptErrors=[];let challenge=false;
    server=createServer(await fixtureCertificate(),(request,response)=>{
      const host=request.headers.host;
      if(!['www.google.com','www.youtube.com','youtube.com'].includes(host)){response.writeHead(403);response.end();return;}
      const url=new URL(request.url,`https://${host}`);requests.push(url.href);
      let body;
      if(url.hostname==='www.google.com'){
        body=challenge?'<h1>CAPTCHA</h1><div id="captcha">Verify you are human</div>':
          `<h1>Synthetic Search</h1><input name="q"><p>${BODY_CANARY}</p><script>document.querySelector('input').addEventListener('input',e=>console.log('SYNTHETIC_INPUT:'+JSON.stringify({value:e.target.value,trusted:e.isTrusted,at:performance.now()})))</script>`;
      }else body=`<input name="search_query"><p>${BODY_CANARY}</p><ytd-rich-item-renderer><a id="video-title">Synthetic garden feed</a></ytd-rich-item-renderer><ytd-rich-item-renderer><a id="video-title">${escape(XSS)}</a></ytd-rich-item-renderer><script>document.querySelector('input').addEventListener('input',e=>console.log('SYNTHETIC_INPUT:'+JSON.stringify({value:e.target.value,trusted:e.isTrusted,at:performance.now()})))</script>`;
      response.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});
      response.end(`<!doctype html><html><head><meta charset="utf-8"><title>Synthetic fixture</title></head><body>${body}</body></html>`);
    });
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    const port=server.address().port;
    context=await chromium.launchPersistentContext(profile,{
      channel:'chromium',headless:true,ignoreHTTPSErrors:true,
      // Only this throwaway profile trusts the in-memory certificate. All other DNS is denied.
      args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,'--disable-background-networking','--disable-component-update','--no-first-run','--no-proxy-server','--ignore-certificate-errors',`--host-resolver-rules=MAP www.google.com 127.0.0.1:${port}, MAP www.youtube.com 127.0.0.1:${port}, MAP youtube.com 127.0.0.1:${port}, MAP * ~NOTFOUND`],
    });
    context.on('page',page=>{
      page.on('pageerror',error=>scriptErrors.push(error.message));
      page.on('console',message=>{
        if(message.type()==='error')scriptErrors.push(message.text());
        if(message.text().startsWith('SYNTHETIC_INPUT:'))inputs.push(JSON.parse(message.text().slice('SYNTHETIC_INPUT:'.length)));
      });
    });
    let [worker]=context.serviceWorkers();worker??=await context.waitForEvent('serviceworker');
    const extensionId=new URL(worker.url()).host;
    await worker.evaluate(syntheticNativeHost,action);
    const popup=await context.newPage();await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    await popup.evaluate(()=>{
      chrome.runtime.connectNative=()=>{
        let live=true;const receivers=[],disconnects=[];
        return {onMessage:{addListener:fn=>receivers.push(fn)},onDisconnect:{addListener:fn=>disconnects.push(fn)},disconnect(){if(live){live=false;for(const fn of disconnects)fn();}},
          postMessage(packet){void chrome.runtime.sendMessage({kind:'synthetic_native_bridge',command:packet.command}).then(result=>{if(live)for(const fn of receivers)fn({version:1,id:packet.id,result});});}};
      };
    });
    const readCore=()=>worker.evaluate(()=>structuredClone(globalThis.syntheticCore));

    await scenario('real scripting types only the approved query and completes after reading',async()=>{
      await popup.locator('#connect').click();
      await until(()=>popup.locator('#tasks').isEnabled(),Boolean);
      await popup.locator('#tasks').click();
      const start=popup.getByRole('button',{name:'Набрать запрос и открыть результаты'});
      await start.waitFor();await start.click();
      const state=await until(readCore,c=>c.completed||c.paused,45000);
      assert.equal(state.completed,true,JSON.stringify({events:state.events,errors:scriptErrors,commands:state.commands.map(c=>c.kind)}));
      assert.equal(state.commands.filter(c=>c.kind==='begin_search').length,1);
      assert.equal(state.commands.filter(c=>c.kind==='finish_search').length,1);
      assert.equal(inputs.map(e=>e.value.at(-1)).join(''),action.text);
      assert.ok(inputs.every(e=>e.trusted===false));
      for(let i=1;i<inputs.length;i++)assert.ok(inputs[i].at-inputs[i-1].at>=50,'typing_burst');
      const sent=requests.filter(url=>new URL(url).pathname==='/search');assert.equal(sent.length,1);
      assert.equal(new URL(sent[0]).searchParams.get('q'),action.text);
      assert.ok(!JSON.stringify(state.commands).includes(BODY_CANARY));
    });

    await scenario('YouTube uses its fixed search field and results URL without following a video',async()=>{
      await worker.evaluate(task=>{const core=globalThis.syntheticCore;core.tasks=[task];core.completed=false;core.claimed=false;core.paused=false;core.commands=[];},{...action,service:'youtube',action_index:3});
      const typed=inputs.length;
      await popup.locator('#tasks').click();
      await popup.getByRole('button',{name:'Набрать запрос и открыть результаты'}).click();
      const state=await until(readCore,c=>c.completed||c.paused,45000);
      assert.equal(state.completed,true,JSON.stringify(state.events));
      assert.equal(inputs.slice(typed).map(e=>e.value.at(-1)).join(''),action.text);
      const sent=requests.filter(url=>new URL(url).pathname==='/results');assert.equal(sent.length,1);
      assert.equal(new URL(sent[0]).searchParams.get('search_query'),action.text);
      assert.ok(!requests.some(url=>new URL(url).pathname==='/watch'));
      assert.ok(!JSON.stringify(state.commands).includes(BODY_CANARY));
    });

    await scenario('real alarm captures safe title text and keeps content out of extension storage',async()=>{
      await worker.evaluate(()=>{globalThis.syntheticCore.paused=false;});
      const feed=await context.newPage();await feed.goto('https://www.youtube.com/');
      await popup.locator('#periodic-mirror').click();
      await until(()=>worker.evaluate(async()=>(await chrome.storage.local.get('mirror-schedule-v1'))['mirror-schedule-v1']?.enabled),Boolean);
      await feed.bringToFront();
      await worker.evaluate(()=>chrome.alarms.create('nymwrap-mirror-hourly-v1',{when:Date.now()+100}));
      const state=await until(readCore,c=>c.snapshots.length>0,15000);
      assert.deepEqual(state.snapshots[0].items,['Synthetic garden feed',XSS]);
      assert.equal(state.snapshots[0].kind,'youtube_feed');
      assert.equal(await feed.evaluate(()=>globalThis.syntheticXssExecuted),undefined);
      const stored=await worker.evaluate(()=>chrome.storage.local.get(null));
      assert.ok(!JSON.stringify(stored).includes(XSS));assert.ok(!JSON.stringify(stored).includes(BODY_CANARY));
      await popup.locator('#periodic-mirror').click();
      await until(()=>worker.evaluate(async()=>(await chrome.storage.local.get('mirror-schedule-v1'))['mirror-schedule-v1']?.enabled),enabled=>enabled===false);
    });

    await scenario('a real challenge page stops before typing or a results request',async()=>{
      challenge=true;
      await worker.evaluate(task=>{const core=globalThis.syntheticCore;core.tasks=[task];core.completed=false;core.claimed=false;core.paused=false;core.commands=[];}, {...action,action_index:1});
      const before=requests.filter(url=>new URL(url).pathname==='/search').length,typed=inputs.length;
      await popup.locator('#tasks').click();
      await popup.getByRole('button',{name:'Набрать запрос и открыть результаты'}).click();
      const state=await until(readCore,c=>c.paused,10000);
      assert.equal(inputs.length,typed);assert.equal(requests.filter(url=>new URL(url).pathname==='/search').length,before);
      const stop=state.commands.find(c=>c.kind==='safety_stop');assert.ok(stop);assert.equal(stop.reason,'captcha');
      assert.deepEqual(Object.keys(stop).sort(),['event_id','kind','reason']);assert.match(stop.event_id,/^[a-f0-9]{32}$/);
      assert.ok(!state.commands.some(c=>c.kind==='finish_search'));
    });

    await scenario('a lost scripting reply after an actual input stops without repeating the character',async()=>{
      challenge=false;
      await worker.evaluate(task=>{const core=globalThis.syntheticCore;core.tasks=[task];core.completed=false;core.claimed=false;core.paused=false;core.commands=[];core.dropNextInput=true;},{...action,action_index:2});
      const before=requests.filter(url=>new URL(url).pathname==='/search').length,typed=inputs.length;
      await popup.locator('#tasks').click();
      await popup.getByRole('button',{name:'Набрать запрос и открыть результаты'}).click();
      const state=await until(readCore,c=>c.paused,10000);
      assert.deepEqual(inputs.slice(typed).map(e=>e.value),[action.text[0]]);
      assert.equal(requests.filter(url=>new URL(url).pathname==='/search').length,before);
      assert.equal(state.commands.filter(c=>c.kind==='begin_search').length,1);
      assert.ok(!state.commands.some(c=>c.kind==='finish_search'||c.kind==='safety_stop'));
      assert.equal(state.dropNextInput,false);
    });
    if(passed!==5)throw Error('incomplete_chromium_scenarios');
    await writeFile(reportPath,JSON.stringify({status:'passed',browser:'Chromium '+context.browser().version(),checked_at:new Date().toISOString(),extension_sha256:artifact,scope:'actual MV3; synthetic loopback HTTPS; fake native core; no user profile',scenarios:['google','youtube','alarm','captcha','lost_reply','xss_storage']},null,2)+'\n');
  }finally{
    await context?.close();
    server?.closeAllConnections();
    if(server?.listening)await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
    const actual=await realpath(fixture),base=await realpath(browserRoot),metadata=await lstat(fixture);
    const norm=value=>process.platform==='win32'?value.toLowerCase():value;
    if(metadata.isSymbolicLink()||!norm(actual).startsWith(norm(base+sep)))throw Error('unsafe_browser_fixture_cleanup');
    await rm(fixture,{recursive:true,force:true});
  }
});
