import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer as httpServer} from 'node:http';
import {createServer as httpsServer} from 'node:https';
import {mkdir,mkdtemp,readFile,writeFile,readdir,copyFile,lstat,realpath,rm} from 'node:fs/promises';
import {resolve,join,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import net from 'node:net';
import {createHash} from 'node:crypto';
import {Marionette} from './helpers/marionette.mjs';
import {syntheticNativeHost} from './helpers/synthetic-native.mjs';
import {fixtureCertificate} from './helpers/certificate.mjs';
import {extensionDigest} from './helpers/artifact.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../..');
const binary=resolve(root,'target/tools/privacy-browser/firefox-160.0.1/core/firefox.exe');
const action={plan_hash:'a'.repeat(64),stage:1,day:1,action_index:0,service:'google',text:'synthetic garden'};
const BODY='SYNTHETIC_FIREFOX_BODY_ONLY_83617',XSS='<script>window.syntheticXssExecuted=true</script>';
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function until(read,predicate,timeout=30000){const end=Date.now()+timeout;while(Date.now()<end){const value=await read();if(predicate(value))return value;await wait(100);}throw Error('firefox_condition_timeout');}
const escape=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
async function freePort(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const port=s.address().port;await new Promise(r=>s.close(r));return port;}

test('stock Firefox MV3 executes fixed searches and stops at challenges on loopback HTTPS',{timeout:180000,skip:process.platform!=='win32'?'stock Firefox integration is currently verified on Windows':false},async t=>{
  await mkdir(resolve(root,'target/browser-tests'),{recursive:true});
  const base=resolve(root,'target/browser-tests'),fixture=await mkdtemp(join(base,'firefox-'));
  const extension=join(fixture,'extension'),profile=join(fixture,'profile');let child,client,proxy,tls;
  const requests=[],inputs=[];let challenge='';
  let passed=0;const scenario=(name,run)=>t.test(name,async()=>{await run();passed++;});
  const reportPath=resolve(root,'target/browser-tests/reports/firefox.json');await mkdir(dirname(reportPath),{recursive:true});await writeFile(reportPath,JSON.stringify({status:'running',browser:'Firefox 160.0.1',scope:'isolated synthetic integration'}));
  try{
    await mkdir(extension);await mkdir(profile);
    const source=resolve(root,'extension/dist-firefox');
    const artifact=await extensionDigest(source);
    for(const entry of await readdir(source,{withFileTypes:true})){
      if(!entry.isFile()||entry.isSymbolicLink())throw Error('unsafe_firefox_fixture');
      await copyFile(join(source,entry.name),join(extension,entry.name));
      if(entry.name.endsWith('.js'))assert.equal(createHash('sha256').update(await readFile(join(source,entry.name))).digest('hex'),createHash('sha256').update(await readFile(join(extension,entry.name))).digest('hex'));
    }
    assert.equal(await extensionDigest(extension),artifact);
    const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8')),csp=structuredClone(manifest.content_security_policy);
    manifest.host_permissions=manifest.optional_host_permissions.slice();manifest.background.scripts.unshift('synthetic-bootstrap.js');
    await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));assert.deepEqual(manifest.content_security_policy,csp);
    await writeFile(join(extension,'synthetic-bootstrap.js'),`(${syntheticNativeHost.toString()})(${JSON.stringify(action)});chrome.tabs.create({url:chrome.runtime.getURL('probe.html')});`);
    await writeFile(join(extension,'probe.html'),'<!doctype html><meta charset="utf-8"><title>Synthetic Firefox probe</title>');
    await writeFile(join(extension,'popup.html'),(await readFile(join(extension,'popup.html'),'utf8')).replace('<script type="module" src="popup.js">','<script src="synthetic-popup.js"></script><script type="module" src="popup.js">'));
    await writeFile(join(extension,'synthetic-popup.js'),`chrome.runtime.connectNative=()=>{let live=true;const receivers=[],disconnects=[];return {onMessage:{addListener:f=>receivers.push(f)},onDisconnect:{addListener:f=>disconnects.push(f)},disconnect(){if(live){live=false;for(const f of disconnects)f();}},postMessage(packet){chrome.runtime.sendMessage({kind:'synthetic_native_bridge',command:packet.command}).then(result=>{if(live)for(const f of receivers)f({version:1,id:packet.id,result});});}};};`);
    tls=httpsServer(await fixtureCertificate(),(req,res)=>{
      const host=req.headers.host;if(!['www.google.com','www.youtube.com','youtube.com'].includes(host)){res.writeHead(403);res.end();return;}
      if(req.method==='POST'&&req.url==='/synthetic-input'){
        let data='';req.on('data',b=>{data+=b;if(data.length>4096)req.destroy();});req.on('end',()=>{inputs.push(JSON.parse(data));res.writeHead(204);res.end();});return;
      }
      const url=new URL(req.url,'https://'+host);requests.push(url.href);
      let body=challenge==='captcha'?'<div id="captcha">Verify you are human</div>':challenge==='login'?'<input type="password">':`<input name="${host==='www.google.com'?'q':'search_query'}">`;
      body+=`<p>${BODY}</p><ytd-rich-item-renderer><a id="video-title">Synthetic garden feed</a></ytd-rich-item-renderer><ytd-rich-item-renderer><a id="video-title">${escape(XSS)}</a></ytd-rich-item-renderer><script>document.querySelector('input')?.addEventListener('input',e=>navigator.sendBeacon('/synthetic-input',JSON.stringify({value:e.target.value,trusted:e.isTrusted,at:performance.now()})))</script>`;
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});res.end('<!doctype html><meta charset="utf-8"><title>Synthetic fixture</title>'+body);
    });
    proxy=httpServer((req,res)=>{res.writeHead(403);res.end();});
    proxy.on('connect',(req,socket,head)=>{
      if(!['www.google.com:443','www.youtube.com:443','youtube.com:443'].includes(req.url)){socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');return;}
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)socket.unshift(head);tls.emit('connection',socket);
    });
    await new Promise(r=>proxy.listen(0,'127.0.0.1',r));const port=await freePort();
    const prefs={'marionette.port':port,'browser.shell.checkDefaultBrowser':false,'browser.startup.homepage':'about:blank','datareporting.healthreport.uploadEnabled':false,'datareporting.policy.dataSubmissionEnabled':false,'toolkit.telemetry.enabled':false,'app.update.disabledForTesting':true,'network.proxy.type':1,'network.proxy.http':'127.0.0.1','network.proxy.http_port':proxy.address().port,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':proxy.address().port,'network.proxy.no_proxies_on':'','network.captive-portal-service.enabled':false,'network.connectivity-service.enabled':false};
    await writeFile(join(profile,'user.js'),Object.entries(prefs).map(([k,v])=>`user_pref(${JSON.stringify(k)},${JSON.stringify(v)});`).join('\n'));
    child=spawn(binary,['-headless','-no-remote','-profile',profile,'-marionette','about:blank'],{cwd:fixture,windowsHide:true,stdio:'ignore',env:{...process.env,MOZ_CRASHREPORTER_DISABLE:'1',MOZ_REMOTE_ALLOW_SYSTEM_ACCESS:'1'}});
    client=await Marionette.connect(port);const session=await client.call('WebDriver:NewSession',{acceptInsecureCerts:true});assert.equal(session.capabilities.browserName,'firefox');
    await client.call('Addon:Install',{path:extension,temporary:true});
    let extensionUrl;
    await until(async()=>{
      const response=await client.call('WebDriver:GetWindowHandles');const handles=response.value??response;
      for(const handle of handles){await client.call('WebDriver:SwitchToWindow',{handle});const url=await client.script('return location.href;');if(url.startsWith('moz-extension:')){const parsed=new URL(url);extensionUrl=parsed.protocol+'//'+parsed.host;return true;}}
      return false;
    },Boolean);
    await client.call('WebDriver:Navigate',{url:extensionUrl+'/popup.html'});
    const popup=(await client.call('WebDriver:GetWindowHandle')).value;
    const control=(op,extra={})=>client.asyncScript(`const done=arguments[arguments.length-1];chrome.runtime.sendMessage(arguments[0]).then(done,e=>done({error:String(e)}));`,[{kind:'synthetic_control',op,...extra}]);
    const click=async selector=>{const result=await client.call('WebDriver:FindElement',{using:'css selector',value:selector});const e=result.value??result;await client.call('WebDriver:ElementClick',{id:e['element-6066-11e4-a52e-4f735466cecf']??e.ELEMENT});};
    await click('#connect');await until(()=>client.script('return document.querySelector("#tasks").disabled;'),v=>v===false);
    const start=async task=>{await control('task',{task});await click('#tasks');await until(()=>client.script('return Array.from(document.querySelectorAll("button")).some(b=>b.textContent.includes("Набрать запрос"));'),Boolean);await client.script('document.querySelectorAll("button").forEach(b=>{if(b.textContent.includes("Набрать запрос"))b.id="synthetic-run";});');await click('#synthetic-run');};
    await scenario('Google and YouTube use real Firefox scripting and exact approved queries',async()=>{
      for(const [i,service] of ['google','youtube'].entries()){
        const before=inputs.length;await start({...action,service,action_index:i});
        const state=await until(()=>control('state'),c=>c.completed||c.paused,45000);
        assert.equal(state.completed,true,JSON.stringify({events:state.events,commands:state.commands.map(c=>c.kind)}));
        assert.equal(inputs.slice(before).map(e=>e.value.at(-1)).join(''),action.text);assert.ok(inputs.slice(before).every(e=>e.trusted===false));
        assert.ok(!JSON.stringify(state.commands).includes(BODY));
        const result=requests.filter(s=>new URL(s).pathname===(service==='google'?'/search':'/results'));assert.equal(result.length,1);
        assert.equal(new URL(result[0]).searchParams.get(service==='google'?'q':'search_query'),action.text);
      }
    });
    await scenario('a real Firefox alarm captures literal title text without extension-storage content',async()=>{
      const value=await client.call('WebDriver:NewWindow',{type:'tab'});await client.call('WebDriver:SwitchToWindow',{handle:(value.value??value).handle});await client.call('WebDriver:Navigate',{url:'https://www.youtube.com/'});
      await client.call('WebDriver:SwitchToWindow',{handle:popup});await click('#periodic-mirror');
      await until(()=>control('storage'),s=>s['mirror-schedule-v1']?.enabled===true);
      await control('alarm');const state=await until(()=>control('state'),s=>s.snapshots.length>0);
      assert.deepEqual(state.snapshots[0].items,['Synthetic garden feed',XSS]);assert.ok(!JSON.stringify(await control('storage')).includes(XSS));assert.ok(!JSON.stringify(await control('storage')).includes(BODY));
      await click('#periodic-mirror');
    });
    await scenario('CAPTCHA and login stop before any character or results request',async()=>{
      for(const [i,kind] of ['captcha','login'].entries()){
        challenge=kind;const typed=inputs.length,before=requests.filter(s=>['/search','/results'].includes(new URL(s).pathname)).length;
        await start({...action,action_index:i+2});const state=await until(()=>control('state'),s=>s.paused);
        assert.equal(inputs.length,typed);assert.equal(requests.filter(s=>['/search','/results'].includes(new URL(s).pathname)).length,before);
        const stop=state.commands.find(c=>c.kind==='safety_stop');assert.ok(stop,JSON.stringify({events:state.events,commands:state.commands,kind}));assert.equal(stop.reason,kind);assert.deepEqual(Object.keys(stop).sort(),['event_id','kind','reason']);
      }
    });
    if(passed!==3)throw Error('incomplete_firefox_scenarios');
    await writeFile(reportPath,JSON.stringify({status:'passed',browser:'Firefox '+session.capabilities.browserVersion,checked_at:new Date().toISOString(),extension_sha256:artifact,scope:'stock Firefox; temporary MV3; synthetic loopback HTTPS; fake native core; no user profile',scenarios:['google','youtube','alarm','captcha','login','xss_storage']},null,2));
  }finally{
    if(client){try{await client.call('Marionette:Quit',{flags:['eForceQuit']},5000);}catch{}client.close();}
    if(child&&child.exitCode===null){await Promise.race([new Promise(r=>child.once('exit',r)),wait(3000)]);if(child.exitCode===null)child.kill();}
    proxy?.closeAllConnections();if(proxy?.listening)await new Promise(r=>proxy.close(r));tls?.closeAllConnections();
    const actual=await realpath(fixture),parent=await realpath(base),m=await lstat(fixture),normal=s=>process.platform==='win32'?s.toLowerCase():s;
    if(m.isSymbolicLink()||!normal(actual).startsWith(normal(parent+sep)))throw Error('unsafe_firefox_cleanup');await rm(fixture,{recursive:true,force:true,maxRetries:20,retryDelay:100});
  }
});
