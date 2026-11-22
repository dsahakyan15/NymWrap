// Explicit Windows integration: a unique temporary native-host alias, real host and real core.
// Does not overwrite the installed host registration or read an existing browser profile.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,mkdtemp,readFile,writeFile,readdir,copyFile,realpath,lstat,rm} from 'node:fs/promises';
import {resolve,join,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes,createHash} from 'node:crypto';
import net from 'node:net';
import {Marionette} from '../browser/helpers/marionette.mjs';
import {extensionDigest} from '../browser/helpers/artifact.mjs';
import {HOST} from '../../dist/protocol.js';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../..'),base=join(root,'target/browser-tests');
const run=promisify(execFile),wait=ms=>new Promise(r=>setTimeout(r,ms));
const alive=child=>child&&child.exitCode===null&&child.signalCode===null;
async function until(read,predicate,timeout=30000){const end=Date.now()+timeout;while(Date.now()<end){const result=await read();if(predicate(result))return result;await wait(100);}throw Error('native_browser_condition_timeout');}
async function stop(child){if(!alive(child))return;child.kill();for(let i=0;i<50&&alive(child);i++)await wait(100);if(alive(child))throw Error('fixture_process_cleanup_failed');}

test('stock Firefox Native Messaging reaches the actual core and persists pause/resume',{timeout:120000,skip:process.platform!=='win32'?'Windows native-host registration fixture':false},async t=>{
  await mkdir(base,{recursive:true});const fixture=await mkdtemp(join(base,'firefox-native-'));
  const binaries=join(root,'app/src-tauri/target/release'),profile=join(fixture,'profile'),extension=join(fixture,'extension');
  const portablePowerShell=join(root,'target/tools/powershell-7.7.0/pwsh.exe');
  const powershell=await lstat(portablePowerShell).then(()=>portablePowerShell,e=>{if(e.code!=='ENOENT')throw e;return 'pwsh';}),alias='org.nymwrap.fixture'+randomBytes(12).toString('hex');
  const manifestPath=join(fixture,'native-host.json'),registryScript=join(root,'extension/tests/native/registry-fixture.ps1');
  const env={...process.env,LOCALAPPDATA:fixture,APPDATA:fixture,XDG_DATA_HOME:fixture,XDG_RUNTIME_DIR:join(fixture,'runtime')};
  const reportPath=join(base,'reports/firefox-native.json');await mkdir(dirname(reportPath),{recursive:true});
  await writeFile(reportPath,JSON.stringify({status:'running',browser:'Firefox',scope:'real native messaging integration'}));
  let daemon,browser,client,proxy,registered=false,created=false,store,record;
  const sockets=new Set(),mark=phase=>writeFile(reportPath,JSON.stringify({status:'running',browser:'Firefox',scope:'real native messaging integration',phase}));
  function rpc(command){return new Promise((accept,reject)=>{
    const child=spawn(join(binaries,'nymwrap.exe'),['rpc'],{cwd:root,env,windowsHide:true,stdio:['pipe','pipe','ignore']});let output='';
    const timer=setTimeout(()=>{child.kill();reject(Error('fixture_rpc_timeout'));},15000);
    child.stdout.on('data',b=>{output+=b;if(output.length>1024**2)child.kill();});child.once('error',reject);
    child.once('exit',code=>{clearTimeout(timer);if(code!==0)reject(Error('fixture_rpc_failed'));else{try{accept(JSON.parse(output));}catch{reject(Error('fixture_rpc_invalid'));}}});
    child.stdin.on('error',()=>{});child.stdin.end(JSON.stringify(command));
  });}
  function nativeStatus(){return new Promise((accept,reject)=>{
    const child=spawn(join(binaries,'nw-drift-host.exe'),[],{cwd:root,env,windowsHide:true,stdio:['pipe','pipe','ignore']});let output=Buffer.alloc(0);
    const timer=setTimeout(()=>{child.kill();reject(Error('fixture_native_timeout'));},10000);
    child.stdout.on('data',b=>{output=Buffer.concat([output,b]);if(output.length>65536)child.kill();});child.once('error',reject);
    child.once('exit',code=>{clearTimeout(timer);try{assert.equal(code,0);assert.equal(output.readUInt32LE(0),output.length-4);const reply=JSON.parse(output.subarray(4));assert.equal(reply.id,47);assert.equal(reply.result.kind,'status');accept(reply.result);}catch{reject(Error('fixture_native_invalid'));}});
    const packet=Buffer.from(JSON.stringify({version:1,id:47,command:{kind:'status'}})),size=Buffer.alloc(4);size.writeUInt32LE(packet.length);child.stdin.on('error',()=>{});child.stdin.end(Buffer.concat([size,packet]));
  });}
  const registry=mode=>run(powershell,['-NoProfile','-NonInteractive','-File',registryScript,'-Mode',mode,'-Name',alias,'-Manifest',manifestPath],{windowsHide:true,maxBuffer:65536});
  try{
    await mkdir(env.XDG_RUNTIME_DIR);await mkdir(profile);await mkdir(extension);
    let existing=false;try{await rpc({op:'status'});existing=true;}catch{}
    if(existing)throw Error('daemon_already_running_close_it_before_native_test');
    daemon=spawn(join(binaries,'nymwrapd.exe'),[],{cwd:root,env,windowsHide:true,stdio:'ignore'});daemon.on('error',()=>{});
    await until(async()=>{if(!alive(daemon))throw Error('fixture_core_start_failed');try{return await rpc({op:'status'});}catch{return null;}},Boolean);
    const opened=await rpc({op:'open_workspace',password:'',create:true,profile:'standard'});store=opened.path;created=true;
    assert.ok(resolve(store).startsWith(resolve(fixture)+sep));assert.equal((await nativeStatus()).paused,false);
    await mark('core_opened');
    const source=join(root,'extension/dist-firefox'),artifact=await extensionDigest(source);
    for(const entry of await readdir(source,{withFileTypes:true})){if(!entry.isFile()||entry.isSymbolicLink())throw Error('unexpected_extension_artifact');await copyFile(join(source,entry.name),join(extension,entry.name));}
    assert.equal(await extensionDigest(extension),artifact);
    const manifest=JSON.parse(await readFile(join(extension,'manifest.json'),'utf8')),csp=structuredClone(manifest.content_security_policy);
    manifest.background.scripts.unshift('fixture-open.js');await writeFile(join(extension,'manifest.json'),JSON.stringify(manifest));assert.deepEqual(manifest.content_security_policy,csp);
    await writeFile(join(extension,'fixture-open.js'),"chrome.tabs.create({url:chrome.runtime.getURL('popup.html')});");
    await writeFile(join(extension,'fixture-alias.js'),'const originalNative=chrome.runtime.connectNative.bind(chrome.runtime);chrome.runtime.connectNative=host=>{if(host!=='+JSON.stringify(HOST)+')throw Error("unexpected_native_host");return originalNative('+JSON.stringify(alias)+');};');
    await writeFile(join(extension,'popup.html'),(await readFile(join(extension,'popup.html'),'utf8')).replace('<script type="module" src="popup.js">','<script src="fixture-alias.js"></script><script type="module" src="popup.js">'));
    const wrapper=join(fixture,'native-relay.exe'),wrapperSource=join(fixture,'native-relay.rs');
    const rust='use std::process::{Command,Stdio};use std::os::windows::process::CommandExt;fn main(){let result=Command::new('+JSON.stringify(join(binaries,'nw-drift-host.exe'))+')'+['LOCALAPPDATA','XDG_DATA_HOME','XDG_RUNTIME_DIR'].map(k=>'.env('+JSON.stringify(k)+','+JSON.stringify(env[k])+')').join('')+'.creation_flags(0x08000000).stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::null()).status();std::process::exit(result.ok().and_then(|s|s.code()).unwrap_or(1));}';
    await writeFile(wrapperSource,rust);await run('rustc',['--edition=2024',wrapperSource,'-o',wrapper],{windowsHide:true,maxBuffer:65536});
    await writeFile(manifestPath,JSON.stringify({name:alias,description:'NymWrap isolated native bridge fixture',path:wrapper,type:'stdio',allowed_extensions:[manifest.browser_specific_settings.gecko.id]}));
    registered=true;await registry('Register');await mark('host_registered');
    // Browser network is denied; the real Native Messaging pipe is independent of it.
    proxy=net.createServer(socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');});await new Promise(r=>proxy.listen(0,'127.0.0.1',r));
    const portServer=net.createServer();await new Promise(r=>portServer.listen(0,'127.0.0.1',r));const port=portServer.address().port;await new Promise(r=>portServer.close(r));
    const prefs={'marionette.port':port,'browser.shell.checkDefaultBrowser':false,'datareporting.healthreport.uploadEnabled':false,'datareporting.policy.dataSubmissionEnabled':false,'toolkit.telemetry.enabled':false,'app.update.disabledForTesting':true,'network.proxy.type':1,'network.proxy.http':'127.0.0.1','network.proxy.http_port':proxy.address().port,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':proxy.address().port,'network.proxy.no_proxies_on':'','network.captive-portal-service.enabled':false,'network.connectivity-service.enabled':false};
    await writeFile(join(profile,'user.js'),Object.entries(prefs).map(([k,v])=>'user_pref('+JSON.stringify(k)+','+JSON.stringify(v)+');').join('\n'));
    browser=spawn(join(root,'target/tools/privacy-browser/firefox-160.0.1/core/firefox.exe'),['-headless','-no-remote','-profile',profile,'-marionette','about:blank'],{cwd:fixture,windowsHide:true,stdio:'ignore',env:{...env,MOZ_CRASHREPORTER_DISABLE:'1',MOZ_REMOTE_ALLOW_SYSTEM_ACCESS:'1'}});browser.on('error',()=>{});
    client=await Marionette.connect(port);const session=await client.call('WebDriver:NewSession',{});
    await client.call('Addon:Install',{path:extension,temporary:true});
    await until(async()=>{
      const reply=await client.call('WebDriver:GetWindowHandles');for(const handle of reply.value??reply){await client.call('WebDriver:SwitchToWindow',{handle});if((await client.script('return location.href;')).startsWith('moz-extension:'))return true;}return false;
    },Boolean);
    const click=async selector=>{const response=await client.call('WebDriver:FindElement',{using:'css selector',value:selector}),element=response.value??response;await client.call('WebDriver:ElementClick',{id:element['element-6066-11e4-a52e-4f735466cecf']??element.ELEMENT});};
    await click('#connect');await until(()=>client.script('return document.querySelector("#pause").disabled;'),value=>value===false);
    await mark('real_bridge_connected');
    await click('#pause');await until(()=>nativeStatus(),value=>value.paused===true);
    await click('#pause');await until(()=>nativeStatus(),value=>value.paused===false);
    await mark('pause_resume_verified');
    assert.equal((await rpc({op:'load_network_usage'})).requests,0);
    const hash=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
    record={status:'passed',browser:'Firefox '+session.capabilities.browserVersion,checked_at:new Date().toISOString(),extension_sha256:artifact,native_host_sha256:await hash(join(binaries,'nw-drift-host.exe')),core_sha256:await hash(join(binaries,'nymwrapd.exe')),test_sha256:await hash(fileURLToPath(import.meta.url)),registry_fixture_sha256:await hash(registryScript),relay_source_sha256:await hash(wrapperSource),relay_binary_sha256:await hash(wrapper),scope:'real Firefox Native Messaging via temporary alias; unchanged product JS and CSP; actual release host/core; synthetic encrypted workspace; network denied',scenarios:['connect','pause','resume','independent_core_status','zero_network_reservations'],registry_restored:true};
  }finally{
    if(client){try{await client.call('Marionette:Quit',{flags:['eForceQuit']});}catch{}client.close();}
    await stop(browser);
    if(registered)await registry('Remove');
    if(created){const status=await rpc({op:'workspace_status'});if(resolve(status.path)!==resolve(store)||!resolve(store).startsWith(resolve(fixture)+sep))throw Error('foreign_workspace_cleanup_refused');await rpc({op:'destroy_data',confirmation:'СТЕРЕТЬ ВСЁ'});}
    await stop(daemon);for(const socket of sockets)socket.destroy();if(proxy?.listening)await new Promise(r=>proxy.close(r));
    const actual=await realpath(fixture),parent=await realpath(base);if((await lstat(fixture)).isSymbolicLink()||!actual.toLowerCase().startsWith((parent+sep).toLowerCase()))throw Error('unsafe_native_fixture_cleanup');await rm(fixture,{recursive:true,force:true});
  }
  if(t.signal.aborted)throw Error('native_fixture_timed_out');
  await writeFile(reportPath,JSON.stringify(record,null,2)+'\n');
});
