// Explicit, read-only compatibility probe. No existing profile, credentials or form submission.
import {spawn} from 'node:child_process';
import net from 'node:net';
import {mkdir,mkdtemp,writeFile,realpath,lstat,rm,readFile} from 'node:fs/promises';
import {resolve,join,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {Marionette} from '../tests/browser/helpers/marionette.mjs';
import {liveProbeExpression} from '../tests/browser/helpers/live-probe.mjs';
if(process.platform!=='win32')throw Error('stock_firefox_public_probe_windows_only');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..'),base=join(root,'target/browser-tests');
await mkdir(base,{recursive:true});const fixture=await mkdtemp(join(base,'public-firefox-'));
let browser,client;
try{
  const server=net.createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;await new Promise(r=>server.close(r));
  const profile=join(fixture,'profile');await mkdir(profile);
  const prefs={'marionette.port':port,'browser.shell.checkDefaultBrowser':false,'browser.startup.homepage':'about:blank','datareporting.healthreport.uploadEnabled':false,'datareporting.policy.dataSubmissionEnabled':false,'toolkit.telemetry.enabled':false,'app.update.disabledForTesting':true,'network.captive-portal-service.enabled':false,'network.connectivity-service.enabled':false};
  await writeFile(join(profile,'user.js'),Object.entries(prefs).map(([k,v])=>`user_pref(${JSON.stringify(k)},${JSON.stringify(v)});`).join('\n'));
  browser=spawn(join(root,'target/tools/privacy-browser/firefox-160.0.1/core/firefox.exe'),['-headless','-no-remote','-profile',profile,'-marionette','about:blank'],{cwd:fixture,windowsHide:true,stdio:'ignore',env:{...process.env,MOZ_CRASHREPORTER_DISABLE:'1'}});
  client=await Marionette.connect(port);const session=await client.call('WebDriver:NewSession',{});
  await client.call('WebDriver:SetTimeouts',{pageLoad:30000,script:10000,implicit:0});
  const observations=[];
  for(const url of ['https://www.google.com/','https://www.youtube.com/','https://myadcenter.google.com/','https://chatgpt.com/','https://claude.ai/','https://gemini.google.com/']){
    let navigation='loaded',observed;
    try{await client.call('WebDriver:Navigate',{url});}catch{navigation='failed_or_timed_out';}
    try{observed=await client.script('return '+liveProbeExpression+';');}catch{navigation='unreadable';}
    const record={requested_origin:new URL(url).origin,navigation,...(observed??{})};observations.push(record);console.log(JSON.stringify(record));
  }
  const sha256=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
  const report={status:'observed',browser:'Firefox '+session.capabilities.browserVersion,checked_at:new Date().toISOString(),scope:'fresh logged-out stock profile; valid TLS; production read-only DOM functions; no search, form input, video click or AI web message; account-only interfaces unverified',capture_sha256:await sha256(join(root,'extension/dist/capture.js')),search_page_sha256:await sha256(join(root,'extension/dist/search_page.js')),observations};
  await mkdir(join(base,'reports'),{recursive:true});await writeFile(join(base,'reports/live-firefox.json'),JSON.stringify(report,null,2)+'\n');
}finally{
  if(client){try{await client.call('Marionette:Quit',{flags:['eForceQuit']});}catch{}client.close();}
  if(browser&&browser.exitCode===null){await new Promise(r=>{browser.once('exit',r);setTimeout(r,5000).unref();});if(browser.exitCode===null)browser.kill();}
  if(browser&&browser.exitCode===null)await new Promise(r=>{browser.once('exit',r);setTimeout(r,5000).unref();});
  const actual=await realpath(fixture),parent=await realpath(base);if((await lstat(fixture)).isSymbolicLink()||!actual.toLowerCase().startsWith((parent+sep).toLowerCase()))throw Error('unsafe_public_firefox_cleanup');
  await rm(fixture,{recursive:true,force:true});
}
