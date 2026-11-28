import {test} from "node:test";
import assert from "node:assert/strict";
import {readFile,readdir} from "node:fs/promises";
const read=path=>readFile(new URL(path,import.meta.url),"utf8");

test("page CSP matches the Tauri CSP and the page loads nothing external or inline",async()=>{
  const [html,css,conf]=await Promise.all([read("../index.html"),read("../style.css"),read("../src-tauri/tauri.conf.json")]);
  const meta=html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/);
  assert.ok(meta);assert.equal(meta[1],JSON.parse(conf).app.security.csp);
  const body=html.replace(meta[0],"");
  assert.doesNotMatch(body,/https?:|\/\/[a-z]/i,"no absolute URLs");
  assert.doesNotMatch(body,/\son[a-z]+=/i,"no inline event handlers");
  assert.doesNotMatch(body,/style=/i,"no inline styles");
  const scripts=[...body.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length,1);assert.match(scripts[0][1],/type="module" src="main\.js"/);assert.equal(scripts[0][2].trim(),"");
  assert.doesNotMatch(css,/@import|url\(|https?:/i,"no external fonts or images");
});

test("navigation has four sections plus settings, and approvals stay explicit",async()=>{
  const html=await read("../index.html");
  const nav=html.match(/<nav id="main-nav"[\s\S]*?<\/nav>/)[0];
  assert.deepEqual([...nav.matchAll(/data-view="([a-z]+)"/g)].map(m=>m[1]),["shield","drift","purge","mirror"]);
  assert.match(html,/data-view="settings"[^>]*aria-label="Настройки"/);
  for(const step of ["1","2","3","4"])assert.match(html,new RegExp(`data-step-pane="${step}"`));
  // The purge approval is hidden until a batch has been shown.
  assert.match(html,/id="approve-purge" class="primary" hidden/);
  for(const id of ["approve-plan","approve-purge","open-workspace","start-model","approve-day"])
    assert.match(html+await read("../src/main.ts"),new RegExp(`["=]${id}["]`));
});

test("built UI never parses data as HTML",async()=>{
  for(const file of (await readdir(new URL("../dist/",import.meta.url))).filter(f=>f.endsWith(".js"))){
    const js=await read(`../dist/${file}`);
    for(const sink of ["outerHTML","insertAdjacentHTML","document.write","createContextualFragment","DOMParser","new Function"])assert.ok(!js.includes(sink),file+": "+sink);
  }
});
