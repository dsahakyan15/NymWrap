import {test} from "node:test";
import assert from "node:assert/strict";
import {readFile,readdir} from "node:fs/promises";
test("local UI has restrictive CSP and no network or content persistence",async()=>{
  const config=JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json",import.meta.url),"utf8"));
  assert.ok(config.app.security.csp.includes("script-src 'self'"));
  assert.ok(!config.app.security.csp.includes("unsafe-inline"));
  assert.equal(config.build.devUrl,undefined);
  for(const file of (await readdir(new URL("../dist/",import.meta.url))).filter(f=>f.endsWith('.js'))){
    const js=await readFile(new URL(`../dist/${file}`,import.meta.url),"utf8");
    for(const forbidden of ["innerHTML","eval(","localStorage","sessionStorage","fetch(","WebSocket("]) assert.ok(!js.includes(forbidden),file+': '+forbidden);
  }
});
