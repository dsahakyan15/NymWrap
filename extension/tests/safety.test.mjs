import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pageState, coverUrl, snapshotTitles } from "../dist/safety.js";
const ready = { url: "https://www.youtube.com/", title: "Home", text: "Synthetic videos", hasPassword: false, hasChallenge: false };
test("stops on CAPTCHA fixture, challenge markers and login", async () => {
  const fixture = await readFile(new URL("fixtures/captcha.html", import.meta.url), "utf8");
  assert.equal(pageState({ ...ready, text: fixture }), "challenge");
  assert.equal(pageState({ ...ready, hasChallenge: true }), "challenge");
  assert.equal(pageState({ ...ready, url: "https://www.google.com/sorry/index" }), "challenge");
  assert.equal(pageState({ ...ready, hasPassword: true }), "login");
  assert.equal(pageState({ ...ready, url: "https://accounts.google.com/" }), "login");
});
test("only explicit supported HTTPS pages and non-AI task URLs", () => {
  assert.equal(pageState(ready), "ready");
  assert.equal(pageState({ ...ready, url: "https://www.youtube.com.evil.test/" }), "unsupported");
  assert.equal(pageState({ ...ready, url: "javascript:alert(1)" }), "unsupported");
  assert.throws(() => coverUrl("chatgpt", "test"));
  assert.match(coverUrl("google", "pottery & gardens"), /pottery%20%26%20gardens$/);
});
test("hostile titles remain data; site access is optional and limited to cover search hosts", async () => {
  const titles = snapshotTitles(Array(40).fill("<script>alert(1)</script>"));
  assert.equal(titles.length, 30); assert.equal(titles[0], "<script>alert(1)</script>");
  const script = await readFile(new URL("../src/popup.ts", import.meta.url), "utf8");
  assert.ok(!script.includes("innerHTML")); assert.ok(script.includes("item.textContent = title"));
  const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
  assert.deepEqual(manifest.permissions, ["activeTab", "scripting", "nativeMessaging", "alarms", "storage"]);
  assert.deepEqual(manifest.optional_host_permissions, ["https://www.youtube.com/*", "https://youtube.com/*", "https://www.google.com/*"]);
  assert.equal(manifest.host_permissions, undefined); assert.equal(manifest.content_scripts, undefined);
  const chrome=JSON.parse(await readFile(new URL('../dist/manifest.json',import.meta.url),'utf8'));
  const firefox=JSON.parse(await readFile(new URL('../dist-firefox/manifest.json',import.meta.url),'utf8'));
  assert.deepEqual(chrome.background,{service_worker:'background.js',type:'module'});
  assert.deepEqual(firefox.background,{scripts:['background.js'],type:'module'});
});
