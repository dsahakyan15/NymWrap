import { NativeBridge } from "./native.js";
import { readMirrorPage } from "./capture.js";
import { MirrorScheduler, MIRROR_ALARM, MIRROR_ORIGINS } from "./mirror_schedule.js";
import { SearchExecutor, searchOrigins } from "./execution.js";
import { searchPageStep } from "./search_page.js";
import { task as validateTask } from "./protocol.js";

declare const chrome: {
  runtime: {
    id: string; getURL(path: string): string;
    onStartup: { addListener(fn: () => void): void };
    onInstalled: { addListener(fn: () => void): void };
    onMessage: { addListener(fn: (message: unknown, sender: { id?: string; url?: string }, respond: (result: unknown) => void) => boolean): void };
  };
  alarms: { get(name: string): Promise<unknown>; create(name: string, options: { periodInMinutes: number }): Promise<void>; clear(name: string): Promise<boolean>; onAlarm: { addListener(fn: (alarm: { name: string }) => void): void } };
  storage: { local: { get(key: string): Promise<Record<string, unknown>>; set(value: Record<string, unknown>): Promise<void> } };
  permissions: { contains(value: { origins: string[] }): Promise<boolean>; onRemoved: { addListener(fn: () => void): void } };
  tabs: { query(value: { url: string[] }): Promise<{ id?: number; url?: string; incognito?: boolean }[]>;get(id:number):Promise<{status?:string;url?:string}>;create(value:{url:string;active:boolean}):Promise<{id?:number}>;update(id:number,value:{url:string}):Promise<unknown> };
  scripting: { executeScript<T,A extends unknown[]>(value: { target: { tabId: number }; func: (...args:A) => T;args?:A }): Promise<{ result?: T }[]> };
};
let executionCode="idle";
const executor=new SearchExecutor({
  bridge:()=>{const bridge=new NativeBridge();bridge.connect();return bridge;},
  permitted:service=>chrome.permissions.contains({origins:searchOrigins(service)}),
  create:async url=>{const tab=await chrome.tabs.create({url,active:true});if(tab.id===undefined)throw Error("execution_interrupted");return tab.id;},
  navigate:async(id,url)=>{await chrome.tabs.update(id,{url});},
  step:async(id,step)=>{
    // A newly created/navigating tab can still expose its previous document.
    const tab=await chrome.tabs.get(id);
    if(tab.status!=="complete")return "loading";
    // Firefox can report the initial about:blank as complete before committing the HTTPS URL.
    // Wait only for a read-only inspection; a lost input acknowledgement is still terminal.
    if(!tab.url||tab.url==="about:blank")return step.letter===undefined?"loading":"unsupported";
    const value=(await chrome.scripting.executeScript({target:{tabId:id},func:searchPageStep,args:[step]}))[0]?.result;
    // Only read-only inspections can retry a lost navigation result. Never retype a character.
    return value??(step.letter===undefined?"loading":"unsupported");
  },
  wait:(ms,signal)=>new Promise((resolve,reject)=>{
    if(signal.aborted){reject(Error("execution_interrupted"));return;}
    const abort=()=>{clearTimeout(timer);reject(Error("execution_interrupted"));};
    const timer=setTimeout(()=>{signal.removeEventListener("abort",abort);resolve();},ms);
    signal.addEventListener("abort",abort,{once:true});
  }),
  now:()=>Date.now(),random:()=>crypto.getRandomValues(new Uint32Array(1))[0]!/4294967296,
  eventId:()=>crypto.randomUUID().replaceAll("-",""),
});
const KEY = "mirror-schedule-v1";
const scheduler = new MirrorScheduler({
  load: async () => (await chrome.storage.local.get(KEY))[KEY],
  save: state => chrome.storage.local.set({ [KEY]: state }),
  permitted: () => chrome.permissions.contains({ origins: MIRROR_ORIGINS }),
  bridge: () => { const bridge = new NativeBridge(); bridge.connect(); return bridge; },
  tabs: () => chrome.tabs.query({ url: MIRROR_ORIGINS }),
  capture: async tabId => (await chrome.scripting.executeScript({ target: { tabId }, func: readMirrorPage }))[0]?.result,
  now: () => Math.floor(Date.now() / 1000),
  eventId: () => crypto.randomUUID().replaceAll("-", ""),
});
async function reconcile() {
  if ((await scheduler.status()).enabled) {
    if (!await chrome.alarms.get(MIRROR_ALARM)) await chrome.alarms.create(MIRROR_ALARM, { periodInMinutes: 60 });
  }
  else await chrome.alarms.clear(MIRROR_ALARM);
}
const safely = (work: Promise<unknown>) => { void work.catch(() => {}); };
chrome.runtime.onStartup.addListener(() => safely(reconcile()));
chrome.runtime.onInstalled.addListener(() => safely(reconcile()));
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === MIRROR_ALARM) safely(scheduler.tick().finally(reconcile));
});
chrome.permissions.onRemoved.addListener(() => {executor.cancel();safely((async () => {
  if (!await chrome.permissions.contains({ origins: MIRROR_ORIGINS })) {
    await scheduler.configure(false, "permission_required"); await reconcile();
  }
})());});
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL("popup.html")) return false;
  if (!message || typeof message !== "object" || Array.isArray(message)) return false;
  const v = message as Record<string, unknown>;
  if(v.kind==="execution_status"&&Object.keys(v).length===1){respond({running:executor.running,code:executionCode});return false;}
  if(v.kind==="execution_cancel"&&Object.keys(v).length===1){executor.cancel();respond({cancelled:true});return false;}
  if(v.kind==="execute_search"&&Object.keys(v).length===2){
    try{
      const task=validateTask(v.task);searchOrigins(task.service);
      if(executor.running||Array.from(task.text).length>512)throw Error("request_in_progress");
      executionCode="running";
      void executor.run(task).then(()=>{executionCode="completed";},error=>{executionCode=error instanceof Error&&/^[a-z_]{1,64}$/.test(error.message)?error.message:"execution_interrupted";});
      respond({started:true});
    }catch{respond({error:"manual_action_required"});}
    return false;
  }
  if (v.kind === "mirror_status" && Object.keys(v).length === 1) {
    void scheduler.status().then(respond, () => respond({ error: "mirror_unavailable" })); return true;
  }
  if (v.kind === "mirror_configure" && Object.keys(v).length === 2 && typeof v.enabled === "boolean") {
    void scheduler.configure(v.enabled).then(async state => {
      await reconcile(); respond(state);
    }).catch(() => respond({ error: "mirror_unavailable" }));
    return true;
  }
  return false;
});
// Recreate an alarm if the browser discarded it while the worker was stopped.
safely(reconcile());
