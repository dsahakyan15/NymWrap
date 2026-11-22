import { pageState, snapshotTitles, coverUrl, type PageSignals } from "./safety.js";
import {NativeBridge} from "./native.js";
import type {Task} from "./protocol.js";
import {readMirrorPage} from "./capture.js";
import {MIRROR_ORIGINS, scheduleState, type ScheduleState} from "./mirror_schedule.js";
import {searchOrigins} from "./execution.js";
declare const chrome: {
  tabs: { query(query: { active: boolean; currentWindow: boolean }): Promise<{ id?: number; url?: string }[]>;create(options:{url:string}):Promise<unknown> };
  scripting: { executeScript<T>(options: { target: { tabId: number }; func: () => T }): Promise<{ result?: T }[]> };
  runtime: { sendMessage(message: unknown): Promise<unknown> };
  permissions: { request(value: {origins: string[]}): Promise<boolean> };
};
const status = document.querySelector<HTMLElement>("#status")!;
const list = document.querySelector<HTMLOListElement>("#titles")!;
const bridge=new NativeBridge();
const button=(id:string)=>document.querySelector<HTMLButtonElement>("#"+id)!;
const bridgeStatus=document.querySelector<HTMLElement>("#bridge-status")!;
const periodicStatus=document.querySelector<HTMLElement>("#periodic-status")!;
let periodicEnabled=false;
function showPeriodic(value:unknown){
  if(value&&typeof value==="object"&&"error" in value)throw Error("mirror_unavailable");
  const state:ScheduleState=scheduleState(value);periodicEnabled=state.enabled;
  button("periodic-mirror").disabled=false;
  button("periodic-mirror").textContent=state.enabled?"Выключить ежедневные снимки":"Включить ежедневные снимки";
  const messages:Record<string,string>={disabled:"Ежедневные снимки выключены.",ready:"Снимок будет сделан с уже открытой главной YouTube, когда ядро доступно.",saved:"Ежедневный снимок сохранён в Mirror.",no_tab:"Ожидание открытой главной YouTube.",empty:"Карточки не найдены. Можно сделать снимок вручную.",paused:"Drift на паузе; снимки приостановлены.",locked:"Откройте пространство NymWrap.",unavailable:"Проверьте ядро, модель и одобренный план.",captcha:"Снимки выключены после CAPTCHA. Продолжение включается вручную.",login:"Снимки выключены: требуется ваш вход.",permission_required:"Нужно разрешение браузера на чтение YouTube."};
  periodicStatus.textContent=messages[state.code]+(state.last_saved?" Последний: "+new Date(state.last_saved*1000).toLocaleString():"");
}
button("periodic-mirror").addEventListener("click",()=>{
  const enabled=!periodicEnabled;button("periodic-mirror").disabled=true;
  // Request optional site access directly in the user's click gesture.
  const permission=enabled?chrome.permissions.request({origins:MIRROR_ORIGINS}):Promise.resolve(true);
  void permission.then(async granted=>{
    if(!granted)throw Error("permission_denied");
    showPeriodic(await chrome.runtime.sendMessage({kind:"mirror_configure",enabled}));
  }).catch(()=>{button("periodic-mirror").disabled=false;periodicStatus.textContent="Настройка не изменена. Проверьте разрешение на YouTube.";});
});
void (async()=>showPeriodic(await chrome.runtime.sendMessage({kind:"mirror_status"})))().catch(()=>{periodicStatus.textContent="Расписание недоступно. Перезагрузите расширение.";});
let paused=false;
let connected=false;
let executionMode="assisted";
let captured:{kind:"youtube_feed"|"ad_topics";items:string[];captured_at:number}|undefined;
let stopped:{event_id:string;reason:"captcha"|"login"}|undefined;
function failure(error:unknown){
  const messages:Record<string,string>={bridge_disconnected:"Канал закрыт. Проверьте установку native host и открытое пространство.",workspace_locked:"Сначала откройте пространство в NymWrap.",not_ready:"Одобрите план и формулировки дня в NymWrap. Проверьте интервал между днями и Mirror.",paused:"Drift на паузе.",invalid_request:"Сообщение отклонено политикой ядра.",model_unavailable:"Локальная модель недоступна.",storage_unavailable:"Хранилище недоступно."};
  bridgeStatus.textContent=messages[error instanceof Error?error.message:""]??"Операция остановлена. Проверьте состояние NymWrap.";
}
async function tasks(){
  if(paused)throw Error("paused");
  const result=await bridge.request({kind:"tasks"});if(result.kind!=="tasks")throw Error("invalid_bridge_reply");
  const out=document.querySelector<HTMLOListElement>("#tasks-list")!;out.replaceChildren();
  for(const task of result.tasks){
    const item=document.createElement("li");const text=document.createElement("p");text.textContent=task.text;
    const service=document.createElement("small");service.textContent=task.service+" · "+task.stage+"."+task.day;
    item.append(service,text);
    if(task.service==="google"||task.service==="youtube"){
      const open=document.createElement("button");open.textContent="Открыть поиск";open.addEventListener("click",()=>{if(paused){failure(Error("paused"));return;}void chrome.tabs.create({url:coverUrl(task.service,task.text)}).catch(failure);});item.append(open);
      if(executionMode==="extension"&&Array.from(task.text).length<=512){
        const execute=document.createElement("button");execute.textContent="Набрать запрос и открыть результаты";
        execute.addEventListener("click",()=>{
          if(paused){failure(Error("paused"));return;}execute.disabled=true;
          void chrome.permissions.request({origins:searchOrigins(task.service)}).then(async granted=>{
            if(!granted)throw Error("permission_required");
            const result=await chrome.runtime.sendMessage({kind:"execute_search",task});
            if(!result||typeof result!=="object"||!("started" in result)||result.started!==true)throw Error("manual_action_required");
            bridgeStatus.textContent="Запуск поиска в отдельной вкладке. Печать: 60–180 мс на символ, чтение: 20–90 с. Результат — в «Состоянии исполнения». Для остановки закройте вкладку или нажмите «Остановить исполнение».";
          }).catch(error=>{execute.disabled=false;failure(error);});
        });item.append(execute);
      }
    }
    const complete=document.createElement("button");complete.textContent="Выполнено вручную";complete.addEventListener("click",()=>{complete.disabled=true;void bridge.request({kind:"complete",task:task as Task}).then(()=>{item.remove();bridgeStatus.textContent="Выполнение сохранено в ядре.";}).catch(e=>{complete.disabled=false;failure(e);});});item.append(complete);out.append(item);
  }
  bridgeStatus.textContent=result.tasks.length?"Только одобренные действия легенды. Выполняйте их в своём темпе.":"План завершён.";
}
button("connect").addEventListener("click",()=>{
  bridge.connect();void bridge.request({kind:"status"}).then(result=>{
    if(result.kind!=="status")throw Error("invalid_bridge_reply");connected=true;paused=result.paused;executionMode=result.mode;button("tasks").disabled=false;button("pause").disabled=false;button("pause").textContent=paused?"Продолжить":"Пауза";button("save-snapshot").disabled=!captured;button("report-stop").disabled=!stopped;bridgeStatus.textContent="Канал легенды открыт. Shield и vault недоступны.";
  }).catch(failure);
});
button("tasks").addEventListener("click",()=>void tasks().catch(failure));
button("stop-execution").addEventListener("click",()=>void chrome.runtime.sendMessage({kind:"execution_cancel"}).then(()=>{bridgeStatus.textContent="Исполнение останавливается. Если запрос мог уйти, проверьте вкладку и отметьте результат вручную. Автоматического повтора не будет.";}).catch(failure));
button("execution-status").addEventListener("click",()=>void chrome.runtime.sendMessage({kind:"execution_status"}).then(result=>{
  if(!result||typeof result!=="object"||!("code" in result))throw Error("invalid_bridge_reply");
  const code=String(result.code);bridgeStatus.textContent=code==="completed"?"Поиск выполнен и отмечен в ядре. Обновите задания.":code==="running"?"Расширение выполняет поиск. Не меняйте вкладку; её закрытие останавливает действие.":code==="idle"?"Исполнение ещё не запускалось в этом фоновом процессе.":"Исполнение остановлено. Проверьте вкладку и отметьте выполненное вручную. Повтор той же попытки запрещён.";
}).catch(failure));
button("pause").addEventListener("click",()=>void bridge.request({kind:"pause",paused:!paused}).then(()=>{paused=!paused;button("pause").textContent=paused?"Продолжить":"Пауза";bridgeStatus.textContent=paused?"Drift на паузе.":"Drift продолжен.";}).catch(failure));
button("report-stop").addEventListener("click",()=>{
  if(!stopped)return;
  button("report-stop").disabled=true;
  void bridge.request({kind:"safety_stop",...stopped}).then(()=>{
    paused=true;button("pause").textContent="Продолжить";
    document.querySelector<HTMLOListElement>("#tasks-list")!.replaceChildren();
    bridgeStatus.textContent="Drift на паузе. Остановка учтена в Mirror; адрес и текст страницы не передавались.";
  }).catch(e=>{button("report-stop").disabled=false;failure(e);});
});
button("save-snapshot").addEventListener("click",()=>{
  if(!captured)return;button("save-snapshot").disabled=true;
  void bridge.request({kind:"snapshot",snapshot:captured}).then(()=>{status.textContent="Снимок сохранён в зашифрованном Mirror. Результат смотрите в приложении.";}).catch(e=>{button("save-snapshot").disabled=false;failure(e);});
});
document.querySelector<HTMLButtonElement>("#capture")!.addEventListener("click", async () => {
  captured=undefined;button("save-snapshot").disabled=true;
  stopped=undefined;button("report-stop").hidden=true;button("report-stop").disabled=true;
  list.replaceChildren();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url?.startsWith("https://")) throw new Error("unsupported");
    const result = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      // Fixed extension code reads the page; strings from the page never become code.
      func: readMirrorPage,
    });
    const data = result[0]?.result as { signals: PageSignals; titles: string[] } | undefined;
    if (!data) throw new Error("unsupported");
    const state = pageState(data.signals);
    if (state !== "ready") {
      status.textContent = state === "challenge" ? "Остановлено: CAPTCHA. Пройдите проверку самостоятельно." : state === "login" ? "Остановлено: требуется ваш вход." : "Эта страница не поддерживается.";
      if(state==="challenge"||state==="login"){
        stopped={event_id:crypto.randomUUID().replaceAll("-",""),reason:state==="challenge"?"captcha":"login"};
        button("report-stop").hidden=false;button("report-stop").disabled=!connected;
      }
      return;
    }
    const titles = snapshotTitles(data.titles);
    for (const title of titles) {
      const item = document.createElement("li"); item.textContent = title; list.append(item);
    }
    if(titles.length){captured={kind:"youtube_feed",items:titles,captured_at:Math.floor(Date.now()/1000)};button("save-snapshot").disabled=!connected;}
    status.textContent = titles.length ? `Прочитано карточек: ${titles.length}. Нажмите «Сохранить в Mirror» для передачи ядру.` : "Карточки не найдены. Откройте главную YouTube.";
  } catch { status.textContent = "Снимок недоступен. Откройте поддерживаемую страницу и повторите."; }
});
