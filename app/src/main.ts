import { takeoutExample } from "./fixtures.js";
import {chatStatusLabel} from "./chat-status.js";
import {createHygienePanel,renderDeviceProbe,renderHygiene,deviceInventoryReady,type DeviceProbeStatus} from "./hygiene.js";
import {activityTransition,activityLabel,type ActivitySchedule} from "./activity.js";
import {sessionTimingLabel,type SessionTiming} from "./session.js";
import {bridgeInput,bridgeStatusLabel,type BridgeStatus} from "./bridges.js";
import {mirrorChart,sourceName,type Observation} from "./mirror.js";
import {renderPurgeGuide,renderPurgeBatches,type PurgeGuide,type PurgeBatchView} from "./purge.js";
declare global { interface Window { __TAURI__?: { core: { invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> } } } }
const $ = <T extends HTMLElement>(id: string): T => {
  const element=document.getElementById(id); if(!element)throw new Error("missing_element"); return element as T;
};
const value=(id:string)=>$<HTMLInputElement|HTMLTextAreaElement|HTMLSelectElement>(id).value;
const lines=(id:string)=>value(id).split("\n").map(s=>s.trim()).filter(Boolean);
let sessionEpoch=0;
let storageExists=false;
let unlocked=false;
let egressAvailable=false;
let displayedHash:string|undefined;
let paused=false;
let config:Config|undefined;
let persona:Persona={traits:[]};
let purgeItems:PurgeCandidate[]=[];
let preparedPurge:{batch:Batch;hash:string}|undefined;
let conversation="new";
let messages:Message[]=[];
let chatEpoch=0;
let chatReadOnly=false;
let activeRemoteReview:((cancelOnServer?:boolean)=>void)|undefined;
let activeRemoteJob:string|undefined;
let histories:{id:string;title:string;resumable:boolean}[]=[];
let storedSecrets:Secret[]=[];
let deviceProbe:DeviceProbeStatus|undefined;
interface Config {hard?:{device_secrets:boolean;defer_max_hours:number;background_tail?:boolean}}
interface Plan {activity?:ActivitySchedule|null}
let dayHash:string|undefined;
interface Secret {kind:string;value:string;local_only:boolean}
interface CredentialInfo {id:string;state:string}
interface Summary {records:number;skipped_files?:number;domains:Record<string,number>;titles:string[];searches:string[];prompt_samples:string[];activity_hours:Record<string,number>}
interface Trait {id:string;claim:string;evidence:string[];confirmed:boolean|null}
interface Persona {traits:Trait[]}
interface Plan {cover:string;days_per_stage:number;stages:{theme:string;bridge:string;actions:{service:string;text:string}[]}[]}
interface PlanReview {hash:string;plan:Plan;checks:{valid:boolean;positions:number[];coverage:number};approved:boolean}
interface Task {plan_hash:string;stage:number;day:number;action_index:number;service:string;text:string}
interface DayReview {hash:string;approved:boolean;day:{stage:number;day:number;actions:{service:string;text:string}[]}}
// Numeric summaries only; the chart never receives raw snapshot text.
interface Overview {profile:string;paused:boolean;has_import:boolean;confirmed_traits:number;has_plan:boolean;plan_approved:boolean;completed_days:number;metrics:{shadow_share:number|null;cover_ratio:number|null;challenge_rate:number|null;leak_blocks:number};observations:Observation[]}
interface StorageStatus {exists:boolean;unlocked:boolean;egress_available:boolean;path:string;overview:Overview|null}
interface Config {profile:string;drift:{mode:string;[key:string]:unknown};llm:{endpoint:string;model:string;embed_model:string;[key:string]:unknown};shield:{history_retention_days:number;min_trust:string;[key:string]:unknown};net:{transport:string;provider_host:string|null;provider_path:string|null;credential_ref:string|null;provider_model:string|null;max_request_cost_microusd:number|null};cover:{max_requests_per_day:number;max_spend_per_day_usd:number;[key:string]:unknown};[key:string]:unknown}
interface NetworkUsage {day:number;requests:number;reserved_microusd:number}
interface TrafficStatus {enabled:boolean;next_slot:number|null;jobs:{id:string;created_at:number;state:string;purpose?:string;code:string|null}[]}
interface PurgeCandidate {id:string;title:string;score:number}
interface Batch {service:string;record_ids:string[]}
interface Message {role:"user"|"assistant"|"system";content:string}
interface ChatReply {conversation:string;text:string;trust:string;local_reason?:string|null}
interface RemoteJobInfo {id:string;conversation:string;created_at:number;updated_at:number;state:string;code:string|null;trust:string}
interface RemoteJobView {info:RemoteJobInfo;reply:ChatReply|null}
interface RemoteReview {approval_id:string;hash:string;conversation:string;transcript:string;max_tokens:number;trust:string;expires_in_s:number}
type RemoteReviewResponse={status:"chat";reply:ChatReply}|{status:"review";review:RemoteReview;provider_host:string;provider_path:string;provider_model:string;cost_microusd:number};
const modelFileFields=[['model_path','chat-model-file','GGUF модели диалога'],['model_sha256','chat-model-sha','SHA-256 модели диалога'],['embed_path','embed-model-file','GGUF nomic-embed-text'],['embed_sha256','embed-model-sha','SHA-256 модели эмбеддингов']] as const;

const names:Record<string,string>={overview:"Обзор",shield:"Shield",drift:"Drift",audit:"Исследование",purge:"Purge",mirror:"Mirror",hygiene:"Гигиена",settings:"Настройки"};
document.querySelector("main")!.insertBefore(createHygienePanel(),$("notification"));
const hygieneNav=document.createElement("button");hygieneNav.dataset.view="hygiene";hygieneNav.textContent="Гигиена";document.querySelector('[data-view="settings"]')!.before(hygieneNav);
function show(view:string) {
  if(!Object.hasOwn(names,view))return;
  document.querySelectorAll<HTMLElement>("[data-panel]").forEach(p=>{p.hidden=p.dataset.panel!==view;});
  document.querySelectorAll<HTMLElement>("[data-view]").forEach(b=>{if(b.dataset.view===view)b.setAttribute("aria-current","page");else b.removeAttribute("aria-current");});
  $("breadcrumb").textContent=`Пространство / ${names[view]}`;window.scrollTo({top:0});
}
document.querySelectorAll<HTMLElement>("[data-view],[data-goto]").forEach(b=>b.addEventListener("click",()=>show(b.dataset.view??b.dataset.goto??"overview")));
document.querySelector(".brand")!.addEventListener("click",()=>show("overview"));
document.querySelectorAll<HTMLInputElement|HTMLTextAreaElement>("input,textarea").forEach(i=>{i.autocomplete="off";i.spellcheck=false;});
let noticeTimer:ReturnType<typeof setTimeout>;
function notify(message:string,error=false) {
  const n=$("notification");n.textContent=message;n.hidden=false;n.dataset.error=String(error);clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>{n.hidden=true;},10000);
}
async function invoke<T>(command:string,args?:Record<string,unknown>):Promise<T> {
  if(!window.__TAURI__)throw new Error("desktop_required");
  const epoch=sessionEpoch;const result=await window.__TAURI__.core.invoke<T>(command,args);
  if(command!=="clear_session"&&epoch!==sessionEpoch)throw new Error("session_changed");return result;
}
function friendly(error:unknown):string {
  const code=error instanceof Error?error.message:String(error);
  const map:Record<string,string>={
    desktop_required:"Для обработки данных запустите десктопное приложение: npm run desktop.",
    workspace_locked:"Сначала откройте пространство на странице «Обзор».",
    workspace_already_open:"Пространство уже открыто.",
    workspace_locked_or_busy:"Хранилище открыто другим процессом.",
    invalid_password:"Пароль неверен или зашифрованные данные повреждены.",
    vault_authentication_failed:"Пароль неверен или данные повреждены.",
    invalid_vault_key:"Пароль неверен или ключ хранилища недоступен.",
    os_secret_unavailable:"Хранилище ключей ОС недоступно. Разблокируйте его и повторите.",
    password_too_short:"Для этого профиля нужен пароль длиной не менее 12 байт.",
    shield_blocked:"Shield заблокировал результат: найден секрет, PII или некорректный плейсхолдер.",
    local_model_unavailable:"Локальная модель недоступна. Проверьте приватный канал и запущенный nw-llmd.",
    invalid_local_model_response:"Модель вернула некорректный ответ. Операция остановлена.",
    local_model_timeout:"Локальная модель не ответила вовремя.",
    invalid_import:"Неверная структура файла для выбранного формата.",
    import_too_large:"Файл или число записей превышает лимит импорта.",
    wal_snapshot_requires_backup:"SQLite-файл использует WAL. Создайте согласованный SQLite backup или выберите JSON-экспорт браузера.",
    import_required:"Сначала импортируйте экспорт в разделе «Исследование».",
    day_not_ready:"Следующий день откроется через 12 часов после начала предыдущего.",
    execution_paused:"Drift на паузе. Продолжите его кнопкой в верхней панели.",
    plan_approval_required:"Сначала подтвердите интересы, постройте и одобрите план.",
    mirror_observation_required:"Перед следующим этапом нужен свежий снимок Mirror, достигший позиции прошлого этапа.",
    authentication_failed:"Пароль неверен или зашифрованные данные повреждены.",
    key_derivation_failed:"Для strict нужен пароль длиной от 12 байт. Проверьте пароль.",
    store_locked:"Хранилище уже открыто другим процессом.",
    invalid_request:"Проверьте поля. Секреты — от 3 символов, интересы — по одному на строку.",
    invalid_workspace_data:"Данные не прошли проверку. Проверьте формат и показанные поля.",
    workspace_policy_error:"Настройка или действие не соответствует политике пространства.",
    confirmation_required:"Введите подтверждение удаления точно так, как показано.",
    conversation_limit:"Достигнут предел длины разговора. Начните новый разговор.",
    request_in_progress:"В этом разговоре уже выполняется запрос. Дождитесь результата или начните другой.",
    remote_job_failed:"Задание остановлено. Посмотрите его состояние в списке запросов; автоматического повтора нет.",
    async_remote_required:"Постоянный режим принимает задания с просмотром. Отправьте запрос через интерфейс очереди.",
    cancelled_by_user:"Запрос отменён. Если отправка уже началась, его результат остаётся неизвестным.",
    previous_session_ended:"Сессия прервалась. Исходный текст сохранён; для новой отправки нужен новый просмотр.",
    network_budget_exhausted:"Достигнут дневной лимит запросов или зарезервированных расходов. Отправка остановлена.",
    invalid_bridge_configuration:"Проверьте тип, адрес, отпечаток и параметры строк мостов. Исполняемые команды и произвольные параметры запрещены.",
    credential_pool_unavailable:"Нет доступного ключа провайдера для этого разговора.",
    remote_transport_unavailable:"Tor или провайдер недоступен. Запрос автоматически не повторяется. При необходимости заблокируйте и откройте пространство заново.",
    approval_required:"Нужно новое одобрение исходящего запроса: предыдущее истекло, отменено или уже использовано.",
    trust_policy_violation:"Этот маршрут L3 не соответствует выбранному минимальному уровню доверия.",
    model_files_required:"Укажите полные пути и SHA-256 обоих GGUF в настройках.",
    model_already_running:"Приватный канал модели уже используется.",
    model_start_failed:"Модель не запущена. Проверьте файлы, SHA-256 и наличие nw-llmd рядом с ядром.",
    invalid_conversation:"Разговор недоступен. Начните новый разговор.",
    session_changed:"Сессия изменилась. Предыдущая операция отменена."
    ,device_probe_required:"Проверка устройства не завершена полностью. Откройте «Гигиена». Локальная модель доступна."
    ,outside_activity_window:"Сейчас вне одобренного окна активности легенды. Посмотрите время UTC в плане; действия автоматически не догоняются."
    ,invalid_activity_window:"Укажите целые часы UTC от 0 до 23 и длительность окна от 1 до 12 часов."
  };
  return map[code]??`Операция остановлена. Проверьте данные, пароль и состояние локальной модели.${/^[a-z0-9_]+$/.test(code)?" Код: "+code:""}`;
}
async function busy(button:HTMLButtonElement,work:()=>Promise<void>){
  button.disabled=true;button.setAttribute("aria-busy","true");
  try{await work();}catch(e){notify(friendly(e),true);}finally{button.disabled=false;button.removeAttribute("aria-busy");if(button.id==="send-chat"||button.id==="send-remote")updateChatButtons();}
}
function on(id:string,work:()=>Promise<void>){$(id).addEventListener("click",e=>void busy(e.currentTarget as HTMLButtonElement,work));}
function secrets():Secret[]{return lines("secrets").map(value=>storedSecrets.find(s=>s.value===value)??{kind:"SECRET",value,local_only:false});}
function renderOverview(o:Overview){
  paused=o.paused;$("pause").textContent=paused?"▷ Продолжить Drift":"Ⅱ Пауза Drift";
  $("overview-state").textContent=`${o.profile} · подтверждённых черт: ${o.confirmed_traits} · завершено дней: ${o.completed_days} · ${o.plan_approved?"план одобрен":o.has_plan?"план ждёт одобрения":"плана ещё нет"}`;
  $("shadow-share").textContent=o.metrics.shadow_share===null?"—":`${Math.round(o.metrics.shadow_share*100)}%`;
  $("leak-blocks").textContent=String(o.metrics.leak_blocks);
  $("cover-ratio").textContent=o.metrics.cover_ratio==null?"—":`${o.metrics.cover_ratio.toLocaleString("ru",{maximumFractionDigits:2})}×`;
  $("challenge-rate").textContent=o.metrics.challenge_rate==null?"—":`${Math.round(o.metrics.challenge_rate*100)}%`;
  $("feed-position").textContent=o.observations.length?o.observations.at(-1)!.position.toFixed(2):"—";
  const out=$("observations");out.replaceChildren();
  if(!o.observations.length){const p=document.createElement("p");p.className="hint";p.textContent="Пока нет наблюдений.";out.append(p);return;}
  out.append(mirrorChart(o.observations));
  const table=document.createElement("table");const heading=document.createElement("tr");
  for(const text of ["Время","Источник","Позиция"]){const th=document.createElement("th");th.textContent=text;heading.append(th);}table.append(heading);
  for(const observation of [...o.observations].reverse()){
    const row=document.createElement("tr");
    for(const text of [new Date(observation.captured_at*1000).toLocaleString(),sourceName(observation.kind),observation.position.toFixed(3)]){const td=document.createElement("td");td.textContent=text;row.append(td);}table.append(row);
  }
  out.append(table);
}
function renderStorage(s:StorageStatus){
  storageExists=s.exists;unlocked=s.unlocked;egressAvailable=s.egress_available;updateChatButtons();
  $("unlock-panel").hidden=s.unlocked;$("workspace-summary").hidden=!s.unlocked;
  $("unlock-title").textContent=s.exists?"Откройте личное пространство":"Создайте личное пространство";
  $("create-options").hidden=s.exists;
  $("open-workspace").textContent=s.exists?"Разблокировать →":"Создать пространство →";
  $("storage-badge").textContent=s.unlocked?"Хранилище открыто":"Хранилище заблокировано";
  $("storage-location").textContent=s.path;
  $("storage-description").textContent=s.unlocked?"Изменения сохраняются зашифрованными на этом компьютере.":"Отдельные ключи доменов. SQLCipher и XChaCha20-Poly1305.";
  if(s.overview)renderOverview(s.overview);
  document.querySelector<HTMLElement>(".offline-badge")!.textContent=s.unlocked&&remoteAllowed()?"● L0 / Tor · L3":"● L0 · локальная модель";
}
async function refreshOverview(){renderStorage(await invoke<StorageStatus>("workspace_status"));}
function renderSummary(result:Summary){
  const out=$("audit-result");out.replaceChildren();
  const h=document.createElement("h2");h.textContent=`Записей: ${result.records} · доменов: ${Object.keys(result.domains).length}`;
  const p=document.createElement("p");p.className="hint";p.textContent="Заголовки — недоверенные данные. Локальный анализ запускается вашей кнопкой."+(result.skipped_files?" Пропущено файлов вне поддерживаемых форматов: "+result.skipped_files+".":"");
  const list=document.createElement("ol");list.className="checklist";
  for(const title of [...result.searches,...result.titles,...result.prompt_samples].slice(0,20)){const li=document.createElement("li");li.textContent=title;list.append(li);}
  out.append(h,p,list);
}
function renderPersona(next:Persona){
  persona=next;const out=$("persona-traits");out.replaceChildren();$("persona-panel").hidden=!next.traits.length;
  for(const trait of next.traits){
    const row=document.createElement("div");row.className="choice";const label=document.createElement("label");const check=document.createElement("input");check.type="checkbox";check.checked=trait.confirmed===true;check.dataset.trait=trait.id;
    const text=document.createElement("span");text.textContent=trait.claim;label.append(check,text);row.append(label);
    for(const evidence of trait.evidence){const p=document.createElement("p");p.className="hint";p.textContent=evidence;row.append(p);}out.append(row);
  }
  $<HTMLTextAreaElement>("interests").value=next.traits.filter(t=>t.confirmed===true).map(t=>t.claim).join("\n");
}
function renderPlan(review:PlanReview|null){
  displayedHash=review?.hash;$("plan-review").hidden=!review;$("daily").hidden=!review?.approved;
  if(!review)return;
  const stages=$("plan-stages");stages.replaceChildren();
  review.plan.stages.forEach((stage,index)=>{
    const timing=document.createElement("p");timing.className="hint";timing.textContent=activityLabel(review.plan.activity,index);
    const row=document.createElement("div");row.className="stage";const h=document.createElement("h3");h.textContent=`${index+1}. ${stage.theme}`;
    const p=document.createElement("p");p.className="hint";p.textContent=`Мост: ${stage.bridge} · ${review.plan.days_per_stage} дней`;
    const list=document.createElement("ol");for(const action of stage.actions){const li=document.createElement("li");li.textContent=`${action.service}: ${action.text}`;list.append(li);}row.append(h,p,timing,list);stages.append(row);
  });
  $("plan-hash").textContent=`${review.approved?"Одобрен":"Ожидает одобрения"} · ${review.hash} · покрытие оси: ${Math.round(review.checks.coverage*100)}%`;
  $("approve-plan").hidden=review.approved;
}
async function hydrate(){
  const [c,s,summary,p,plan]=await Promise.all([invoke<Config>("load_config"),invoke<Secret[]>("load_secrets"),invoke<Summary|null>("load_summary"),invoke<Persona>("load_persona"),invoke<PlanReview|null>("load_plan")]);
  config=c;
  const bridgeStatus=await invoke<BridgeStatus>("load_bridge_status");$("bridge-status").textContent=bridgeStatusLabel(bridgeStatus);$<HTMLSelectElement>("bridge-transport").value=bridgeStatus.transport??"disabled";
  const windows=plan?.plan.activity?.windows;
  $<HTMLInputElement>("activity-start").value=String(windows?.[0]?.start_hour_utc??12);
  $<HTMLInputElement>("activity-target").value=String(windows?.at(-1)?.start_hour_utc??12);
  $<HTMLInputElement>("activity-width").value=String(windows?.[0]?.width_hours??6);
  deviceProbe=await invoke<DeviceProbeStatus>("load_device_probe");renderDeviceProbe($("device-probe-status"),deviceProbe);
  renderHygiene($("hygiene-checks"),deviceProbe);
  driftMode.value=c.drift.mode;
  storedSecrets=s;
  $<HTMLInputElement>("model-socket").value=c.llm.endpoint;$<HTMLInputElement>("settings-socket").value=c.llm.endpoint;
  $<HTMLInputElement>("settings-model").value=c.llm.model;$<HTMLInputElement>("settings-embed").value=c.llm.embed_model;
  $<HTMLInputElement>("history-days").value=String(c.shield.history_retention_days);
  for(const [field,id]of modelFileFields)$<HTMLInputElement>(id).value=typeof c.llm[field]==="string"?c.llm[field] as string:"";
  $<HTMLSelectElement>("net-transport").value=c.net.transport;
  $<HTMLInputElement>("net-host").value=c.net.provider_host??"";$<HTMLInputElement>("net-path").value=c.net.provider_path??"/v1/chat/completions";$<HTMLInputElement>("net-model").value=c.net.provider_model??"";
  $<HTMLInputElement>("net-cost").value=c.net.max_request_cost_microusd?String(c.net.max_request_cost_microusd/1_000_000):"";
  $<HTMLInputElement>("net-daily-count").value=String(c.cover.max_requests_per_day);$<HTMLInputElement>("net-daily-budget").value=String(c.cover.max_spend_per_day_usd);
  $<HTMLInputElement>("traffic-enabled").checked=c.cover.enabled===true;$<HTMLInputElement>("traffic-interval").value=String(c.cover.mean_interval_s);
  $<HTMLInputElement>("background-tail").checked=c.hard?.background_tail===true;
  $("session-timing").textContent=sessionTimingLabel(await invoke<SessionTiming>("session_timing"));
  $<HTMLSelectElement>("traffic-mode").value=String(c.cover.mode);
  renderTraffic(await invoke<TrafficStatus>("traffic_status"));
  $("send-remote").toggleAttribute("disabled",!remoteAllowed());renderNetworkUsage(await invoke<NetworkUsage>("load_network_usage"));
  document.querySelector<HTMLElement>(".offline-badge")!.textContent=remoteAllowed()?"● L0 / Tor · L3":"● L0 · локальная модель";
  $<HTMLTextAreaElement>("secrets").value=s.map(s=>s.value).join("\n");
  if(summary)renderSummary(summary);else $("audit-result").replaceChildren();
  renderPersona(p);renderPlan(plan);
  await refreshHistory();
  await refreshRemoteJobs();
  await refreshPurgeBatches();
  renderProviderKeys(await invoke<CredentialInfo[]>("load_provider_keys"));
  if(plan?.approved){try{renderDay(await invoke<DayReview|null>("load_day"));}catch{$("day-variants").textContent="План завершён или ждёт нового дня.";}}
}
function renderProviderKeys(keys:CredentialInfo[]){
  const list=$("provider-keys");list.replaceChildren();
  for(const key of keys){
    const item=document.createElement("li"),label=document.createElement("span"),remove=document.createElement("button");
    label.textContent=key.id.slice(0,12)+"… · "+(key.state==="available"?"доступен":key.state==="leased"?"закреплён за разговором":"выведен из пула");
    remove.className="quiet danger";remove.textContent="Удалить с компьютера";
    remove.addEventListener("click",()=>{remove.disabled=true;void invoke<CredentialInfo[]>("retire_provider_key",{id:key.id}).then(renderProviderKeys).catch(e=>{remove.disabled=false;notify(friendly(e),true);});});
    item.append(label,remove);list.append(item);
  }
  if(!keys.length)list.textContent="Ключей нет. Локальная модель работает без них.";
}
on("open-workspace",async()=>{
  const password=value("workspace-password");$<HTMLInputElement>("workspace-password").value="";
  renderStorage(await invoke<StorageStatus>("open_workspace",{password,create:!storageExists,profile:value("workspace-profile")}));
  await hydrate();notify("Пространство открыто. Изменения сохраняются зашифрованными.");
});
$("sample").addEventListener("click",()=>{
  $<HTMLTextAreaElement>("prompt").value="Я Синтетик Тестов из Синтеграда. Напиши на demo@example.test про садоводство.";
  $<HTMLTextAreaElement>("secrets").value="Синтетик Тестов\nСинтеграда";
});
on("preview",async()=>{
  $("preview-result").textContent="Проверка…";$("preview-info").textContent="Проверка ещё не завершена.";
  try{const result=await invoke<{minimized:string;sensitivity:string;replacements:number}>("preview_shield",{input:{text:value("prompt"),secrets:secrets()}});
    $("preview-result").textContent=result.minimized;$("preview-info").textContent=`Замен: ${result.replacements} · leakcheck пройден · ${result.sensitivity==="local_only"?"только локально":"remote_ok после предварительной проверки"}`;
  }catch(e){$("preview-result").textContent="Результат заблокирован или недоступен.";$("preview-info").textContent="Успешной проверки нет.";throw e;}
});
on("save-secrets",async()=>{await invoke("save_secrets",{secrets:secrets()});resetChat();notify("Список секретов сохранён. Новый список применяется к новым разговорам.");});
function remoteAllowed(){return unlocked&&egressAvailable&&config?.net.transport==="tor"&&config.shield.min_trust==="L3"&&(config.hard?.device_secrets===false||deviceInventoryReady(deviceProbe));}
function updateChatButtons(){
  $<HTMLButtonElement>("send-chat").disabled=!unlocked||chatSending||chatReadOnly;
  $<HTMLButtonElement>("send-remote").disabled=chatSending||chatReadOnly||!remoteAllowed();
}
function resetChat(cancelOnServer=true){activeRemoteReview?.(cancelOnServer);if(activeRemoteJob){if(cancelOnServer)void invoke("cancel_remote_job",{id:activeRemoteJob}).catch(()=>{});activeRemoteJob=undefined;}chatEpoch++;chatSending=false;conversation="new";messages=[];chatReadOnly=false;$("chat-messages").replaceChildren();updateChatButtons();$("chat-history-info").textContent="Новый отдельный разговор.";}
async function confirmRemote(response:Extract<RemoteReviewResponse,{status:"review"}>,original:Message[]):Promise<boolean>{
  const {review}=response;
  const dialog=document.createElement("dialog"),heading=document.createElement("h2"),details=document.createElement("p"),privacy=document.createElement("p"),body=document.createElement("pre"),approve=document.createElement("button"),cancel=document.createElement("button");
  dialog.className="remote-review";heading.textContent="Одобрение исходящего запроса";heading.id="remote-review-title";dialog.setAttribute("aria-labelledby",heading.id);
  details.textContent=`${response.provider_host}${response.provider_path} · модель ${response.provider_model} · ${review.trust} · максимум ${review.max_tokens} токенов · резерв $${(response.cost_microusd/1_000_000).toFixed(6)}. Отправится показанный текст; одобрение действует ${review.expires_in_s} секунд.`;
  privacy.id="remote-review-privacy";privacy.className="hint";privacy.textContent="Провайдер может узнать профиль по редким фактам и связать запросы с аккаунтом или API-ключом. Для личного контекста отмените отправку и выберите «Спросить локально».";dialog.setAttribute("aria-describedby",privacy.id);
  const readable=(history:Message[])=>history.map(message=>`${{user:"Вы",assistant:"Ответ",system:"Инструкция"}[message.role]}:\n${message.content}`).join("\n\n");
  const comparison=document.createElement("div"),before=document.createElement("pre"),beforeTitle=document.createElement("h3"),afterTitle=document.createElement("h3"),beforeColumn=document.createElement("div"),afterColumn=document.createElement("div");comparison.className="review-comparison";beforeTitle.textContent="Исходная история";afterTitle.textContent="Уйдёт провайдеру";
  before.textContent=readable(original);body.textContent=readable(JSON.parse(review.transcript) as Message[]);beforeColumn.append(beforeTitle,before);afterColumn.append(afterTitle,body);comparison.append(beforeColumn,afterColumn);
  approve.textContent="Одобрить и отправить";approve.className="primary";cancel.textContent="Отменить";cancel.className="secondary";
  dialog.append(heading,details,privacy,comparison,cancel,approve);document.body.append(dialog);
  return new Promise(resolve=>{
    let finished=false;
    const finish=(accepted:boolean,cancelOnServer=true)=>{if(finished)return;finished=true;clearTimeout(timer);activeRemoteReview=undefined;dialog.close();before.textContent="";body.textContent="";dialog.remove();if(!accepted&&cancelOnServer)void invoke("cancel_remote",{approvalId:review.approval_id}).catch(()=>{});resolve(accepted);};
    const timer=setTimeout(()=>finish(false),review.expires_in_s*1000);
    activeRemoteReview=(cancelOnServer=true)=>finish(false,cancelOnServer);approve.addEventListener("click",()=>finish(true));cancel.addEventListener("click",()=>finish(false));dialog.addEventListener("cancel",event=>{event.preventDefault();finish(false);});
    dialog.showModal();cancel.focus();
  });
}
function renderChat(){
  const out=$("chat-messages");out.replaceChildren();
  for(const message of messages){const p=document.createElement("div");p.className="chat-message";p.dataset.role=message.role;p.textContent=message.content;out.append(p);}
}
$("new-chat").addEventListener("click",()=>resetChat());
let chatSending=false;
async function sendChat(remote:boolean){
  if(chatSending||chatReadOnly)throw new Error("request_in_progress");
  const epoch=chatEpoch;
  const startedSession=sessionEpoch;
  const text=value("prompt").trim();if(!text)throw new Error("invalid_request");
  chatSending=true;$<HTMLButtonElement>("send-chat").disabled=true;$<HTMLButtonElement>("send-remote").disabled=true;
  try{
  const next:Message[]=[...messages,{role:"user",content:text}];
  let reply:ChatReply;
  if(remote){
    const response=await invoke<RemoteReviewResponse>("review_remote",{conversation,messages:next});
    if(epoch!==chatEpoch){if(response.status==="review")await invoke("cancel_remote",{approvalId:response.review.approval_id});throw new Error("session_changed");}
    if(response.status==="chat")reply=response.reply;
    else{
      if(!await confirmRemote(response,next))return;
      let job=await invoke<RemoteJobView>("start_remote_job",{approvalId:response.review.approval_id,hash:response.review.hash});
      if(epoch!==chatEpoch){await invoke("cancel_remote_job",{id:job.info.id});throw new Error("session_changed");}
      activeRemoteJob=job.info.id;
      try{
        while(job.info.state==="queued"||job.info.state==="sending"){
          if(epoch!==chatEpoch)throw new Error("session_changed");
          $("chat-history-info").textContent=job.info.state==="queued"?(config?.cover.enabled&&config.cover.mode==="constant"?"Запрос сохранён. Ожидает ближайшего слота с доступным бюджетом.":"Запрос сохранён. Ожидает подготовки транспорта и отправки."):"Отправка началась. Неопределённый результат не будет повторён автоматически.";
          await new Promise(resolve=>setTimeout(resolve,800));job=await invoke<RemoteJobView>("load_remote_job",{id:job.info.id});
        }
        if(!job.reply)throw new Error(job.info.code??"remote_job_failed");reply=job.reply;
      }finally{if(activeRemoteJob===job.info.id)activeRemoteJob=undefined;if(startedSession===sessionEpoch&&epoch===chatEpoch&&unlocked)await refreshRemoteJobs();}
    }
  }else reply=await invoke<ChatReply>("chat",{conversation,messages:next});
  if(epoch!==chatEpoch)throw new Error("session_changed");
  conversation=reply.conversation;messages=[...next,{role:"assistant",content:reply.text}];renderChat();if(value("prompt").trim()===text)$<HTMLTextAreaElement>("prompt").value="";await refreshOverview();await refreshHistory();
  $("chat-history-info").textContent=chatStatusLabel(reply);
  document.querySelector<HTMLElement>(".offline-badge")!.textContent=reply.trust==="L0"?"● L0 · локальная модель":"● L3 · Tor / ключ";
  renderNetworkUsage(await invoke<NetworkUsage>("load_network_usage"));
  }finally{if(epoch===chatEpoch)chatSending=false;updateChatButtons();}
}
on("send-chat",()=>sendChat(false));
async function loadSummary(content:string,format:string,encoding?:string){renderSummary(await invoke<Summary>("audit_import",{content,format,encoding}));await refreshOverview();notify("Импорт обработан и сохранён зашифрованным.");}
on("import-sample",async()=>loadSummary(takeoutExample,"takeout"));
$("import-file").addEventListener("change",async()=>{
  const input=$<HTMLInputElement>("import-file"),file=input.files?.[0];if(!file)return;
  try{
    if(file.size>8*1024*1024)throw new Error("import_too_large");
    const data=new Uint8Array(await file.arrayBuffer());
      const chunks:string[]=[];
      for(let i=0;i<data.length;i+=32768)chunks.push(String.fromCharCode(...data.subarray(i,i+32768)));
      await loadSummary(btoa(chunks.join("")),value("import-format"),"base64");
  }catch(e){notify(friendly(e),true);}finally{input.value="";}
});
on("research-persona",async()=>{renderPersona(await invoke<Persona>("research_persona"));notify("Исследование готово. Проверьте доказательства каждой черты.");});
on("confirm-persona",async()=>{
  const choices=Array.from(document.querySelectorAll<HTMLInputElement>("[data-trait]")).map(c=>[c.dataset.trait,c.checked]);
  renderPersona(await invoke<Persona>("confirm_traits",{choices}));await refreshOverview();notify("Подтверждённые черты сохранены.");
});
const activityControls=document.createElement("div"),activityTitle=document.createElement("h2"),activityHint=document.createElement("p");
activityTitle.textContent="Часы активности легенды";activityHint.className="hint";activityHint.textContent="Укажите часы UTC для исходного образа и цели. Постепенное расписание будет показано в плане перед одобрением. Существующий план меняется только после нового построения и одобрения.";
activityControls.append(activityTitle,activityHint);
for(const [id,title,initial,min,max]of [["activity-start","Начало исходного окна, час UTC",12,0,23],["activity-target","Начало целевого окна, час UTC",12,0,23],["activity-width","Длительность окна, часов",6,1,12]]as const){const label=document.createElement("label"),input=document.createElement("input");label.htmlFor=id;label.textContent=title;input.id=id;input.type="number";input.min=String(min);input.max=String(max);input.step="1";input.value=String(initial);activityControls.append(label,input);}
$("generate-plan").before(activityControls);
on("generate-plan",async()=>{
  const activity=activityTransition($<HTMLInputElement>("activity-start").valueAsNumber,$<HTMLInputElement>("activity-target").valueAsNumber,$<HTMLInputElement>("activity-width").valueAsNumber);
  const review=await invoke<PlanReview>("generate_plan",{input:{confirmed_interests:lines("interests"),cover:value("cover"),sensitive_consent:false,activity},socket:value("model-socket"),secrets:secrets()});
  renderPlan(review);await refreshOverview();
});
async function refreshTasks(){
  const tasks=await invoke<Task[]>("daily_tasks");const list=$("daily-tasks");list.replaceChildren();
  if(!tasks.length){const p=document.createElement("p");p.className="hint";p.textContent="План завершён.";list.append(p);}
  for(const task of tasks){
    const row=document.createElement("div");row.className="task";
    const label=document.createElement("span");label.textContent=task.text;const service=document.createElement("small");service.textContent=`${task.service} · ${task.stage}.${task.day}`;
    const button=document.createElement("button");button.className="secondary";button.textContent="Выполнено";
    button.addEventListener("click",()=>void busy(button,async()=>{await invoke("complete_task",{task});row.remove();await refreshOverview();if(!list.children.length)notify("День завершён. Следующий откроется не раньше чем через 12 часов.");}));
    row.append(label,service,button);list.append(row);
  }
  $("daily").hidden=false;
}
on("approve-plan",async()=>{if(!displayedHash)throw new Error("invalid_request");await invoke("approve_plan",{hash:displayedHash});$("approve-plan").hidden=true;$("daily").hidden=false;renderDay(null);await refreshOverview();notify("План одобрен. Подготовьте формулировки на первый день.");});
on("refresh-tasks",refreshTasks);
on("pause",async()=>{await invoke("pause",{paused:!paused});await refreshOverview();notify(paused?"Drift приостановлен.":"Drift продолжен.");});
on("prepare-template",async()=>{$("purge-template").textContent=await invoke<string>("purge_template");});
on("rank-purge",async()=>{
  preparedPurge=undefined;$("approve-purge").hidden=true;purgeItems=await invoke<PurgeCandidate[]>("purge_candidates");
  const out=$("purge-candidates");out.replaceChildren();$("purge-review").hidden=!purgeItems.length;
  for(const item of purgeItems){
    const row=document.createElement("div");row.className="choice";const label=document.createElement("label");const check=document.createElement("input");check.type="checkbox";check.dataset.purge=item.id;const text=document.createElement("span");text.textContent=`${item.title} · сила ${item.score.toFixed(2)}`;label.append(check,text);row.append(label);out.append(row);
    check.addEventListener("change",()=>{preparedPurge=undefined;$("approve-purge").hidden=true;$("purge-batch").textContent="Выбор изменён. Просмотрите партию заново.";});
  }
  if(!purgeItems.length)out.textContent="В этой выборке нет сильных сигналов для удаления.";
});
$("purge-service").addEventListener("change",()=>{preparedPurge=undefined;$("approve-purge").hidden=true;});
on("prepare-purge",async()=>{
  const ids=Array.from(document.querySelectorAll<HTMLInputElement>("[data-purge]:checked")).map(c=>c.dataset.purge!);
  const batch:Batch={service:value("purge-service"),record_ids:ids};const hash=await invoke<string>("purge_hash",{batch});
  preparedPurge={batch,hash};
  $("purge-batch").textContent=`Сервис: ${batch.service}\n${purgeItems.filter(i=>ids.includes(i.id)).map(i=>i.title).join("\n")}\n\nХеш: ${hash}`;$("approve-purge").hidden=false;
});
on("approve-purge",async()=>{if(!preparedPurge)throw new Error("invalid_request");await invoke("approve_purge",preparedPurge);$("approve-purge").hidden=true;await refreshPurgeBatches();notify("Партия одобрена и сохранена. Удалите выбранные записи вручную в указанном сервисе.");});
on("save-snapshot",async()=>{await invoke("save_snapshot",{kind:value("snapshot-kind"),items:lines("snapshot-items")});$<HTMLTextAreaElement>("snapshot-items").value="";await refreshOverview();notify("Снимок измерен и сохранён зашифрованным.");});
on("record-account",async()=>{await invoke("account_activity",{count:Number(value("account-count"))});await refreshOverview();});
async function saveSettings(){
  if(!config)throw new Error("workspace_locked");
  const next:Config={...config,llm:{...config.llm,endpoint:value("settings-socket"),model:value("settings-model"),embed_model:value("settings-embed")},shield:{...config.shield,history_retention_days:Number(value("history-days"))}};
  next.drift={...config.drift,mode:driftMode.value};
  for(const [field,id]of modelFileFields)next.llm[field]=value(id).trim()||null;
  const transport=value("net-transport");
  next.net={transport,provider_host:value("net-host").trim()||null,provider_path:value("net-path").trim()||null,provider_model:value("net-model").trim()||null,credential_ref:transport==="local"?null:"keyring:pool",max_request_cost_microusd:value("net-cost").trim()?Math.ceil(Number(value("net-cost"))*1_000_000):null};
  next.cover={...config.cover,mode:value("traffic-mode"),enabled:$<HTMLInputElement>("traffic-enabled").checked,mean_interval_s:Number(value("traffic-interval")),max_requests_per_day:Number(value("net-daily-count")),max_spend_per_day_usd:Number(value("net-daily-budget"))};
  next.hard={device_secrets:config.hard?.device_secrets??true,defer_max_hours:config.hard?.defer_max_hours??0,background_tail:$<HTMLInputElement>("background-tail").checked};
  await invoke("save_config",{config:next});config=next;$<HTMLInputElement>("model-socket").value=next.llm.endpoint;resetChat();notify("Настройки сохранены.");
}
on("save-settings",saveSettings);
function clearSensitiveUi(){
  $("bridge-status").textContent="Пространство заблокировано.";$<HTMLTextAreaElement>("bridge-lines").value="";
  $("session-timing").textContent=sessionTimingLabel({phase:"locked",first_send_in_s:0,tail_remaining_s:null});
  deviceProbe=undefined;renderDeviceProbe($("device-probe-status"),undefined);
  renderHygiene($("hygiene-checks"),undefined);
  config=undefined;persona={traits:[]};storedSecrets=[];histories=[];historySelect.replaceChildren();dayHash=undefined;displayedHash=undefined;purgeItems=[];preparedPurge=undefined;resetChat(false);paused=false;unlocked=false;
  document.querySelectorAll<HTMLInputElement|HTMLTextAreaElement>("input,textarea").forEach(i=>{i.value="";});
  for(const id of ["audit-result","plan-stages","daily-tasks","persona-traits","purge-candidates","purge-batch","purge-results","observations","provider-keys","remote-jobs"])$(id).replaceChildren();
  $("network-usage").textContent="Пространство заблокировано.";$("traffic-status").replaceChildren();$<HTMLButtonElement>("send-remote").disabled=true;
  for(const id of ["plan-review","daily","persona-panel","purge-review"])$(id).hidden=true;
  for(const id of ["shadow-share","feed-position","leak-blocks","cover-ratio","challenge-rate"])$(id).textContent="—";
  $("preview-result").textContent="Ожидает вашего текста";$("preview-info").textContent="Пространство заблокировано.";
  renderDay(null);
}
on("clear-session",async()=>{sessionEpoch++;await invoke("clear_session");clearSensitiveUi();await refreshOverview();show("overview");notify("Пространство заблокировано. Зашифрованные данные сохранены.");});
on("run-device-probe",async()=>{
  deviceProbe=await invoke<DeviceProbeStatus>("run_device_probe");renderDeviceProbe($("device-probe-status"),deviceProbe);
  renderHygiene($("hygiene-checks"),deviceProbe);
  storedSecrets=await invoke<Secret[]>("load_secrets");$<HTMLTextAreaElement>("secrets").value=storedSecrets.map(s=>s.value).join("\n");
  updateChatButtons();notify(deviceInventoryReady(deviceProbe)?"Источники устройства проверены; список секретов обновлён.":"Результат сохранён. Проверьте список недоступных источников.");
});
on("erase-data",async()=>{
  const confirmation=value("erase-confirmation"),domain=value("erase-domain");$<HTMLInputElement>("erase-confirmation").value="";
  if(domain==="all"){await invoke("destroy_data",{confirmation});sessionEpoch++;clearSensitiveUi();await refreshOverview();show("overview");}
  else {await invoke("shred_domain",{domain,confirmation});clearSensitiveUi();await refreshOverview();await hydrate();}
  notify("Выбранные ключи и данные уничтожены.");
});
const dayControls=document.createElement("div");
const historyControls=document.createElement("div");historyControls.className="button-row";
const historySelect=document.createElement("select");historySelect.id="chat-history";historySelect.setAttribute("aria-label","Сохранённые разговоры");
const openHistory=document.createElement("button");openHistory.id="open-history";openHistory.className="secondary";openHistory.textContent="Открыть разговор";
const historyInfo=document.createElement("p");historyInfo.id="chat-history-info";historyInfo.className="hint";
historyControls.append(historySelect,openHistory);$("chat-messages").before(historyControls,historyInfo);
async function refreshHistory(){
  histories=await invoke<typeof histories>("list_conversations");historySelect.replaceChildren();
  for(const history of histories){const option=document.createElement("option");option.value=history.id;option.textContent=history.title;historySelect.append(option);}
  openHistory.disabled=!histories.length;
}
on("open-history",async()=>{
  const id=historySelect.value,history=histories.find(h=>h.id===id);if(!history)throw new Error("invalid_request");const epoch=++chatEpoch;
  const stored=await invoke<Message[]>("load_history",{conversation:id});if(epoch!==chatEpoch)throw new Error("session_changed");
  activeRemoteReview?.();conversation=id;messages=stored;chatReadOnly=!history.resumable;renderChat();updateChatButtons();historyInfo.textContent=history.resumable?"Контекст и плейсхолдеры восстановятся при следующем вопросе.":"Vault этого разговора удалён. История доступна для чтения; начните новый разговор.";
});
for(const [id,label]of [["chrome_sqlite","Chrome / Edge — SQLite backup"],["firefox_sqlite","Firefox — places.sqlite backup"],["safari_sqlite","Safari — History.db backup"]]){const option=document.createElement("option");option.value=id!;option.textContent=label!;$("import-format").append(option);}
$<HTMLInputElement>("import-file").accept=".json,.html,.htm,.zip,.sqlite,.db,application/octet-stream";
const generateDay=document.createElement("button");generateDay.id="generate-day";generateDay.className="secondary";generateDay.textContent="Подготовить формулировки дня";
const variants=document.createElement("div");variants.id="day-variants";
const dayHashLabel=document.createElement("p");dayHashLabel.id="day-hash";dayHashLabel.className="hint mono";
const approveDay=document.createElement("button");approveDay.id="approve-day";approveDay.className="primary";approveDay.textContent="Одобряю действия этого дня";approveDay.hidden=true;
dayControls.append(generateDay,variants,dayHashLabel,approveDay);$("daily-tasks").before(dayControls);
function renderDay(review:DayReview|null){
  dayHash=review?.hash;variants.replaceChildren();dayHashLabel.textContent=review?review.hash:"Сначала подготовьте и одобрите формулировки на сегодня.";approveDay.hidden=!review||review.approved;
  if(review){const h=document.createElement("h3");h.textContent=`Этап ${review.day.stage+1}, день ${review.day.day+1}`;variants.append(h);const list=document.createElement("ol");list.className="checklist";for(const a of review.day.actions){const li=document.createElement("li");li.textContent=`${a.service}: ${a.text}`;list.append(li);}variants.append(list);}
}
on("generate-day",async()=>{renderDay(await invoke<DayReview>("generate_day"));});
on("approve-day",async()=>{if(!dayHash)throw new Error("invalid_request");await invoke("approve_day",{hash:dayHash});approveDay.hidden=true;await refreshTasks();await refreshOverview();});
const credentialPanel=document.createElement("div");credentialPanel.className="surface";
const remoteSend=document.createElement("button");remoteSend.id="send-remote";remoteSend.className="secondary";remoteSend.textContent="Спросить через Tor · L3";remoteSend.disabled=true;$("send-chat").after(remoteSend);on("send-remote",()=>sendChat(true));
const jobsPanel=document.createElement("section"),jobsHeading=document.createElement("h2"),jobsHint=document.createElement("p"),jobsList=document.createElement("div"),jobsRefresh=document.createElement("button");
jobsPanel.className="surface";jobsHeading.textContent="Запросы к провайдеру";jobsHint.className="hint";jobsHint.textContent="Состояния сохраняются зашифрованными. Отмена после начала отправки не отзывает уже отправленные байты. Исходный текст можно вернуть в новый разговор; повтор потребует нового просмотра.";
jobsList.id="remote-jobs";jobsRefresh.className="secondary";jobsRefresh.textContent="Обновить список";jobsRefresh.addEventListener("click",()=>void busy(jobsRefresh,refreshRemoteJobs));jobsPanel.append(jobsHeading,jobsHint,jobsList,jobsRefresh);document.querySelector('[data-panel="shield"]')!.append(jobsPanel);
async function refreshRemoteJobs(){
  const list=$("remote-jobs");const jobs=await invoke<RemoteJobInfo[]>("load_remote_jobs");list.replaceChildren();
  if(!jobs.length){list.textContent="Удалённых заданий пока нет.";return;}
  for(const job of jobs.slice().reverse()){
    const row=document.createElement("div"),label=document.createElement("p"),restore=document.createElement("button"),actions=document.createElement("div");row.className="job-row";actions.className="button-row";
    label.textContent=`${new Date(job.created_at*1000).toLocaleString()} · ${{queued:"ожидание",sending:"отправка",done:"ответ получен",uncertain:"результат неизвестен, повтор запрещён",blocked:"остановлено",cancelled:"отменено",expired:"история удалена"}[job.state]??job.state} · ${job.trust}${job.code&&job.state!=="cancelled"?" · "+friendly(job.code):""}`;
    restore.className="secondary";restore.textContent="Вернуть текст в новый разговор";restore.disabled=job.state==="expired";
    restore.addEventListener("click",()=>void busy(restore,async()=>{const input=await invoke<Message[]>("load_remote_job_input",{id:job.id});const last=input.at(-1);if(!last||last.role!=="user")throw new Error("invalid_request");resetChat();messages=input.slice(0,-1);$<HTMLTextAreaElement>("prompt").value=last.content;renderChat();notify("Исходный текст восстановлен. Для отправки нужен новый просмотр.");}));
    actions.append(restore);row.append(label,actions);
    if(job.state==="done"){const answer=document.createElement("button");answer.className="secondary";answer.textContent="Показать ответ";answer.addEventListener("click",()=>void busy(answer,async()=>{const view=await invoke<RemoteJobView>("load_remote_job",{id:job.id});if(!view.reply)throw new Error("invalid_request");const result=document.createElement("pre");result.className="text-output";result.textContent=view.reply.text;row.append(result);answer.remove();}));actions.append(answer);}
    if(job.state==="queued"||job.state==="sending"){const cancel=document.createElement("button");cancel.className="secondary danger";cancel.textContent="Остановить";cancel.addEventListener("click",()=>void busy(cancel,async()=>{await invoke("cancel_remote_job",{id:job.id});await refreshRemoteJobs();}));actions.append(cancel);}
    list.append(row);
  }
}
const networkPanel=document.createElement("div");networkPanel.className="surface";
const networkHeading=document.createElement("h2");networkHeading.textContent="Удалённый маршрут Shield";
const networkHint=document.createElement("p");networkHint.className="hint";networkHint.textContent="Tor + ключ даёт L3: провайдер видит связь с оплатой. Для Strict/Paranoid этот маршрут запрещён. Поддерживается OpenAI chat API по HTTPS. При смене провайдера переоткройте пространство и начните новый разговор.";
const transportLabel=document.createElement("label");transportLabel.htmlFor="net-transport";transportLabel.textContent="Маршрут";
const transportSelect=document.createElement("select");transportSelect.id="net-transport";
for(const [id,title]of [["local","Только локальная модель · L0"],["tor","Tor + пул ключей · L3"]]){const option=document.createElement("option");option.value=id!;option.textContent=title!;transportSelect.append(option);}
networkPanel.append(networkHeading,networkHint,transportLabel,transportSelect);
for(const [id,title,type]of [["net-host","Хост HTTPS провайдера","text"],["net-path","Путь API","text"],["net-model","Имя удалённой модели","text"],["net-cost","Верхняя оценка цены одного запроса, USD","number"],["net-daily-count","Дневной лимит сетевых запросов","number"],["net-daily-budget","Дневной лимит резервирования, USD","number"]]){
  const label=document.createElement("label");label.htmlFor=id!;label.textContent=title!;
  const input=document.createElement("input");input.id=id!;input.type=type!;input.autocomplete="off";input.spellcheck=false;input.maxLength=253;
  if(type==="number"){input.min=id==="net-daily-count"?"1":"0.000001";input.step=id==="net-daily-count"?"1":"0.000001";input.max=id==="net-daily-count"?"10000":"100";}
  networkPanel.append(label,input);
}
const networkPriceHint=document.createElement("p");networkPriceHint.className="hint";networkPriceHint.textContent="Укажите запас по тарифу провайдера для полного входа и ответа до 2048 токенов. Резервирование — локальная оценка, а не банковский лимит. Неопределённая попытка тоже учитывается. Дополнительно ограничьте расходы в кабинете провайдера.";
const networkUsage=document.createElement("p");networkUsage.id="network-usage";networkUsage.className="hint";networkUsage.textContent="Откройте пространство для просмотра бюджета.";
const networkSave=document.createElement("button");networkSave.id="save-network";networkSave.className="secondary";networkSave.textContent="Сохранить маршрут и лимиты";
networkPanel.append(networkPriceHint,networkUsage,networkSave);document.querySelector('[data-panel="settings"]')!.append(networkPanel);on("save-network",saveSettings);
const bridgePanel=document.createElement("section"),bridgeHeading=document.createElement("h2"),bridgeHint=document.createElement("p"),bridgeKindLabel=document.createElement("label"),bridgeKind=document.createElement("select"),bridgeLinesLabel=document.createElement("label"),bridgeLines=document.createElement("textarea"),bridgeStatus=document.createElement("p"),bridgeSave=document.createElement("button");
bridgePanel.className="surface";bridgeHeading.textContent="Мосты Tor";bridgeHint.className="hint";bridgeHint.textContent="Мост скрывает обычное подключение Tor от оператора сети; сам мост видит ваш IP. В paranoid рекомендуется мост. Доступность L1/L2 и поддержка профиля проверяются отдельно. Вставьте строки полученных мостов одного типа. Используется только закреплённый Lyrebird; при ошибке обхода через прямой Tor нет. После изменения переоткройте пространство и начните новый разговор.";
bridgeKind.id="bridge-transport";bridgeKindLabel.textContent="Транспорт моста";for(const [id,title]of [["disabled","Без мостов"],["obfs4","obfs4"],["snowflake","Snowflake"],["webtunnel","WebTunnel"]]){const option=document.createElement("option");option.value=id!;option.textContent=title!;bridgeKind.append(option);}bridgeKindLabel.append(bridgeKind);
bridgeLines.id="bridge-lines";bridgeLines.rows=4;bridgeLines.maxLength=65536;bridgeLines.autocomplete="off";bridgeLines.spellcheck=false;bridgeLinesLabel.textContent="Новые строки мостов (до 16). Сохранённые строки не показываются.";bridgeLinesLabel.append(bridgeLines);
bridgeStatus.id="bridge-status";bridgeStatus.textContent="Состояние мостов ещё не получено.";bridgeSave.textContent="Сохранить мосты";bridgeSave.className="secondary";
bridgeSave.addEventListener("click",()=>void busy(bridgeSave,async()=>{if(!config)throw new Error("workspace_locked");const status=await invoke<BridgeStatus>("save_bridges",{config:bridgeInput(bridgeKind.value,bridgeLines.value)});bridgeLines.value="";bridgeStatus.textContent=bridgeStatusLabel(status);resetChat();notify("Мосты сохранены. Заблокируйте и снова откройте пространство перед удалённой отправкой.");}));
bridgePanel.append(bridgeHeading,bridgeHint,bridgeKindLabel,bridgeLinesLabel,bridgeStatus,bridgeSave);document.querySelector('[data-panel="settings"]')!.append(bridgePanel);
const trafficPanel=document.createElement("section"),trafficHeading=document.createElement("h2"),trafficConsent=document.createElement("label"),trafficCheckbox=document.createElement("input"),trafficIntervalLabel=document.createElement("label"),trafficInterval=document.createElement("input"),trafficHint=document.createElement("p"),trafficStatus=document.createElement("div"),trafficRefresh=document.createElement("button");
trafficPanel.className="surface";trafficHeading.textContent="Ритм теневого трафика";
trafficCheckbox.type="checkbox";trafficCheckbox.id="traffic-enabled";trafficConsent.append(trafficCheckbox,document.createTextNode(" Разрешаю автоматические платные запросы из независимых синтетических тем (standard, Tor L3)."));
const tailConsent=document.createElement("label"),tailCheckbox=document.createElement("input"),sessionTiming=document.createElement("p");
tailCheckbox.type="checkbox";tailCheckbox.id="background-tail";tailConsent.append(tailCheckbox,document.createTextNode(" Разрешаю после закрытия окна ещё 10–60 минут держать ядро, локальную модель и ключи в памяти для платных независимых приманок в пределах бюджета. Требуются включённые автоматические приманки. «Заблокировать» останавливает всё сразу."));
sessionTiming.id="session-timing";sessionTiming.textContent=sessionTimingLabel(undefined);
const sessionHint=document.createElement("p");sessionHint.className="hint";sessionHint.textContent="Первый внешний запрос после открытия пространства ждёт случайные 5–30 минут. Хвост работает при доступном маршруте, проверке устройства, ключах и бюджете; сон и выключение компьютера прерывают его. Под L3 один ключ связывает запросы: суточный ритм ключа остаётся виден провайдеру.";
trafficInterval.type="number";trafficInterval.id="traffic-interval";trafficInterval.min="1";trafficInterval.max="86400";trafficIntervalLabel.textContent="Средний интервал, секунды";trafficIntervalLabel.append(trafficInterval);
const trafficModeLabel=document.createElement("label"),trafficMode=document.createElement("select");trafficModeLabel.textContent="Режим";trafficMode.id="traffic-mode";for(const [mode,title]of [["poisson","Приманки по Пуассону"],["constant","Постоянные слоты: реальные запросы ждут"]]){const option=document.createElement("option");option.value=mode!;option.textContent=title!;trafficMode.append(option);}trafficModeLabel.append(trafficMode);
trafficHint.className="hint";trafficHint.textContent="Каждая приманка занимает отдельный ключ и разговор. В постоянном режиме задания ждут слота; без бюджета остаются в очереди. Сеть и модель могут задержать слот. Оставьте ключи для своих вопросов. Прерванные попытки не повторяются. L3 запрещён в strict/paranoid; автоматические приманки недоступны при обязательном просмотре каждого запроса. Изменения сохраняются кнопкой маршрута выше.";
trafficStatus.id="traffic-status";trafficRefresh.textContent="Обновить состояние приманок";trafficRefresh.className="secondary";trafficRefresh.addEventListener("click",()=>void busy(trafficRefresh,async()=>{renderTraffic(await invoke<TrafficStatus>("traffic_status"));sessionTiming.textContent=sessionTimingLabel(await invoke<SessionTiming>("session_timing"));}));
trafficPanel.append(trafficHeading,trafficConsent,tailConsent,sessionHint,sessionTiming,trafficModeLabel,trafficIntervalLabel,trafficHint,trafficStatus,trafficRefresh);document.querySelector('[data-panel="settings"]')!.append(trafficPanel);
function renderTraffic(status:TrafficStatus){
  const out=$("traffic-status");out.replaceChildren();const summary=document.createElement("p");summary.textContent=status.enabled?`${config?.cover.mode==="constant"?"Постоянные слоты включены":"Пуассоновский режим включён"}. Следующий слот: ${status.next_slot?new Date(status.next_slot*1000).toLocaleString():"ожидает планирования"}.`:"Фоновые запросы выключены.";out.append(summary);
  const list=document.createElement("ul");for(const job of status.jobs.slice(-8).reverse()){const item=document.createElement("li");item.textContent=`${new Date(job.created_at*1000).toLocaleString()} · ${job.purpose==="real"?"запрос":"приманка"} · ${{preparing:"подготовка / отправка",succeeded:"получен ответ",uncertain:"результат неизвестен, повтор запрещён",blocked:"остановлено"}[job.state]??job.state}${job.code?" · "+job.code:""}`;list.append(item);}out.append(list);
}
function renderNetworkUsage(usage:NetworkUsage){networkUsage.textContent=`Учёт за ${new Date(usage.day*86400*1000).toISOString().slice(0,10)} UTC: запросов ${usage.requests}, зарезервировано ${(usage.reserved_microusd/1_000_000).toFixed(6)} USD.`;}
const modelFiles=document.createElement("div");
const driftModeLabel=document.createElement("label"),driftMode=document.createElement("select"),driftModeHint=document.createElement("p");
driftMode.id="drift-mode";driftModeLabel.htmlFor=driftMode.id;driftModeLabel.textContent="Исполнение легенды";
for(const [id,title]of [["assisted","Вручную (по умолчанию)"],["extension","Поиск Google / YouTube через расширение"]]){const option=document.createElement("option");option.value=id!;option.textContent=title!;driftMode.append(option);}
driftModeHint.className="hint";driftModeHint.textContent="В режиме расширения каждое действие запускается вашей кнопкой с разрешением на сайт. Ввод идёт в отдельной вкладке, затем 20–90 секунд чтения. CAPTCHA, вход, закрытие вкладки или пауза останавливают действие; прерванные попытки не повторяются. Веб-чаты ИИ и просмотр видео остаются ручными.";
modelFiles.append(driftModeLabel,driftMode,driftModeHint);
for(const [field,id,title]of modelFileFields){
  const label=document.createElement("label");label.htmlFor=id;label.textContent=title;
  const input=document.createElement("input");input.id=id;input.maxLength=field.endsWith('sha256')?64:4096;input.spellcheck=false;input.autocomplete="off";input.placeholder=field.endsWith('sha256')?"64 шестнадцатеричных символа":"Полный путь к локальному файлу";modelFiles.append(label,input);
}
const modelStart=document.createElement("button");modelStart.id="start-model";modelStart.className="secondary";modelStart.textContent="Запустить проверенные модели";
const modelHint=document.createElement("p");modelHint.className="hint";modelHint.textContent="Файлы не скачиваются автоматически. Проверка SHA-256 и загрузка могут занять до двух минут. При блокировке пространства запущенные здесь модели завершаются.";
modelFiles.append(modelStart,modelHint);$("save-settings").after(modelFiles);
on("start-model",async()=>{await saveSettings();notify("Проверка и загрузка локальных моделей…");renderStorage(await invoke<StorageStatus>("start_model"));notify("Модели запущены. Можно открыть Shield или исследование.");});
const credentialHeading=document.createElement("h2");credentialHeading.textContent="Ключи провайдеров";
const credentialHint=document.createElement("p");credentialHint.className="hint";credentialHint.textContent="Ключи хранятся в хранилище ОС. Они дают L3: провайдер может связать их с плательщиком. Удаление здесь не отзывает ключ у провайдера.";
const credentialLabel=document.createElement("label");credentialLabel.htmlFor="provider-key";credentialLabel.textContent="Новый API-ключ";
const credentialInput=document.createElement("input");credentialInput.id="provider-key";credentialInput.type="password";credentialInput.autocomplete="off";credentialInput.spellcheck=false;credentialInput.maxLength=4096;
const credentialButton=document.createElement("button");credentialButton.id="add-provider-key";credentialButton.className="secondary";credentialButton.textContent="Сохранить в хранилище ОС";
const credentialList=document.createElement("ul");credentialList.id="provider-keys";credentialList.className="checklist";credentialList.textContent="Откройте пространство для просмотра ключей.";
credentialPanel.append(credentialHeading,credentialHint,credentialLabel,credentialInput,credentialButton,credentialList);
document.querySelector('[data-panel="settings"]')!.append(credentialPanel);
on("add-provider-key",async()=>{const key=credentialInput.value;credentialInput.value="";renderProviderKeys(await invoke<CredentialInfo[]>("add_provider_key",{key}));notify("Ключ сохранён. Его значение больше не показывается.");});
const metricGrid=$("shadow-share").closest(".metric-grid")!;
for(const [id,label,hint] of [
  ["cover-ratio","Приманки / удалённые запросы","Только подтверждённые ответы транспорта за период наблюдения. L0 и неизвестные исходы не входят."],
  ["challenge-rate","Остановки CAPTCHA / вход","Учтённые остановки / (остановки + выполненные действия легенды) за период наблюдения."],
]){
  const card=document.createElement("div");card.className="surface";
  const title=document.createElement("span");title.className="metric-label";title.textContent=label!;
  const number=document.createElement("strong");number.id=id!;number.className="metric-value";number.textContent="—";
  const description=document.createElement("p");description.className="hint";description.textContent=hint!;
  card.append(title,number,description);metricGrid.append(card);
}
const refreshMetrics=document.createElement("button");refreshMetrics.className="quiet";refreshMetrics.textContent="Обновить метрики и паузу из ядра";
refreshMetrics.addEventListener("click",()=>void busy(refreshMetrics,refreshOverview));metricGrid.after(refreshMetrics);
const purgeHelp=document.createElement("section"),purgeHelpHeading=document.createElement("h2"),purgeGuideSelect=document.createElement("select"),purgeGuideLabel=document.createElement("label"),purgeGuideBody=document.createElement("div"),purgeResults=document.createElement("div"),purgeResultsHeading=document.createElement("h2"),purgeResultsRefresh=document.createElement("button");
purgeHelp.className="surface";purgeHelpHeading.textContent="Инструкции по сервисам";purgeGuideSelect.id="purge-guide-service";purgeGuideLabel.htmlFor=purgeGuideSelect.id;purgeGuideLabel.textContent="Сервис";
for(const [id,title]of [["google","Google"],["youtube","YouTube"],["chatgpt","ChatGPT"],["claude","Claude"],["gemini","Gemini"]]){const option=document.createElement("option");option.value=id!;option.textContent=title!;purgeGuideSelect.append(option);}
purgeGuideBody.textContent="Откройте пространство и обновите инструкции.";purgeResults.id="purge-results";purgeResultsHeading.textContent="Одобренные партии и мои отметки";purgeResultsRefresh.textContent="Обновить партии и инструкции";purgeResultsRefresh.className="secondary";
purgeHelp.append(purgeHelpHeading,purgeGuideLabel,purgeGuideSelect,purgeGuideBody,purgeResultsHeading,purgeResultsRefresh,purgeResults);document.querySelector('[data-panel="purge"]')!.append(purgeHelp);
const purgeGuides=new Map<string,PurgeGuide>();
async function loadPurgeGuide(service:string){let guide=purgeGuides.get(service);if(!guide){guide=await invoke<PurgeGuide>("purge_guide",{service});purgeGuides.set(service,guide);}return guide;}
async function refreshPurgeBatches(){
  const epoch=sessionEpoch;
  const selectedService=purgeGuideSelect.value;
  const batches=await invoke<PurgeBatchView[]>("load_purge_batches");
  await Promise.all([...new Set([selectedService,...batches.map(v=>v.batch.service)])].map(loadPurgeGuide));
  if(epoch!==sessionEpoch)throw new Error("session_changed");
  if(purgeGuideSelect.value===selectedService)renderPurgeGuide(purgeGuideBody,purgeGuides.get(selectedService)!);
  renderPurgeBatches(purgeResults,batches,purgeGuides,async(hash,outcome,steps)=>{
    await invoke("record_purge_result",{hash,outcome,completedSteps:steps});await refreshPurgeBatches();notify("Ваши отметки о ручной проверке сохранены зашифрованными.");
  },error=>notify(friendly(error),true));
}
purgeGuideSelect.addEventListener("change",()=>{const selected=purgeGuideSelect.value;void loadPurgeGuide(selected).then(guide=>{if(purgeGuideSelect.value===selected)renderPurgeGuide(purgeGuideBody,guide);}).catch(error=>notify(friendly(error),true));});
purgeResultsRefresh.addEventListener("click",()=>void busy(purgeResultsRefresh,refreshPurgeBatches));
if(window.__TAURI__)void (async()=>{await refreshOverview();if(unlocked)await hydrate();})().catch(e=>notify(friendly(e),true));
else notify("Это статический интерфейс. Для обработки данных запустите десктопное приложение.");
export {};

