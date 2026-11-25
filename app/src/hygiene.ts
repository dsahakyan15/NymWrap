export interface HygieneReport {checks:{kind:string;verdict:"pass"|"fail"|"unknown"}[];llmnr_disabled:boolean|null;netbios_disabled:boolean|null;mdns_disabled:boolean|null}
export interface DeviceProbeStatus {last_attempt:number;last_success:number;protected_values:number;unavailable:string[];observed?:string[];code:string|null;hygiene?:HygieneReport|null}
const checkNames:Record<string,string>={wifi_mac:"MAC-рандомизация в прочитанных Wi-Fi профилях",hostname:"Нейтральное имя компьютера без совпадения с известным именем",multicast:"LLMNR, NetBIOS и mDNS",location:"Политика отключения геолокации",clock:"Оценка расхождения часов меньше пяти минут",browser:"WebRTC и геолокация в проверенных политиках Firefox"};
export function hygieneStats(report:HygieneReport){
  const kinds=Object.keys(checkNames);if(report.checks.length!==6||report.checks.some((check,index)=>check.kind!==kinds[index]||!["pass","fail","unknown"].includes(check.verdict)))throw new Error("invalid_core_reply");
  const known=report.checks.filter(c=>c.verdict!=="unknown").length,passed=report.checks.filter(c=>c.verdict==="pass").length;
  return {known,passed,score:known?passed/6:null};
}
export function renderHygiene(root:HTMLElement,status:DeviceProbeStatus|undefined){
  root.replaceChildren();const summary=document.createElement("p");
  if(!status?.hygiene){summary.textContent="Снимок настроек ОС ещё не получен. Ручные инструкции не считаются измерением.";root.append(summary);return;}
  const stats=hygieneStats(status.hygiene),fresh=Date.now()/1000>=status.last_success&&Date.now()/1000-status.last_success<86400&&status.last_success>0&&status.code===null;
  summary.textContent=`Снимок: ${new Date(status.last_success*1000).toLocaleString()}. Измерено ${stats.known}/6, подтверждено ${stats.passed}/6. hygiene_score: ${fresh&&stats.score!==null?Math.round(stats.score*100)+"%":"неизвестно"}.${fresh?"":" Снимок устарел, его время неверно или последняя проверка не завершена."}`;
  const list=document.createElement("ul");for(const check of status.hygiene.checks){const item=document.createElement("li");item.textContent=`${checkNames[check.kind]}: ${{pass:"подтверждено чтением настройки",fail:"нуждается во внимании",unknown:"не измерено или нет доступа"}[check.verdict]}.`;list.append(item);}
  const details=document.createElement("p");const state=(value:boolean|null)=>value===true?"наблюдается отключение":value===false?"наблюдается включение":"не измерено";
  details.textContent=`LLMNR: ${state(status.hygiene.llmnr_disabled)}; NetBIOS: ${state(status.hygiene.netbios_disabled)}; mDNS: ${state(status.hygiene.mdns_disabled)}. Наблюдение конфигурации не заменяет захват трафика.`;
  root.append(summary,list,details);
}
const sources:Record<string,string>={user:"имя и отображаемое имя пользователя",host:"имя компьютера и домен",home:"домашние пути",mac:"MAC-адреса",wifi:"сохранённые Wi-Fi сети",ip:"локальные IP-адреса",machine:"идентификатор машины",timezone:"часовой пояс",git:"git-личность"};
export function deviceInventoryReady(status:DeviceProbeStatus|undefined,now=Date.now()/1000):boolean{return !!status&&status.last_success>0&&now>=status.last_success&&now-status.last_success<86400&&status.code===null&&status.unavailable.length===0&&Object.keys(sources).every(source=>status.observed?.includes(source));}
export function renderDeviceProbe(root:HTMLElement,status:DeviceProbeStatus|undefined){
  root.replaceChildren();const summary=document.createElement("p"),coverage=document.createElement("p");
  if(!status){summary.textContent="Откройте пространство, чтобы прочитать состояние проверки устройства.";root.append(summary);return;}
  summary.textContent=`Секретов устройства под защитой: ${status.protected_values}. Последняя попытка: ${status.last_attempt?new Date(status.last_attempt*1000).toLocaleString():"ещё не выполнялась"}.`;
  coverage.textContent=deviceInventoryReady(status)?"Все обязательные источники прочитаны. Проверка повторяется раз в сутки.":"Проверка устройства не завершена полностью. Удалённая отправка при включённой защите устройства остановлена. Локальная модель доступна.";
  root.append(summary,coverage);
  const unknown=[...new Set([...Object.keys(sources).filter(source=>!status.observed?.includes(source)),...status.unavailable])];
  if(unknown.length){const list=document.createElement("ul");for(const source of unknown){const item=document.createElement("li");item.textContent=`Неизвестно, источник не прочитан полностью: ${sources[source]??source}.`;list.append(item);}root.append(list);}
  if(status.code){const issue=document.createElement("p");issue.textContent=`Проверка не завершилась. Код: ${status.code}`;root.append(issue);}
}
export function createHygienePanel():HTMLElement{
  const panel=document.createElement("section");panel.dataset.panel="hygiene";panel.hidden=true;
  const title=document.createElement("h1");title.textContent="Гигиена устройства";
  const intro=document.createElement("p");intro.className="lede";intro.textContent="Проверка только читает данные. Настройки компьютера остаются под вашим контролем.";
  const inventory=document.createElement("div");inventory.className="surface";const heading=document.createElement("h2");heading.textContent="Секреты устройства";
  const status=document.createElement("div");status.id="device-probe-status";renderDeviceProbe(status,undefined);
  const refresh=document.createElement("button");refresh.id="run-device-probe";refresh.className="secondary";refresh.textContent="Повторить проверку устройства";
  const edit=document.createElement("p");edit.textContent="Найденные значения добавляются в список секретов Shield. Их можно посмотреть и удалить там. Удалённые вами значения не возвращаются при автоматической проверке. Недоступные источники остаются отмеченными; добавление значения вручную не считается проверкой источника.";
  inventory.append(heading,status,refresh,edit);
  const observed=document.createElement("div"),observedTitle=document.createElement("h2"),observedStatus=document.createElement("div");observed.className="surface";observedTitle.textContent="Наблюдения настроек ОС";observedStatus.id="hygiene-checks";renderHygiene(observedStatus,undefined);observed.append(observedTitle,observedStatus);
  const manual=document.createElement("div");manual.className="surface";const manualTitle=document.createElement("h2");manualTitle.textContent="Проверьте настройки ОС вручную";
  const note=document.createElement("p");note.className="hint";note.textContent="Покрытие автоматической проверки зависит от доступа ОС. Часы оцениваются по доступной оценке ошибки ядра; для браузера проверяются заблокированные политики Firefox, если он выбран по умолчанию. Остальные браузеры и непрочитанные настройки остаются неизвестными. Инструкции ниже не меняют результат измерения.";
  const list=document.createElement("ol");for(const text of [
    "Включите случайный или частный MAC для Wi-Fi в настройках вашей сети. На Windows проверьте случайные аппаратные адреса, на macOS — частный адрес Wi-Fi, на Linux — параметры MAC подключения NetworkManager.",
    "Проверьте имя компьютера: оно не должно содержать ваше имя, фамилию или логин. Изменение имени выполняйте средствами ОС.",
    "Для публичных сетей проверьте отключение LLMNR, NetBIOS и mDNS. На управляемом компьютере уточните настройки у администратора; NymWrap их не меняет.",
    "Проверьте доступ настольных приложений к геолокации в настройках конфиденциальности ОС.",
    "Сверьте часы с доверенным источником. Расхождение больше пяти минут требует синхронизации времени в ОС.",
    "В браузере для настоящего сёрфинга проверьте разрешения геолокации и WebRTC. Для теневой активности используйте Tor Browser или Mullvad Browser.",
  ]){const item=document.createElement("li");item.textContent=text;list.append(item);}manual.append(manualTitle,note,list);
  panel.append(title,intro,inventory,observed,manual);return panel;
}
