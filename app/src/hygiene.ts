export interface DeviceProbeStatus {last_attempt:number;last_success:number;protected_values:number;unavailable:string[];code:string|null}
const sources:Record<string,string>={user:"имя и отображаемое имя пользователя",host:"имя компьютера и домен",home:"домашние пути",mac:"MAC-адреса",wifi:"сохранённые Wi-Fi сети",ip:"локальные IP-адреса",machine:"идентификатор машины",timezone:"часовой пояс",git:"git-личность"};
export function deviceInventoryReady(status:DeviceProbeStatus|undefined,now=Date.now()/1000):boolean{return !!status&&status.last_success>0&&now>=status.last_success&&now-status.last_success<86400&&status.code===null&&status.unavailable.length===0;}
export function renderDeviceProbe(root:HTMLElement,status:DeviceProbeStatus|undefined){
  root.replaceChildren();const summary=document.createElement("p"),coverage=document.createElement("p");
  if(!status){summary.textContent="Откройте пространство, чтобы прочитать состояние проверки устройства.";root.append(summary);return;}
  summary.textContent=`Секретов устройства под защитой: ${status.protected_values}. Последняя попытка: ${status.last_attempt?new Date(status.last_attempt*1000).toLocaleString():"ещё не выполнялась"}.`;
  coverage.textContent=deviceInventoryReady(status)?"Все обязательные источники прочитаны. Проверка повторяется раз в сутки.":"Проверка устройства не завершена полностью. Удалённая отправка при включённой защите устройства остановлена. Локальная модель доступна.";
  root.append(summary,coverage);
  if(status.unavailable.length){const list=document.createElement("ul");for(const source of status.unavailable){const item=document.createElement("li");item.textContent=`Не удалось прочитать: ${sources[source]??source}.`;list.append(item);}root.append(list);}
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
  const manual=document.createElement("div");manual.className="surface";const manualTitle=document.createElement("h2");manualTitle.textContent="Проверьте настройки ОС вручную";
  const note=document.createElement("p");note.className="hint";note.textContent="Эти пункты не отмечаются выполненными автоматически. Полная автоматическая проверка настроек ОС и оценка гигиены пока не реализованы.";
  const list=document.createElement("ol");for(const text of [
    "Включите случайный или частный MAC для Wi-Fi в настройках вашей сети. На Windows проверьте случайные аппаратные адреса, на macOS — частный адрес Wi-Fi, на Linux — параметры MAC подключения NetworkManager.",
    "Проверьте имя компьютера: оно не должно содержать ваше имя, фамилию или логин. Изменение имени выполняйте средствами ОС.",
    "Для публичных сетей проверьте отключение LLMNR, NetBIOS и mDNS. На управляемом компьютере уточните настройки у администратора; NymWrap их не меняет.",
    "Проверьте доступ настольных приложений к геолокации в настройках конфиденциальности ОС.",
    "Сверьте часы с доверенным источником. Расхождение больше пяти минут требует синхронизации времени в ОС.",
    "В браузере для настоящего сёрфинга проверьте разрешения геолокации и WebRTC. Для теневой активности используйте Tor Browser или Mullvad Browser.",
  ]){const item=document.createElement("li");item.textContent=text;list.append(item);}manual.append(manualTitle,note,list);
  panel.append(title,intro,inventory,manual);return panel;
}
