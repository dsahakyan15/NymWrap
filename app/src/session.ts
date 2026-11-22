export interface SessionTiming {phase:"locked"|"starting"|"foreground"|"tail";first_send_in_s:number;tail_remaining_s:number|null}
export function sessionTimingLabel(status:SessionTiming|undefined):string {
  if(!status)return "Состояние границ сеанса ещё не получено.";
  if(!Number.isSafeInteger(status.first_send_in_s)||status.first_send_in_s<0||status.first_send_in_s>1800||!(status.tail_remaining_s===null||Number.isSafeInteger(status.tail_remaining_s)&&status.tail_remaining_s>=0&&status.tail_remaining_s<=3600))throw new Error("invalid_core_reply");
  switch(status.phase){
    case "locked":return "Пространство заблокировано; фоновый хвост остановлен.";
    case "starting":return `До разрешения первого внешнего запроса: ${Math.ceil(status.first_send_in_s/60)} мин. Локальные ответы доступны. Внешние задания остаются в очереди.`;
    case "foreground":return "Начальная задержка закончилась. Исходящие запросы проходят остальные проверки маршрута.";
    case "tail":return `Окно фоновых приманок: ещё ${Math.ceil((status.tail_remaining_s??0)/60)} мин. Доступ к пространству требует пароля.`;
    default:throw new Error("invalid_core_reply");
  }
}
