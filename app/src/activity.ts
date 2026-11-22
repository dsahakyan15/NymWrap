export interface ActivityTransition{start_hour_utc:number;target_hour_utc:number;width_hours:number}
export interface ActivitySchedule{windows:{start_hour_utc:number;width_hours:number}[]}
export function activityTransition(start:number,target:number,width:number):ActivityTransition{
  if(![start,target,width].every(Number.isInteger)||start<0||start>23||target<0||target>23||width<1||width>12)throw new Error("invalid_activity_window");
  return {start_hour_utc:start,target_hour_utc:target,width_hours:width};
}
export function activityLabel(schedule:ActivitySchedule|null|undefined,index:number):string{
  const window=schedule?.windows[index];if(!window)return "Прежний план без окна активности. Для нового расписания перестройте и одобрите план.";
  if(!Number.isInteger(window.start_hour_utc)||!Number.isInteger(window.width_hours)||window.start_hour_utc<0||window.start_hour_utc>23||window.width_hours<1||window.width_hours>12)throw new Error("invalid_activity_window");
  const hour=(value:number)=>String(value).padStart(2,"0")+":00";
  return `Окно активности: ${hour(window.start_hour_utc)}–${hour((window.start_hour_utc+window.width_hours)%24)} UTC. Сдвиг не больше двух часов за этап.`;
}
