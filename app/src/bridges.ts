export type BridgeTransport="obfs4"|"snowflake"|"webtunnel";
export interface BridgeStatus{transport:BridgeTransport|null;lines:number;isolation_supported?:boolean}
export interface BridgeConfig{transport:BridgeTransport;lines:string[]}
export function bridgeInput(transport:string,text:string):BridgeConfig|null{
  if(transport==="disabled")return null;
  if(!["obfs4","snowflake","webtunnel"].includes(transport))throw new Error("invalid_bridge_configuration");
  const lines=text.split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
  if(!lines.length||lines.length>16||lines.some(line=>line.length>4096)||new Set(lines).size!==lines.length)throw new Error("invalid_bridge_configuration");
  return{transport:transport as BridgeTransport,lines};
}
export function bridgeStatusLabel(status:BridgeStatus):string{
  if(!Number.isSafeInteger(status.lines)||status.lines<0||status.lines>16||!(status.transport===null||["obfs4","snowflake","webtunnel"].includes(status.transport)))throw new Error("invalid_core_reply");
  if(status.transport&&status.isolation_supported!==true)return `Сохранён транспорт ${status.transport}; строк мостов: ${status.lines}. Изоляция PT на этой ОС недоступна или не подтверждена: запуск мостов запрещён, перехода на обычный Tor нет. Для изолированных мостов используйте Linux.`;
  return status.transport?`Сохранён транспорт ${status.transport}; строк мостов: ${status.lines}. Строки хранятся зашифрованными и повторно не показываются. Песочница PT проверяется при запуске.`:"Мосты выключены. Используется обычный Tor, если он разрешён профилем.";
}
