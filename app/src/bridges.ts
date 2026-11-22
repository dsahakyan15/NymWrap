export type BridgeTransport="obfs4"|"snowflake"|"webtunnel";
export interface BridgeStatus{transport:BridgeTransport|null;lines:number}
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
  return status.transport?`Сохранён транспорт ${status.transport}; строк мостов: ${status.lines}. Строки хранятся зашифрованными и повторно не показываются.`:"Мосты выключены. Используется обычный Tor, если он разрешён профилем.";
}
