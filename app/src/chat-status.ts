export interface ChatStatus {trust:string;local_reason?:string|null}
const reasons:Record<string,string>={
  entity_verification_unavailable:"Проверка персональных данных недоступна или вернула неподтверждённые фрагменты. Удалённая отправка запрещена.",
  missing_dossier:"Досье пока недоступно для полной проверки связывания.",
  verification_unavailable:"Проверка связывания не смогла подтвердить безопасность удалённой отправки.",
  generalization_failed:"Безопасно обобщить редкие факты не удалось.",
  independent_split_unavailable:"Даже после обобщения совокупность фактов может выдать вас. Независимое разделение разговоров пока недоступно.",
};
export function chatStatusLabel(reply:ChatStatus):string{
  if(reply.trust==="L0")return "Ответ получен локально (L0)."+(reply.local_reason?" "+(Object.hasOwn(reasons,reply.local_reason)?reasons[reply.local_reason]:"Проверка приватности потребовала локального ответа."):"");
  if(reply.trust==="L3")return "Ответ получен через Tor с ключом провайдера (L3).";
  return "Ответ получен. Уровень доверия: "+reply.trust;
}
