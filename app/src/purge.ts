export interface PurgeGuide {
  service:string;checked_on:string;
  steps:{id:string;title:string;text:string}[];
  sources:{title:string;url:string}[];
}
export type PurgeOutcome="not_checked"|"no_longer_visible"|"still_visible"|"unavailable";
export interface PurgeBatchView {
  hash:string;batch:{service:string;record_ids:string[]};
  review:{outcome:PurgeOutcome;completed_steps:string[];checked_at:number}|null;
}
const outcomeNames:Record<PurgeOutcome,string>={not_checked:"Ещё не проверял(а)",no_longer_visible:"Выбранные записи больше не видны",still_visible:"Выбранные записи ещё видны",unavailable:"Проверка недоступна"};
const element=<K extends keyof HTMLElementTagNameMap>(tag:K,text?:string)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;return node;};
export function renderPurgeGuide(container:HTMLElement,guide:PurgeGuide){
  container.replaceChildren();
  container.append(element("p",`Инструкции проверены: ${guide.checked_on}. Названия настроек могут зависеть от аккаунта.`));
  const list=element("ol");list.className="checklist";
  for(const step of guide.steps){const item=element("li");item.append(element("strong",step.title),element("p",step.text));list.append(item);}
  container.append(list,element("p","Официальная справка — скопируйте адрес в свой браузер:"));
  for(const source of guide.sources){const line=element("p",`${source.title}: ${source.url}`);line.className="hint mono";container.append(line);}
}
export function renderPurgeBatches(
  container:HTMLElement,batches:PurgeBatchView[],guides:Map<string,PurgeGuide>,
  save:(hash:string,outcome:PurgeOutcome,steps:string[])=>Promise<void>,failure:(error:unknown)=>void,
){
  container.replaceChildren();
  if(!batches.length){container.append(element("p","Одобренных партий пока нет."));return;}
  for(const view of batches){
    const guide=guides.get(view.batch.service);if(!guide)continue;
    const card=element("details"),summary=element("summary",`${view.batch.service} · записей: ${view.batch.record_ids.length} · ${view.hash.slice(0,12)}…`);
    card.append(summary,element("p",`Хеш одобренной партии: ${view.hash}`));
    const prior=view.review?`${outcomeNames[view.review.outcome]} · ${new Date(view.review.checked_at*1000).toLocaleString()}`:"Проверка результата ещё не сохранена.";
    card.append(element("p",prior),element("p","Это ваши отметки о ручных действиях. NymWrap не проверяет серверное удаление."));
    const checks:{id:string;input:HTMLInputElement}[]=[];
    for(const step of guide.steps){
      const label=element("label"),input=element("input");input.type="checkbox";input.checked=view.review?.completed_steps.includes(step.id)??false;
      label.append(input,element("span",step.title));card.append(label);checks.push({id:step.id,input});
    }
    const label=element("label","Наблюдаемый результат"),select=element("select");
    for(const [value,text]of Object.entries(outcomeNames)){const option=element("option",text);option.value=value;select.append(option);}
    select.value=view.review?.outcome??"not_checked";label.append(select);card.append(label);
    const button=element("button","Сохранить мои отметки");button.className="secondary";
    button.addEventListener("click",()=>{
      button.disabled=true;
      void save(view.hash,select.value as PurgeOutcome,checks.filter(c=>c.input.checked).map(c=>c.id))
        .catch(failure).finally(()=>{button.disabled=false;});
    });
    card.append(button);container.append(card);
  }
}
