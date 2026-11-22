export interface Observation {kind:string;captured_at:number;position:number}
const sources:Record<string,string>={youtube_feed:"Лента YouTube",ad_topics:"Рекламные темы",search_suggestions:"Подсказки поиска",ai_memory:"Память ИИ",takeout:"Takeout"};
const kinds=Object.keys(sources);
export function sourceName(kind:string):string{return Object.hasOwn(sources,kind)?sources[kind]!:"Неизвестный источник";}
/** Keep sources separate and preserve positions beyond [0,1], without overflowing SVG coordinates. */
export function timeline(items:readonly Observation[]){
  const valid=items.filter(o=>Object.hasOwn(sources,o.kind)&&Number.isFinite(o.position)&&Number.isSafeInteger(o.captured_at)&&o.captured_at>=0&&o.captured_at<=8_640_000_000_000).slice(-100).sort((a,b)=>a.captured_at-b.captured_at);
  const start=valid.at(0)?.captured_at??0,end=valid.at(-1)?.captured_at??start;
  const scale=Math.max(1,...valid.map(o=>Math.abs(o.position)));
  const low=Math.min(0,...valid.map(o=>o.position/scale))-.1/scale;
  const high=Math.max(1/scale,...valid.map(o=>o.position/scale))+.1/scale;
  const y=(position:number)=>225-(position/scale-low)/(high-low)*180;
  const points=valid.map(o=>({...o,x:end===start?380:70+(o.captured_at-start)/(end-start)*620,y:y(o.position)}));
  return {start,end,baseline:y(0),target:y(1),series:kinds.map(kind=>({kind,points:points.filter(o=>o.kind===kind)})).filter(s=>s.points.length)};
}
const namespace="http://www.w3.org/2000/svg";
function svg<K extends keyof SVGElementTagNameMap>(name:K,attributes:Record<string,string|number>={}){
  const element=document.createElementNS(namespace,name);
  for(const [key,value]of Object.entries(attributes))element.setAttribute(key,String(value));
  return element;
}
export function mirrorChart(items:readonly Observation[]):HTMLElement{
  const container=document.createElement("figure");container.className="mirror-chart";
  const label=document.createElement("label");label.textContent="Показать источник";
  const select=document.createElement("select");select.setAttribute("aria-label","Источник графика Mirror");
  for(const [value,text]of [["all","Все источники"],...kinds.map(k=>[k,sourceName(k)])]){
    const option=document.createElement("option");option.value=value!;option.textContent=text!;select.append(option);
  }
  label.append(select);
  const drawing=document.createElement("div"),caption=document.createElement("figcaption");caption.className="hint";caption.setAttribute("aria-live","polite");
  function render(){
    drawing.replaceChildren();
    const data=timeline(select.value==="all"?items:items.filter(o=>o.kind===select.value));
    const count=data.series.reduce((n,s)=>n+s.points.length,0);
    caption.textContent=count?"Наведите на точку или выберите её клавишей Tab. 0 — исходная персона, 1 — легенда; выход за эти границы допустим.":"Для этого источника пока нет измерений.";
    if(!count)return;
    const chart=svg("svg",{viewBox:"0 0 720 285",role:"img","aria-label":"Позиции снимков на оси персона — легенда"});
    for(const [value,y]of [[0,data.baseline],[1,data.target]]){
      chart.append(svg("line",{x1:65,x2:695,y1:y!,y2:y!,class:"mirror-reference"}));
      const text=svg("text",{x:52,y:y!+4,"text-anchor":"end",class:"mirror-axis-label"});text.textContent=String(value);chart.append(text);
    }
    const date=(at:number)=>new Date(at*1000).toLocaleDateString();
    for(const [x,at,anchor]of [[70,data.start,"start"],[690,data.end,"end"]]as const){
      const text=svg("text",{x,y:262,"text-anchor":anchor,class:"mirror-axis-label"});text.textContent=date(at);chart.append(text);
    }
    const legend=document.createElement("ul");legend.className="mirror-legend";
    for(const series of data.series){
      const className="mirror-series-"+kinds.indexOf(series.kind);
      chart.append(svg("polyline",{points:series.points.map(p=>`${p.x},${p.y}`).join(" "),class:className}));
      const item=document.createElement("li");item.className=className;item.textContent=sourceName(series.kind);legend.append(item);
      for(const point of series.points){
        const text=`${new Date(point.captured_at*1000).toLocaleString()} · ${sourceName(point.kind)} · позиция ${point.position.toFixed(3)}`;
        const dot=svg("circle",{cx:point.x,cy:point.y,r:5,tabindex:0,role:"img","aria-label":text,class:className});
        const title=svg("title");title.textContent=text;dot.append(title);
        dot.addEventListener("pointerenter",()=>{caption.textContent=text;});dot.addEventListener("focus",()=>{caption.textContent=text;});chart.append(dot);
      }
    }
    drawing.append(chart,legend);
  }
  select.addEventListener("change",render);container.append(label,drawing,caption);render();return container;
}
