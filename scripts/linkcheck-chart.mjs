// Presentation of recorded measurements only; never invokes a model.
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const base=join(root,'docs/evaluations/shield-linkcheck-task5');
const held=JSON.parse(await readFile(join(base,'held-out.json'),'utf8'));
const paired=JSON.parse(await readFile(join(base,'paired.json'),'utf8')).phases;
const rows=[
  ['Development · исходный',paired.development.model.all.before,'var(--chart-2,slategray)'],
  ['Development · выход',paired.development.model.all.after,'var(--chart-2,slategray)'],
  ['Held-out · исходный',paired.held_out.model.all.before,'var(--chart-1,teal)'],
  ['Held-out · выход',paired.held_out.model.all.after,'var(--chart-1,teal)'],
];
const x=value=>230+value*450,pct=value=>(100*value).toFixed(2)+'%';
const dots=rows.map(([label,value,color],index)=>{
  const y=42+index*57;
  if(!value.trials)return `<text x="0" y="${y+4}">${label}</text><text x="238" y="${y+4}">не измерено</text>`;
  if(![value.accuracy,...value.ci95].every(n=>Number.isFinite(n)&&n>=0&&n<=1))throw Error('invalid_chart_measurement');
  const [left,right]=value.ci95.map(x),point=x(value.accuracy);
  return `<text x="0" y="${y+4}">${label}</text><path d="M${left} ${y-6}v12 M${left} ${y}H${right} M${right} ${y-6}v12" fill="none" stroke="${color}" stroke-width="2"/><circle cx="${point}" cy="${y}" r="5" fill="${color}"/><text x="230" y="${y+23}" class="detail">${value.correct}/${value.trials} · ${pct(value.accuracy)} · CI95 ${pct(value.ci95[0])}–${pct(value.ci95[1])}</text>`;
}).join('');
const axis=[0,.25,.5,.75,1].map(value=>`<path d="M${x(value)} 248v5" stroke="currentColor"/><text x="${x(value)}" y="270" text-anchor="middle" class="detail">${100*value}%</text>`).join('');
const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="710" height="315" viewBox="0 0 710 315" role="img" aria-label="Модельный top-1 приватных разговоров: исходный текст и выход Shield, development и held-out; интервалы 95 процентов"><style>svg{font:13px var(--font-sans,system-ui,sans-serif);color:var(--foreground,CanvasText)}text{fill:currentColor}.detail{font-size:11px;opacity:.8}.chance{fill:var(--destructive,crimson)}</style><path d="M${x(1/64)} 15V245" stroke="var(--destructive,crimson)" stroke-width="1.5" stroke-dasharray="4 4"/>${dots}<path d="M230 248H680" stroke="currentColor" opacity=".5"/>${axis}<text x="230" y="303" class="chance">Случайный top-1: 1/64 = 1,5625%</text></svg>`;
const html=`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{background:none;margin:0;padding:0}body{font:14px/1.5 var(--font-sans,system-ui,sans-serif);color:var(--foreground,CanvasText)}figure{margin:0}svg{width:100%;height:315px;display:block}figcaption{font-size:12px;opacity:.8;margin-top:8px}</style><figure>${svg}<figcaption>Точки — top-1 модельного оценщика на одних и тех же приватных отправленных разговорах с двумя валидными атаками; линии — точные CI95. Held-out: измерено ${held.measured_cases}/360, неизвестно ${held.unmeasured.length}. Показатели условны на измеренной части. Первоначальный протокол исполнения нарушен; приёмка не подтверждена.</figcaption></figure></html>`;
await writeFile(join(base,'linkcheck.svg'),svg+'\n',{flag:'wx'});
await writeFile(join(base,'chart.html'),html+'\n',{flag:'wx'});
console.log('recorded_linkcheck_chart_written');
