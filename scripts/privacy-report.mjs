// Reports fixed synthetic measurements, never a probability of anonymity for a person.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {artifactHash} from './evaluation-artifacts.mjs';
const sum=(items,key)=>items.reduce((n,o)=>n+o[key],0);
const attacks=items=>({attempts:items.length,correct:items.filter(a=>a.correct).length,invalid:items.filter(a=>!a.valid).length,abstained:items.filter(a=>a.valid&&a.abstained).length,literal_links:items.filter(a=>a.unique_literal_link).length});
export function summarize(report){
  if(report.version!==2||report.status!=='complete'||!Array.isArray(report.observations)||!Number.isSafeInteger(report.case_count)||report.case_count<1||report.observations.length!==report.case_count)throw Error('incomplete_privacy_measurement');
  const observations=report.observations,ids=new Set();
  for(const o of observations){
    if(!/^[a-zA-Z0-9_]+$/.test(o.id)||ids.has(o.id)||!['local','blocked','egress_candidate'].includes(o.decision))throw Error('invalid_privacy_observation');ids.add(o.id);
    for(const key of ['ner_calls','model_errors','expected_entity_characters','hidden_entity_characters','unexpected_hidden_characters','task_terms','task_terms_retained','elapsed_ms','egress_turns','local_turns','blocked_turns'])if(!Number.isSafeInteger(o[key])||o[key]<0)throw Error('invalid_privacy_counter');
    for(const key of ['expected_local_only','ner_rejected','egress_gold_leak','policy_miss'])if(typeof o[key]!=='boolean')throw Error('invalid_privacy_flag');
    if(o.hidden_entity_characters>o.expected_entity_characters||o.task_terms_retained>o.task_terms||Boolean(o.egress_turns)!==(o.decision==='egress_candidate')||o.policy_miss!==(o.expected_local_only&&o.egress_turns>0))throw Error('inconsistent_privacy_observation');
    for(const a of [o.raw_attack,o.egress_attack])if(a!==null&&(!a||['valid','correct','abstained','unique_literal_link'].some(k=>typeof a[k]!=='boolean')||a.correct&&(!a.valid||a.abstained)||a.abstained&&!a.valid))throw Error('invalid_linkage_measurement');
    if(o.egress_attack!==null&&(o.raw_attack===null||!o.egress_turns))throw Error('unpaired_linkage_measurement');
  }
  const outbound=observations.filter(o=>o.egress_turns),paired=observations.filter(o=>o.egress_attack!==null),ner=observations.filter(o=>o.ner_calls),controls=observations.filter(o=>o.group==='public_control');
  return {
    cases:observations.length,
    outcomes:Object.fromEntries(['egress_candidate','local','blocked'].map(d=>[d,observations.filter(o=>o.decision===d).length])),
    outbound_turns:sum(outbound,'egress_turns'),
    gold_leak_cases:outbound.filter(o=>o.egress_gold_leak).length,
    gold_positive_outbound_cases:outbound.filter(o=>o.expected_entity_characters>0).length,
    incomplete_pre_rewrite_masks:outbound.filter(o=>o.hidden_entity_characters<o.expected_entity_characters).length,
    local_policy_misses:observations.filter(o=>o.policy_miss).length,
    expected_local_cases:observations.filter(o=>o.expected_local_only).length,
    ner:{cases:ner.length,calls:sum(ner,'ner_calls'),rejected_cases:ner.filter(o=>o.ner_rejected).length,model_errors:sum(observations,'model_errors')},
    controls:{cases:controls.length,outbound:controls.filter(o=>o.egress_turns).length,local:controls.filter(o=>o.decision==='local').length,blocked:controls.filter(o=>o.decision==='blocked').length,terms:sum(controls,'task_terms'),retained:sum(controls,'task_terms_retained')},
    attacks:{raw_all:attacks(observations.map(o=>o.raw_attack).filter(Boolean)),raw_paired:attacks(paired.map(o=>o.raw_attack)),outbound_paired:attacks(paired.map(o=>o.egress_attack)),no_outbound:observations.filter(o=>o.raw_attack!==null&&!o.egress_turns).length},
    duration_ms:sum(observations,'elapsed_ms'),
    findings:observations.filter(o=>o.egress_gold_leak||o.policy_miss||o.egress_attack?.correct||o.egress_attack?.unique_literal_link||o.egress_turns&&o.hidden_entity_characters<o.expected_entity_characters).map(o=>o.id),
  };
}
export function compare(reports){
  if(!Array.isArray(reports)||reports.length<1)throw Error('missing_privacy_measurement');
  const first=reports[0].provenance;
  for(const report of reports){
    for(const key of ['worker_sha256','client_sha256','corpus_sha256','model_sha256','embedding_sha256'])if(!/^[a-f0-9]{64}$/.test(report.provenance?.[key]))throw Error('missing_privacy_provenance');
    if(report.case_count!==reports[0].case_count||['worker_sha256','client_sha256','corpus_sha256','embedding_sha256','platform'].some(k=>report.provenance[k]!==first[k])||JSON.stringify(report.scope)!==JSON.stringify(reports[0].scope)||report.observations.some((o,i)=>o.id!==reports[0].observations[i]?.id))throw Error('incomparable_privacy_measurements');
  }
  return reports.map(report=>({model:report.provenance.model,provenance:report.provenance,summary:summarize(report)}));
}
export function validateNerReport(report,expected){
  if(report.corpus!=='synthetic-privacy-v1'||report.cases!==16||!Array.isArray(report.observations)||report.cases!==report.observations.length)throw Error('invalid_ner_report');
  for(const key of ['worker_sha256','client_sha256','corpus_sha256'])if(!/^[a-f0-9]{64}$/.test(report.provenance?.[key]))throw Error('invalid_ner_provenance');
  if(report.provenance.model!==expected.model||report.provenance.worker_sha256!==expected.worker_sha256||report.provenance.corpus_sha256!==expected.corpus_sha256||report.provenance.models?.[0]?.sha256!==expected.model_sha256)throw Error('incompatible_ner_report');
  for(const key of ['valid_responses','rejected_responses','model_errors','policy_false_negatives','policy_false_positives','unsafe_remote_cases','expected_entity_characters','hidden_entity_characters','unexpected_hidden_characters'])if(!Number.isSafeInteger(report[key])||report[key]<0)throw Error('invalid_ner_counter');
  if(report.hidden_entity_characters>report.expected_entity_characters||report.valid_responses+report.rejected_responses+report.model_errors!==report.cases)throw Error('inconsistent_ner_report');
  return report;
}
const escape=value=>String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
export function renderReport(comparison,browsers=[],nerReports=[]){
  const name=m=>m==='smoke'?'Qwen 0.5B (контроль)':m==='qwen2.5-7b-q4_k_m'?'Qwen 2.5 7B Q4_K_M':m;
  const candidate=comparison.find(r=>r.model==='qwen2.5-7b-q4_k_m')??comparison.at(-1),remaining=candidate.summary.attacks.outbound_paired;
  const headline=remaining.attempts?`После Shield уникальное сочетание фактов сохранилось в ${remaining.literal_links}/${remaining.attempts} исходящих кейсах. Модель выбрала верное досье в ${remaining.correct}/${remaining.attempts}; невалидных ответов ${remaining.invalid}.`:'В кейсах с досье исходящего текста не было; сравнение после Shield не проводилось.';
  const colors={egress_candidate:'var(--chart-1,#56b4e9)',local:'var(--chart-2,#8ac6a3)',blocked:'var(--chart-3,#e7b65a)'};
  const label={egress_candidate:'кандидат на выход',local:'только локально',blocked:'заблокирован'};
  const outcomes=comparison.map(({model,summary:s})=>`<div class="chart-row"><strong>${escape(name(model))}</strong><div class="stack" role="img" aria-label="${Object.entries(s.outcomes).map(([k,n])=>`${label[k]}: ${n}`).join('; ')}">${Object.entries(s.outcomes).filter(([,n])=>n).map(([k,n])=>`<span title="${label[k]}: ${n}" style="flex:${n};background:${colors[k]}">${n}</span>`).join('')}</div></div>`).join('');
  const rows=comparison.map(({model,summary:s})=>`<tr><th>${escape(name(model))}</th><td>${s.gold_leak_cases} / ${s.outcomes.egress_candidate}</td><td>${s.local_policy_misses} / ${s.expected_local_cases}</td><td>${s.ner.rejected_cases} / ${s.ner.cases}</td><td>${s.controls.outbound} / ${s.controls.cases}</td></tr>`).join('');
  const linkage=comparison.map(({model,summary:s})=>{
    const a=s.attacks,p=a.outbound_paired,raw=a.raw_paired;
    const bars=p.attempts?[[raw,'Исходный текст'],[p,'После Shield']].map(([a,l])=>`<div class="attack-row"><span>${l}</span><div class="track"><div class="fill" style="width:${100*a.correct/a.attempts}%"></div></div><strong>${a.correct}/${a.attempts}</strong></div>`).join(''):'<p>Нет пар для сравнения: исходящего текста в этих кейсах не было.</p>';
    const calibration=a.raw_all.correct*4<a.raw_all.attempts*3?'<p class="small notice">Атакующий плохо узнаёт даже исходный текст. Его неудачи после Shield дают мало сведений о защите.</p>':'';
    return `<article class="box"><h3>${escape(name(model))}</h3>${bars}<p class="small">Совпадения локальной модели среди тех же ${p.attempts} исходящих кейсов. Невалидные ответы: до ${raw.invalid}, после ${p.invalid}; отказ от выбора: после ${p.abstained}. Буквальное связывание по уникальному сочетанию: ${p.literal_links}/${p.attempts}.</p><p class="small">Калибровка на всех исходных кейсах: ${a.raw_all.correct}/${a.raw_all.attempts}, невалидных ${a.raw_all.invalid}. Ещё ${a.no_outbound} кейсов не имели исходящего текста и исключены из пар.</p>${calibration}</article>`;
  }).join('');
  const utility=comparison.map(({model,summary:s})=>`<li>${escape(name(model))}: на выход прошли ${s.controls.outbound}/${s.controls.cases} публичных задач; локально ${s.controls.local}, заблокировано ${s.controls.blocked}. Сохранилось ${s.controls.retained}/${s.controls.terms} заданных ключевых слов (буквальная проверка, не оценка качества ответа). Неполное маскирование размеченной сущности до canonicalize среди исходящих кейсов: ${s.incomplete_pre_rewrite_masks}. Это отдельный повод для проверки, даже если полное совпадение не найдено в финальном тексте.</li>`).join('');
  const provenance=comparison.map(({model,provenance:p,summary:s})=>`<details><summary>${escape(name(model))}: хеши и границы измерения</summary><p>Кейсов ${s.cases}; исходящих ходов ${s.outbound_turns}; вызовов NER ${s.ner.calls}; ошибок модели в конвейере ${s.ner.model_errors}. Суммарное время кейсов ${Math.round(s.duration_ms/60000)} мин, включая загрузку модели и атаки. Кандидаты с известными идентификаторами: ${s.gold_positive_outbound_cases}.</p><p>Кейсы с наблюдаемой утечкой или связыванием: ${escape(s.findings.join(', ')||'в этом наборе не обнаружены')}.</p><dl>${Object.entries(p).map(([k,v])=>`<dt>${escape(k)}</dt><dd><code>${escape(v)}</code></dd>`).join('')}</dl></details>`).join('');
  const browserRows=browsers.map(b=>`<tr><td>${escape(b.browser)}</td><td>${escape(b.status)}</td><td>${escape(b.scope)}</td></tr>`).join('');
  const publicProbe=browsers.find(b=>b.observations?.length===6);
  const publicRows=publicProbe?.observations.map(o=>{
    const state=o.navigation!=='loaded'?'Загрузка не подтверждена':o.challenge?'Challenge/вход: дальнейших действий нет':o.origin==='https://adssettings.google.com'?'Анонимная страница; темы аккаунта недоступны':o.search_state==='ready'?'Поле поиска распознано; запрос не отправлялся':o.composer_count?'Элементы ввода есть; отправка не проверялась':'Загружена страница; функции не проверены';
    return `<tr><td>${escape(o.requested_origin)}</td><td>${escape(o.path??'—')}</td><td>${escape(state)}${o.requested_origin==='https://www.youtube.com'?'; карточек: '+Number(o.mirror_title_count):''}</td></tr>`;
  }).join('')??'';
  const nerRows=nerReports.map(r=>`<tr><td>${escape(name(r.provenance.model))}</td><td>${r.valid_responses}/${r.cases}</td><td>${r.rejected_responses}</td><td>${r.model_errors}</td><td>${r.hidden_entity_characters}/${r.expected_entity_characters}</td></tr>`).join('');
  const nerSection=nerRows?`<details><summary>Отдельная проверка NER на базовых 16 кейсах</summary><div class="table"><table><thead><tr><th>Модель</th><th>Валидный ответ</th><th>Отвергнуто</th><th>Ошибки</th><th>Скрыто символов сущностей</th></tr></thead><tbody>${nerRows}</tbody></table></div><p class="small">Вызов NER принудителен даже для L0; coverage включает исходные детерминированные маски. Это базовый диагностический корпус, без canonicalize/выхода. Валидный JSON не означает полноту распознавания.</p></details>`:'';
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NymWrap — измерения защиты</title><style>
  :root{font-family:var(--font-sans,system-ui,sans-serif);color:var(--foreground,#334155);font-size:14px;line-height:1.5}*{box-sizing:border-box}body{margin:0}h2{font-size:19px;margin:22px 0 10px}h3{font-size:15px;margin:0 0 10px}p{margin:8px 0}.small,summary{font-size:12px;color:var(--muted-foreground,#64748b)}.box{padding:16px;border:1px solid var(--border,#cbd5e1);border-radius:var(--radius,10px);margin:12px 0}.notice{border-left:4px solid var(--warning,#b7791f);padding-left:12px}.chart-row{margin:14px 0}.chart-row strong{font-size:13px}.stack{display:flex;height:34px;border-radius:5px;overflow:hidden;margin-top:5px}.stack span{display:flex;align-items:center;justify-content:center;color:#12202f;font-weight:700;font-size:12px}.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{text-align:left;vertical-align:top;padding:9px 6px;border-bottom:1px solid var(--border,#cbd5e1)}.table{overflow:auto}th{font-weight:600}.attack-row{display:flex;align-items:center;gap:9px;margin:9px 0;font-size:12px}.attack-row>span{width:106px;flex-shrink:0}.track{height:17px;flex:1;background:var(--secondary,#e2e8f0);border-radius:3px;overflow:hidden}.fill{height:17px;background:var(--chart-4,#cb6686)}.attack-row strong{min-width:34px}details{padding:10px 0;border-bottom:1px solid var(--border,#cbd5e1)}summary{cursor:pointer}dl{font-size:11px}dt{font-weight:600}dd{margin:0 0 7px;overflow-wrap:anywhere}li{margin:8px 0}@media(max-width:480px){td,th{padding:7px 4px}.legend{gap:8px}}
  </style></head><body><p class="notice"><strong>${headline}</strong><br>Это не процент вашей анонимности. Измерен только текстовый конвейер на ${comparison[0].summary.cases} вымышленных примерах, с локальным атакующим и восемью вымышленными профилями. Вход в аккаунт, API-ключ, IP, оплата, браузерный отпечаток и сильный внешний атакующий здесь не проверяются.</p>
  <h2>Что произошло с запросами</h2><p class="small">Сначала реальный Engine: minimize → NER → canonicalize → leakcheck → штатное формирование запроса в перехватчик памяти. Внешней отправки нет. Ответ перехватчика и финальный ответ L0 — заглушки.</p>${outcomes}<div class="legend">${Object.entries(label).map(([k,l])=>`<span><i style="background:${colors[k]}"></i>${l}</span>`).join('')}</div>
  <h2>Утечки и цена ограничений</h2><p class="small">В ходе разработки этот корпус выявил медицинскую тему, ошибочно разрешённую моделью, и пропущенное составное имя. Добавлены детерминированные ограничения (ADR 0040/0042). Здесь — полные повторные замеры исправленной версии; прежние отрицательные результаты сохранены отдельно.</p><div class="table"><table><thead><tr><th>Модель</th><th>Известный идентификатор в выходе / исходящие кейсы</th><th>Нарушение L0 / чувствительные кейсы</th><th>Отвергнутая NER / кейсы с NER</th><th>Публичная задача на выход / контроль</th></tr></thead><tbody>${rows}</tbody></table></div><p class="small">Проверка идентификаторов использует тот же детерминированный matcher, включая кодировки; это не независимый поиск любых смысловых утечек. Отказы и L0 показаны отдельно, не считаются успешной анонимизацией. NER вызывается только там, где её допускает политика: таблица не измеряет полноту NER на всём корпусе.</p><ul>${utility}</ul>
  ${nerSection}<h2>Можно ли связать косвенные признаки</h2><p class="small">Атакующий выбирает один из восьми профилей по трём пересекающимся признакам. Есть одиночные и двухходовые запросы. Факты из досье заранее не добавлены в список секретов. Измеряется связывание описанного человека с известным досье, а не установление автора произвольного сообщения. Сравнение «до / после» использует только кейсы, где был исходящий текст; отсутствие выхода не засчитывается как ошибка атакующего.</p>${linkage}
  <h2>Реальные браузеры</h2><div class="table"><table><thead><tr><th>Браузер</th><th>Результат</th><th>Границы</th></tr></thead><tbody>${browserRows}</tbody></table></div><p class="small">Фикстуры проверяют расширение и остановки; публичный DOM проверяет доступность элементов без аккаунтов. Они не доказывают работу персонализированной ленты, анонимность аккаунта или скрытие автоматизации.</p>
  ${publicRows?`<details><summary>Живые публичные страницы: результаты по сервисам</summary><p class="small">${escape(publicProbe.browser)}, ${escape(publicProbe.checked_at)}. Входа, поиска, сообщений и обхода проверок не было.</p><div class="table"><table><thead><tr><th>Сервис</th><th>Путь</th><th>Наблюдение</th></tr></thead><tbody>${publicRows}</tbody></table></div></details>`:''}
  <h2>Воспроизводимость</h2><p class="small">Фиксированный регрессионный корпус использован при разработке; независимой выборки нет. Нулевые счётчики не дают гарантии для новых запросов. strict/paranoid требуют просмотра каждого выхода; L0 оставляет запрос на устройстве.</p>${provenance}</body></html>`;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),base=join(root,'target/privacy-eval');
  const reports=await Promise.all(['smoke','qwen2.5-7b-q4_k_m'].map(id=>readFile(join(base,'pipeline-'+id+'.json'),'utf8').then(JSON.parse)));
  const comparison=compare(reports),browsers=[],nerReports=[];
  for(const file of ['chromium.json','firefox.json','firefox-native.json','live-firefox.json','live-public.json']){
    try{browsers.push(JSON.parse(await readFile(join(root,'target/browser-tests/reports',file),'utf8')));}catch(e){if(e.code!=='ENOENT')throw e;}
  }
  const nerCorpus=await artifactHash(join(root,'tests/models/privacy-v1.json'));
  for(const report of reports){const id=report.provenance.model;
    try{const r=JSON.parse(await readFile(join(base,'ner-'+id+'.json'),'utf8'));nerReports.push(validateNerReport(r,{model:id,worker_sha256:report.provenance.worker_sha256,model_sha256:report.provenance.model_sha256,corpus_sha256:nerCorpus}));}catch(e){if(e.code!=='ENOENT')throw e;}
  }
  if(nerReports.some(r=>r.provenance.client_sha256!==nerReports[0].provenance.client_sha256))throw Error('incomparable_ner_evaluators');
  await mkdir(base,{recursive:true});await writeFile(join(base,'summary.json'),JSON.stringify({version:1,scope:reports[0].scope,comparison,ner_reports:nerReports,browsers},null,2)+'\n');
  await writeFile(join(base,'report.html'),renderReport(comparison,browsers,nerReports));console.log('Privacy report: target/privacy-eval/report.html');
}
