// Publication only. No model calls or threshold selection.
import {readFile,readdir,writeFile} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {artifactHash} from './evaluation-artifacts.mjs';
import {validateLinkcheckMeasurement} from './linkcheck-report.mjs';
import {summarizeLinkcheck,chanceComparison} from './linkcheck-statistics.mjs';
import {verifyFrozenProvenance} from './linkcheck-experiment.mjs';
import {phaseMetrics} from './linkcheck-turn-accounting.mjs';
import {continuationPartition} from './linkcheck-continuation.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),base=join(root,'docs/evaluations/shield-linkcheck-task5');
const json=async path=>JSON.parse(await readFile(path,'utf8'));
const pct=value=>value===null?'не измерено':(value*100).toFixed(2)+'%';
const stats=value=>!value.trials?'не измерено':`${value.correct}/${value.trials} (${pct(value.accuracy)}), CI95 [${value.ci95.map(pct).join('; ')}], p=${value.pvalue_greater===0?'<1e-300':value.pvalue_greater.toPrecision(4)}`;
function tablePhase(name,report,corpus,planned,unknown){
  const rows=[];
  for(const language of ['all','en','ru','hy']){
    const measured=report.observations.filter(r=>language==='all'||r.language===language),allCases=planned.cases.filter(c=>language==='all'||c.language===language);
    const local=measured.filter(r=>r.local_turns>0).length,missing=unknown.filter(r=>language==='all'||planned.cases.find(c=>c.id===r.id).language===language).length;
    const useful=measured.filter(r=>r.utility===true).length;
    rows.push(`| ${name}/${language} | ${measured.length}/${allCases.length} | ${local}/${allCases.length}; ${pct(local/allCases.length)}–${pct((local+missing)/allCases.length)} | ${measured.filter(r=>r.blocked_turns>0).length} | ${measured.filter(r=>r.error).length} | ${useful}/${allCases.length} (${pct(useful/allCases.length)}) | ${measured.filter(r=>r.remote_turns>0).length} | ${missing} |`);
  }
  return rows;
}
function markdown(frozen,report,development,devCorpus,corpus){
  const lines=['# Shield/linkcheck: один проход без изменения порогов','',
    '**Приёмка защиты не подтверждена.** Это локальное исследование синтетических EN/RU/HY данных, не зелёный CI. Исходный замороженный протокол исполнения был нарушен из-за перегрузки памяти и недостаточного общего таймера; все отклонения и неизмеренные случаи сохранены. См. [RUN_NOTES.md](RUN_NOTES.md), ADR 0086/0087.','',
    `Пороги: top_k=${frozen.policy.shield.linkcheck.top_k}, max_margin=${frozen.policy.shield.linkcheck.max_margin}; после начала held-out не менялись. Embedding: Qwen3-Embedding-0.6B Q8_0. Защита, настоящие ответы и модельный экстрактор фактов: Qwen2.5-7B Q4_K_M. Точные executable/model SHA — в freeze.json. Source commit бинарников не аттестован (null), измерение не приписывается текущему HEAD. Default production не меняется.`,
    '', '## Данные и порядок','',
    'Development — 384 завершённых разговора; восемь исходных частей проверены и объединены. Freeze создан до генерации held-out. Затем новый случайный seed и отдельные словари шести осей, биографии, nonce и формулировки арифметических задач дали 360 разговоров: 24 на каждую пару трёх языков и пяти групп. Проверено нулевое буквальное пересечение фактов, секретов и полных вопросов с development. Это разделение сущностей и текста в узком генераторе, не независимая внешняя выборка реальных людей.',
    `Из held-out полностью измерено ${report.observations.length}/360. ${report.unmeasured.length} позиций после остановки первых координаторов или дальнейших сбоев оставлены неизвестными, включая консервативный буфер. Их egress, канарейки и исход атаки не предполагаются нулевыми. Только ещё не начатые ID исполнялись новым координатором, два процесса, до 12 разговоров в части. Точный план выбран без просмотра точности и полезности, зафиксирован отдельным amendment. Повторов разговоров нет.`,
    'Production Engine формирует настоящие ShapedRequest; выход перехватывается в памяти. Ответ L0 и симулированного провайдера даёт настоящая модель. Внешних запросов, аккаунтов, OS pcap и реального досье нет. Полезность узкая: каждый настоящий ответ разговора должен точно совпасть с заранее заданным целым числом. Сохранение слов задачи в переписывании полезностью не считается.',
    '', '## L0, отказы и полезность','',
    'L0 — разговоры хотя бы с одним принятым локальным ответом; могут пересекаться с ранее отправленными ходами. Неудавшаяся генерация без ответа учитывается как отказ отдельно. Диапазон учитывает неизвестные случаи. Полезность в таблице — подтверждённая нижняя доля: полезные ответы делятся на все planned разговоры, неизвестные не улучшают оценку. Отправка означает раскрытие запроса, включая ошибку ответа; раскрытие и отказ могут пересекаться. Число попыток — успешные ответы плюс отказы, не сумма раскрытий и ответов. Операторские прерывания показаны отдельно и не выдаются за отказы Shield.','',
    '| Часть/язык | Измерено/planned | Разговоры с L0; границы доли | Отказы | Ошибки | Полезные ответы/planned | Отправлено, разговоры | Неизмерено |',
    '|---|---:|---:|---:|---:|---:|---:|---:|'];
  lines.push(...tablePhase('development',development,devCorpus,devCorpus,[]),...tablePhase('held-out',report,corpus,corpus,report.unmeasured));
  lines.push('',`Held-out, измеренные ходы: L0 ${report.phase_metrics.l0_turns}, удалённые ${report.phase_metrics.remote_turns}, отказы ${report.phase_metrics.refused_turns}, не начаты после отказа ${report.phase_metrics.unattempted_turns}. Во всём planned held-out ${corpus.cases.reduce((n,c)=>n+c.turns.length,0)} ходов; для неизмеренных случаев ходовые исходы неизвестны.`,
    '', '## Связываемость','',
    'Случайный top-1 = 1/64 = 1,5625%. Основной показатель — модельный top-1 приватных отправленных разговоров. Единица — весь накопленный разговор, а не ход. Модель выделяет наблюдаемые факты, код ранжирует 64 досье без доступа к subject; отдельно работает literal matcher. L0, отказы и неизвестные атаки не становятся промахами оценщика.',
    'Приведены точные двусторонние Clopper–Pearson CI95 и односторонний binomial p для превышения 1/64 (α=0,05). Разрезы описательные, p без поправки на множественность. Отсутствие значимости не доказывает равенство случайной точности. Интервалы условны на измеренной части искусственного генератора.','',
    '| Часть/оценщик/язык | Исходный приватный текст | Все отправленные | Приватные отправленные | Статус |',
    '|---|---|---|---|---|');
  for(const [name,item]of [['development',development],['held-out',report]])for(const [attacker,summary]of Object.entries(item.analysis.attackers))for(const language of ['all','en','ru','hy']){
    const result=language==='all'?summary.all:summary.by_language[language];
    lines.push(`| ${name}/${attacker}/${language} | ${stats(result.raw_private)} | ${stats(result.top1)} | ${stats(result.private_top1)} | ${result.chance_gate} |`);
  }
  const primary=report.analysis.attackers.model.all;
  lines.push('',`Неизмеренные позиции могут изменить результат. Дополнительный консервативный сценарий предполагает, что все ${report.unmeasured.length} неизвестных разговоров были приватными отправленными и оценщик ошибся во всех них: ${stats(report.analysis.privacy_best_case_for_missing)}. Это анализ границы, не восстановленные наблюдения.`,
    '', '## Ограничения и вывод','',
    `Development уже не прошёл проверку: модельный top-1 приватного выхода 6/33 против 1/64. Held-out, измеренная часть: ${stats(primary.private_top1)}; статус ${primary.chance_gate}.`,
    `Канареек среди измеренных outgoing: ${primary.canary_leaks}; отсутствие канареек в ${report.unmeasured.length} неизвестных случаях не установлено. Невалидные модельные атаки: outgoing ${primary.invalid_attacks}, исходные приватные ${primary.raw_private.invalid}; дополнительно неизмеренные случаи не заменяются угадыванием.`,
    'Исходные raw-атаки калибруются отдельно в каждом языке/приватной группе; полные разрезы находятся в JSON. Публичные контрольные задачи не разбавляют приватную проверку. Literal-only результат, all-L0 и широкие интервалы не доказывают защиту. Любые unmeasured/uncalibrated/invalid статусы сохраняются.',
    'Подкачка, пауза/остановка первого запуска и дополнительные холодные старты ограничивают сравнение полезности и ошибок как свойств одной модели. Отчёт не объявляет выполненной приёмку SPEC, даже если отдельная статистическая проверка не отвергает случайный уровень. Корпус шаблонный и малый; вероятности анонимности реального человека здесь нет.',
    'После этого просмотра held-out становится регрессией. Изменение порогов, защиты или моделей требует нового development и нового, ещё не просмотренного held-out. В этой задаче изменения защиты по результатам не делались.','',
    'Свидетельства: development.json, held-out.json, freeze.json, infrastructure-amendment.json, attempts/, fragments/ и manifest корпуса. Сырые ответы модели и промпты в отчёт не сохраняются.','');
  return lines.join('\n');
}
export async function collectOnePass(){
  const frozen=await json(join(base,'freeze.json')),amendment=await json(join(base,'infrastructure-amendment.json'));
  const freezeHash=await artifactHash(join(base,'freeze.json')),amendmentHash=await artifactHash(join(base,'infrastructure-amendment.json'));
  const publication=await json(join(base,'publication-spec-v2.json')),originalPublication=await json(join(base,'publication-spec.json'));
  if(publication.reporter_sha256!==await artifactHash(fileURLToPath(import.meta.url))||publication.amendment_sha256!==amendmentHash||publication.statistics_sha256!==frozen.scripts['scripts/linkcheck-statistics.mjs']||
    publication.previous_spec_sha256!==await artifactHash(join(base,'publication-spec.json'))||originalPublication.reporter_sha256!==await artifactHash(join(base,'archive/publication-reporter-v1.mjs.txt'))||
    publication.turn_accounting_sha256!==await artifactHash(join(root,'scripts/linkcheck-turn-accounting.mjs')))throw Error('publication_protocol_changed');
  const corpus=await json(join(root,'tests/models/privacy-v3-held-out.json')),manifest=await json(join(root,'tests/models/privacy-v3-held-out.manifest.json'));
  if(amendment.freeze_sha256!==freezeHash||manifest.freeze_sha256!==freezeHash||manifest.sha256!==await artifactHash(join(root,'tests/models/privacy-v3-held-out.json'))||amendment.source_sha256!==await artifactHash(join(root,'scripts/linkcheck-continuation.mjs')))throw Error('amended_experiment_identity_changed');
  for(const [path,sha]of Object.entries(frozen.scripts))if(await artifactHash(join(root,path))!==sha)throw Error('frozen_protocol_changed');
  const observations=[],sources=[],initial=[],unmeasured=[...amendment.unmeasured],claimed=new Set();
  for(const source of amendment.initial_fragments){
    const path=join(base,'fragments',source.file);if(await artifactHash(path)!==source.sha256)throw Error('initial_fragment_changed');
    const part=await json(path);initial.push(part);verifyFrozenProvenance(part.provenance,frozen);
    if(!isDeepStrictEqual(part.scope.policy,frozen.policy))throw Error('initial_policy_changed');
    observations.push(...part.observations);sources.push({file:source.file,sha256:source.sha256});
  }
  const originalPlan=continuationPartition(corpus,initial);
  if(!isDeepStrictEqual(originalPlan.observed,amendment.observed)||!isDeepStrictEqual(originalPlan.pending,amendment.pending)||!isDeepStrictEqual(originalPlan.unmeasured,amendment.unmeasured))throw Error('continuation_selection_changed');
  for(const chunk of amendment.chunks){
    const filename=`continuation-${chunk.index}.json`,path=join(base,'fragments',filename),part=await json(path);
    if(!['complete','failed'].includes(part.status)||part.amendment_sha256!==amendmentHash||part.start!==chunk.start||part.end!==chunk.end||part.observations.length>chunk.end-chunk.start)throw Error('continuation_not_settled_or_changed');
    verifyFrozenProvenance(part.inference_provenance,frozen);
    const attempt=join(base,'attempts',filename);if(part.attempt_sha256!==await artifactHash(attempt))throw Error('continuation_attempt_changed');
    for(let i=chunk.start;i<chunk.end;i++){if(claimed.has(i))throw Error('repeated_conversation_attempt');claimed.add(i);}
    for(const [offset,row]of part.observations.entries())validateLinkcheckMeasurement(row,corpus.cases[chunk.start+offset],64);
    observations.push(...part.observations);
    for(let i=chunk.start+part.observations.length;i<chunk.end;i++)unmeasured.push({id:corpus.cases[i].id,reason:'continuation_failure_not_retried',possible_egress:'unknown'});
    sources.push({file:filename,sha256:await artifactHash(path),attempt_sha256:part.attempt_sha256});
  }
  observations.sort((a,b)=>a.id.localeCompare(b.id));unmeasured.sort((a,b)=>a.id.localeCompare(b.id));
  const ids=[...observations.map(r=>r.id),...unmeasured.map(r=>r.id)];
  if(ids.length!==360||new Set(ids).size!==360||observations.length<300)throw Error('one_pass_incomplete_or_too_small');
  const knownCorpus={...corpus,cases:corpus.cases.filter(c=>observations.some(r=>r.id===c.id))};
  const model=summarizeLinkcheck(observations,{candidates:64}),literal=summarizeLinkcheck(observations.map(r=>({...r,attack:r.literal_attack,raw_attack:r.raw_literal_attack})),{candidates:64});
  const report={version:1,status:'completed_with_protocol_deviation_and_unmeasured_cases',partition:'held_out',synthetic_only:true,
    planned_cases:360,measured_cases:observations.length,freeze_sha256:freezeHash,amendment_sha256:amendmentHash,
    publication_spec_sha256:await artifactHash(join(base,'publication-spec-v2.json')),
    scope:{external_requests:false,local_answers_stubbed:false,provider_answers:'real local model, simulated provider',policy:frozen.policy,inference_provenance:frozen.expected_provenance,one_pass:true,original_protocol_fulfilled:false},
    observations,unmeasured,sources,
    analysis:{acceptance:'not_accepted',attackers:{model,literal},privacy_best_case_for_missing:chanceComparison(model.all.private_top1.correct,model.all.private_top1.trials+unmeasured.length,64)},
    phase_metrics:phaseMetrics({observations},knownCorpus)};
  return {report,frozen,corpus};
}
async function main(){
  if(process.argv.length!==2)throw Error('usage_linkcheck_one_pass_report');
  const {report,frozen,corpus}=await collectOnePass();
  await writeFile(join(base,'held-out.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  await writeFile(join(base,'REPORT.md'),markdown(frozen,report,await json(join(base,'development.json')),await json(join(root,'tests/models/privacy-v3-dev.json')),corpus),{flag:'wx'});
  console.log(JSON.stringify({measured:report.measured_cases,unmeasured:report.unmeasured.length,model:report.analysis.attackers.model.all,literal:report.analysis.attackers.literal.all}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
