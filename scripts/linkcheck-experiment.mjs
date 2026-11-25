// Local synthetic experiment: completed development -> freeze -> one held-out pass.
import {readFile,writeFile,mkdir,readdir,lstat} from 'node:fs/promises';
import {createHash,randomBytes} from 'node:crypto';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {artifactHash} from './evaluation-artifacts.mjs';
import {summarizeLinkcheckReport,validateLinkcheckReport} from './linkcheck-report.mjs';
import {mergeShardReports} from './linkcheck-merge.mjs';
import {main as evaluate} from './linkcheck-eval.mjs';
import {generateHeldOutCorpus,verifyIndependentSplit,heldOutPlan} from './generate-linkcheck-held-out.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const output=join(root,'docs/evaluations/shield-linkcheck-task5');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=async path=>JSON.parse(await readFile(path,'utf8'));
const writeOnce=(path,value)=>writeFile(path,JSON.stringify(value,null,2)+'\n',{flag:'wx'});
export async function claimHeldOutAttempt(path,record){
  if(record.reruns_allowed!==false||record.shards!==8||!Number.isSafeInteger(record.shard)||record.shard<0||record.shard>=8)throw Error('invalid_held_out_attempt');
  await writeOnce(path,record);
}
const developmentPath=join(output,'development.json');
const corpusPath=join(root,'tests/models/privacy-v3-dev.json');
const frozenPath=join(output,'freeze.json');
const heldPath=join(root,'tests/models/privacy-v3-held-out.json');
const manifestPath=join(root,'tests/models/privacy-v3-held-out.manifest.json');
const inferenceKeys=['client_sha256','defender_worker_sha256','attacker_worker_sha256','model_sha256','attacker_model_sha256','embedding_sha256','config_sha256','embedding_catalog_sha256','embedding_recipe_id','embedding_dimension','model','attacker_model','platform','arch'];
const protocolFiles=['scripts/linkcheck-eval.mjs','scripts/linkcheck-experiment.mjs','scripts/generate-linkcheck-held-out.mjs','scripts/linkcheck-report.mjs','scripts/linkcheck-statistics.mjs','scripts/linkcheck-shards.mjs','scripts/linkcheck-merge.mjs','scripts/linkcheck-embeddings.mjs'];
async function regular(path,maximum=64*1024*1024){const info=await lstat(path);if(info.isSymbolicLink()||!info.isFile()||info.size>maximum)throw Error('unsafe_experiment_artifact');return path;}
export function validateFreezeDevelopment(report,corpus,corpusHash){
  validateLinkcheckReport(report,corpus,corpusHash);
  if(corpus.partition!=='development'||corpus.cases.length<300)throw Error('freeze_requires_complete_development');
  const policy=report.scope.policy;
  if(!policy||hash(JSON.stringify(policy)+'\n')!==report.provenance.config_sha256)throw Error('freeze_policy_identity_mismatch');
  const summary=summarizeLinkcheckReport(report,corpus,corpusHash);
  // A failing defence may be measured, never relabelled a passing candidate.
  // The raw attackers must still demonstrate actual ability in every stratum.
  for(const attacker of Object.values(summary.attackers))for(const groups of Object.values(attacker.by_language_group))for(const [group,result]of Object.entries(groups)){
    if(group!=='public_control'&&(result.raw_private.invalid||result.raw_private.no_significant_excess!==false))throw Error('freeze_requires_calibrated_raw_attackers');
  }
  return summary;
}
export function verifyFrozenProvenance(provenance,frozen){
  for(const [key,value]of Object.entries(frozen.expected_provenance))if(provenance[key]!==value)throw Error('frozen_inference_changed');
}
async function protocolIdentity(){return Object.fromEntries(await Promise.all(protocolFiles.map(async name=>[name,await artifactHash(join(root,name))])));}
async function freeze(){
  const corpus=await json(corpusPath),development=await json(developmentPath),corpusHash=await artifactHash(corpusPath);
  const summary=validateFreezeDevelopment(development,corpus,corpusHash);
  const suffix=process.platform==='win32'?'.exe':'';
  for(const [name,key]of [[`target/release/examples/privacy_linkcheck${suffix}`,'client_sha256'],[`target/release/nw-llmd${suffix}`,'defender_worker_sha256']]){
    if(await artifactHash(await regular(join(root,name)))!==development.provenance[key])throw Error('development_binary_not_retained');
  }
  const scripts=await protocolIdentity(),p=development.provenance;
  const expected=Object.fromEntries(inferenceKeys.map(key=>[key,p[key]]));
  Object.assign(expected,{evaluator_script_sha256:scripts['scripts/linkcheck-eval.mjs'],report_script_sha256:scripts['scripts/linkcheck-report.mjs'],statistics_sha256:scripts['scripts/linkcheck-statistics.mjs'],shard_script_sha256:scripts['scripts/linkcheck-shards.mjs']});
  const result={version:1,created_utc:new Date().toISOString(),synthetic_only:true,
    decision:'measure_existing_candidate_without_threshold_tuning; development quality failed',
    development_sha256:await artifactHash(developmentPath),development_corpus_sha256:corpusHash,
    policy:development.scope.policy,expected_provenance:expected,scripts,held_out_plan:heldOutPlan,
    selection:'Retain the measured top_k=3/max_margin=0.03 and Qwen candidate, including its negative development outcome; no search or production-default change.',
    inference_source_commit:null,inference_identity:'retained executable SHA-256, not a claim that the current source head produced these binaries',
    inference_development_provenance:p,
    development_outcome:{model:summary.attackers.model.all,literal:summary.attackers.literal.all},
    protocol:{one_attempt_per_conversation:true,resume:false,regenerate:false,confidence:0.95,alpha:0.05,chance:1/64,
      unit:'whole conversation, cumulative provider-visible history',utility:corpus.utility_scope,
      primary_endpoint:'model private top-1 on outgoing conversations',subgroup_tests:'descriptive unadjusted p-values; no population-anonymity claim',
      refusal:'blocked turns; errors reported separately; missing attacks and L0 never count as incorrect attacker guesses',
      inference_scope:'production Engine in the retained evaluator; final L0 and provider-simulation answers from the real local model; no external requests',
      acceptance:'report negative or inconclusive outcomes; no significance is not evidence of equality or population anonymity'}};
  await mkdir(output,{recursive:true});await writeOnce(frozenPath,result);
  console.log(JSON.stringify({freeze:await artifactHash(frozenPath),policy:result.policy.shield.linkcheck,development_cases:corpus.cases.length}));
}
async function readFreeze(){
  const frozen=await json(await regular(frozenPath)),freezeHash=await artifactHash(frozenPath);
  if(frozen.version!==1||frozen.synthetic_only!==true||!isDeepStrictEqual(frozen.held_out_plan,heldOutPlan)||
    await artifactHash(developmentPath)!==frozen.development_sha256||await artifactHash(corpusPath)!==frozen.development_corpus_sha256||
    !isDeepStrictEqual(await protocolIdentity(),frozen.scripts)||hash(JSON.stringify(frozen.policy)+'\n')!==frozen.expected_provenance.config_sha256)throw Error('frozen_experiment_changed');
  return {frozen,freezeHash};
}
async function generate(){
  const {frozen,freezeHash}=await readFreeze();
  const corpus=generateHeldOutCorpus(randomBytes(32).toString('hex'));
  const independence=verifyIndependentSplit(await json(corpusPath),corpus);
  const bytes=JSON.stringify(corpus)+'\n';
  await writeFile(heldPath,bytes,{flag:'wx'});
  await writeOnce(manifestPath,{version:1,partition:'held_out',synthetic_only:true,generated_utc:new Date().toISOString(),freeze_sha256:freezeHash,
    sha256:hash(bytes),generator_sha256:frozen.scripts['scripts/generate-linkcheck-held-out.mjs'],plan:heldOutPlan,independence});
  console.log(JSON.stringify({held_out_generated:true,cases:360,sha256:hash(bytes),freeze_sha256:freezeHash}));
}
async function heldOut(){
  const result=await readFreeze(),manifest=await json(await regular(manifestPath));
  if(manifest.freeze_sha256!==result.freezeHash||manifest.sha256!==await artifactHash(await regular(heldPath))||manifest.generator_sha256!==result.frozen.scripts['scripts/generate-linkcheck-held-out.mjs'])throw Error('held_out_generation_changed');
  const corpus=await json(heldPath),independence=verifyIndependentSplit(await json(corpusPath),corpus);
  if(!isDeepStrictEqual(independence,manifest.independence))throw Error('held_out_independence_changed');
  return {...result,manifest,corpus};
}
async function run(index){
  const {frozen,freezeHash,manifest}=await heldOut();
  if(!Number.isSafeInteger(index)||index<0||index>=heldOutPlan.shards)throw Error('invalid_held_out_shard');
  const attempts=join(output,'attempts');await mkdir(attempts,{recursive:true});
  const attemptPath=join(attempts,`held-shard-${index}.json`);
  const attempt={version:1,freeze_sha256:freezeHash,corpus_sha256:manifest.sha256,shard:index,shards:heldOutPlan.shards,started_utc:new Date().toISOString(),reruns_allowed:false};
  // Exclusive, durable and committed with the report. A crash consumes the
  // attempt too; no --resume or hidden retry of a difficult conversation.
  await claimHeldOutAttempt(attemptPath,attempt);
  const p=frozen.expected_provenance;
  await evaluate(['--model',p.model,'--attacker',p.attacker_model,'--embedding','qwen3-0.6b-q8_0','--shard',`${index}/${heldOutPlan.shards}`],
    {corpusPath:heldPath,manifest,policy:frozen.policy,expectedProvenance:p,freezeHash,attemptHash:await artifactHash(attemptPath)});
}
export function phaseMetrics(report,corpus){
  const rows=report.observations,turns=corpus.cases.reduce((n,c)=>n+c.turns.length,0);
  const count=key=>rows.reduce((n,r)=>n+r[key],0);
  return {cases:rows.length,turns,remote_turns:count('remote_turns'),l0_turns:count('local_turns'),refused_turns:count('blocked_turns'),
    unattempted_turns:turns-count('remote_turns')-count('local_turns')-count('blocked_turns'),
    l0_only_cases:rows.filter(r=>r.local_turns>0&&r.remote_turns===0).length,l0_case_fraction:rows.filter(r=>r.local_turns>0).length/rows.length,
    l0_turn_fraction:count('local_turns')/turns,
    by_language:Object.fromEntries(heldOutPlan.languages.map(language=>[language,{cases:rows.filter(r=>r.language===language).length,
      l0_turns:rows.filter(r=>r.language===language).reduce((n,r)=>n+r.local_turns,0),turns:corpus.cases.filter(c=>c.language===language).reduce((n,c)=>n+c.turns.length,0)}]))};
}
const pct=value=>value===null?'не измерено':(value*100).toFixed(2)+'%';
const comparison=value=>!value.trials?'не измерено':`${value.correct}/${value.trials} (${pct(value.accuracy)}); 95% [${value.ci95.map(pct).join('; ')}]; p=${value.pvalue_greater===0?'<1e-300':value.pvalue_greater.toPrecision(4)}`;
function markdown(frozen,freezeHash,development,held,devCorpus,heldCorpus){
  const text=['# Shield/linkcheck: один замороженный held-out прогон','',
    'Все данные синтетические, EN/RU/HY. Внешних запросов, аккаунтов и настоящего досье нет. Это локальное измерение, не зелёный CI и не закрытие этапа.','',
    `Пороги заморожены до создания held-out: top_k=${frozen.policy.shield.linkcheck.top_k}, max_margin=${frozen.policy.shield.linkcheck.max_margin}. Embedding — Qwen3-Embedding-0.6B Q8_0; защита, ответы и модельный экстрактор — Qwen2.5-7B Q4_K_M. Настройки после held-out не менялись. Freeze SHA-256: \`${freezeHash}\`.`,
    '', '## Протокол и независимость','',
    'Development — 384 ранее завершённых случая. Восемь исходных частей проверены и объединены без подмены бинарников или условий. До freeze проверены сохранённые executable SHA. Source commit этих бинарников не аттестован; измерение относится к их точным SHA, а не к сборке текущего HEAD.',
    'Held-out — 360 новых разговоров: по 24 в каждой из 15 пар язык/группа, 64 досье на разговор. После freeze взята новая случайность; словарь всех шести осей, биографии, секреты и формулировки задач отделены от development. Нулевое пересечение буквальных фактов, секретов и полных вопросов проверено кодом. Это разделение сущностей и текстов внутри одной узкой искусственной задачи, не независимая внешняя выборка людей.',
    'Каждый разговор исполнен один раз. Восемь частей делят целые разговоры, не историю. Эксклюзивные attempt receipts запрещают повтор и resume. Production Engine, настоящий локальный worker и полная накопленная история; provider заменён настоящей локальной генерацией. Текст на выходе перехватывается в памяти до провайдера, это не OS pcap.',
    'Два оценщика: модель выделяет факты, детерминированный код ранжирует 64 досье; отдельно literal matcher. Индекс субъекта недоступен ранжированию. L0 и отказы не считаются ошибками атакующего. Полезность — все реальные ответы разговора должны точно совпасть с заранее заданными целыми числами; это не оценка произвольных ответов.',
    '', '## Результаты','',
    '| Часть / язык | Случаи | L0, ходы / все ходы | Отказы, разговоры | Ошибки, разговоры | Полезные ответы, разговоры | Отправлено, разговоры |',
    '|---|---:|---:|---:|---:|---:|---:|'];
  for(const [name,report,corpus]of [['development',development,devCorpus],['held-out',held,heldCorpus]]){
    const summary=report.analysis.attackers.model,metrics=phaseMetrics(report,corpus);
    for(const language of ['all',...heldOutPlan.languages]){
      const result=language==='all'?summary.all:summary.by_language[language];
      const m=language==='all'?{l0_turns:metrics.l0_turns,turns:metrics.turns}:metrics.by_language[language];
      text.push(`| ${name} / ${language} | ${result.cases} | ${m.l0_turns}/${m.turns} (${pct(m.l0_turns/m.turns)}) | ${result.blocked_cases} | ${result.errors} | ${result.useful_answers}/${result.cases} (${pct(result.useful_fraction)}) | ${result.remote_cases} |`);
    }
    text.push('',`${name}: полностью локальных разговоров ${metrics.l0_only_cases}/${metrics.cases}; разговоров с хотя бы одним L0 ${pct(metrics.l0_case_fraction)}; отказавших ходов ${metrics.refused_turns}; не начатых после отказа ходов ${metrics.unattempted_turns}. Ошибки могут пересекаться с L0/отказами; числа не складываются в разбиение.`, '');
  }
  text.push('## Связываемость относительно случайной','',
    'Случайный top-1 = 1/64 = 1,5625%. Единица — разговор. Основной показатель — модельный top-1 приватных отправленных разговоров. Указаны точные Clopper–Pearson 95% интервалы и односторонний binomial p для превышения 1/64, α=0,05; разрезы описательные, p без поправки на множественные сравнения. Отсутствие значимости не доказывает равенство случайной точности. Публичные задачи и группы доступны отдельно в полном JSON; широкие интервалы и отсутствие исходящих приватных запросов оставляют оценку неопределённой.','',
    '| Часть / оценщик / язык | Исходный приватный текст | Все отправленные разговоры | Приватные отправленные разговоры | Статус проверки |',
    '|---|---|---|---|---|');
  for(const [name,report]of [['development',development],['held-out',held]])for(const [attacker,summary]of Object.entries(report.analysis.attackers))for(const language of ['all',...heldOutPlan.languages]){
    const result=language==='all'?summary.all:summary.by_language[language];
    text.push(`| ${name} / ${attacker} / ${language} | ${comparison(result.raw_private)} | ${comparison(result.top1)} | ${comparison(result.private_top1)} | ${result.chance_gate} |`);
  }
  text.push('', '## Ограничения и вывод','',
    `Канареек: development ${development.analysis.attackers.model.all.canary_leaks}, held-out ${held.analysis.attackers.model.all.canary_leaks}. Невалидные исходящие модельные атаки held-out: ${held.analysis.attackers.model.all.invalid_attacks}; исходные приватные: ${held.analysis.attackers.model.all.raw_private.invalid}.`,
    'Уже development не прошёл проверку: модельный оценщик связывал приватные отправленные разговоры значимо лучше случайного. Пороги намеренно сохранены для честного подтверждающего измерения, а не подобраны под held-out. Защита не объявляется принятой независимо от результата literal matcher.',
    'Арифметика, шаблонные факты и закрытый набор из 64 вымышленных людей не моделируют произвольную биографию, смысловую полезность или реальную популяционную анонимность. Исправления и новая настройка требуют development и нового, ещё не просмотренного held-out; этот набор после отчёта может служить только регрессией.',
    '', 'Полные числовые наблюдения, разрезы по группам и исходные SHA: development.json, held-out.json, freeze.json, attempts/, manifest корпуса. Сырые ответы модели и промпты в отчёт не записываются.','');
  return text.join('\n');
}
async function report(){
  const {frozen,freezeHash,manifest,corpus}=await heldOut();
  const base=join(root,'target/linkcheck-eval'),sources=[];
  for(const name of await readdir(base))if(/^held-out-.*-shard-\d+-of-8\.json$/.test(name)){
    const path=join(base,name),part=await json(await regular(path,4*1024*1024));if(part.scope?.freeze_sha256!==freezeHash)continue;
    verifyFrozenProvenance(part.provenance,frozen);
    const attempt=join(output,'attempts',`held-shard-${part.shard?.index}.json`);
    if(part.attempt_sha256!==await artifactHash(await regular(attempt,65536)))throw Error('missing_original_held_out_attempt');
    sources.push({report:part,sha256:await artifactHash(path)});
  }
  if(sources.length!==8)throw Error('held_out_pass_incomplete');
  const combined=mergeShardReports(sources,corpus,manifest.sha256);
  combined.freeze_sha256=freezeHash;combined.attempts=sources.map(s=>({index:s.report.shard.index,sha256:s.report.attempt_sha256})).sort((a,b)=>a.index-b.index);
  combined.analysis.acceptance='not_accepted; negative development candidate; inspect held-out statistics and calibration';
  combined.phase_metrics=phaseMetrics(combined,corpus);
  await writeOnce(join(output,'held-out.json'),combined);
  const development=await json(developmentPath);
  await writeFile(join(output,'REPORT.md'),markdown(frozen,freezeHash,development,combined,await json(corpusPath),corpus),{flag:'wx'});
  console.log(JSON.stringify({complete:true,cases:360,freeze_sha256:freezeHash,model:combined.analysis.attackers.model.all,literal:combined.analysis.attackers.literal.all}));
}
export async function main(args=process.argv.slice(2)){
  if(args.length===1&&args[0]==='freeze')return freeze();
  if(args.length===1&&args[0]==='generate')return generate();
  if(args.length===2&&args[0]==='run'&&/^[0-7]$/.test(args[1]))return run(Number(args[1]));
  if(args.length===1&&args[0]==='report')return report();
  throw Error('usage_linkcheck_experiment_freeze_generate_run_0_to_7_or_report');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
