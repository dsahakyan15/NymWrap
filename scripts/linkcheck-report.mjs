import {summarizeLinkcheck} from './linkcheck-statistics.mjs';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {artifactHash} from './evaluation-artifacts.mjs';
import {shardRange} from './linkcheck-shards.mjs';
import {knownEmbedding} from './linkcheck-embeddings.mjs';
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const counter=value=>Number.isSafeInteger(value)&&value>=0&&value<=1000000000;
// Complete measurement is a prerequisite for statistics, not a declaration that
// privacy, held-out blinding or an implementation milestone has passed.
export function validateLinkcheckReport(report,corpus,corpusHash,{allowShard=false}={}){
  const shard=report?.shard;
  const range=shard?shardRange(corpus?.cases?.length,shard.index,shard.count):{start:0,end:corpus?.cases?.length};
  if(shard&&(!allowShard||JSON.stringify(shard)!==JSON.stringify(range)))throw Error('invalid_linkcheck_shard_scope');
  if(report?.version!==3||report.sample!==undefined||report.status!==(shard?'complete_shard':'complete')||!hash(corpusHash)||report.provenance?.corpus_sha256!==corpusHash||
    corpus?.version!==3||!corpus.synthetic_only||corpus.candidates!==64||report.partition!==corpus.partition||
    !Array.isArray(report.observations)||report.case_count!==corpus.cases?.length||report.observations.length!==range.end-range.start||
    report.scope?.external_requests!==false||report.scope?.local_answers_stubbed!==false||report.scope?.provider_answers!=='real local model, simulated provider')throw Error('incomplete_or_incompatible_linkcheck_report');
  for(const key of ['client_sha256','defender_worker_sha256','attacker_worker_sha256','model_sha256','attacker_model_sha256','embedding_sha256','config_sha256','evaluator_script_sha256','report_script_sha256','statistics_sha256','shard_script_sha256','embedding_catalog_sha256'])if(!hash(report.provenance[key]))throw Error('missing_linkcheck_provenance');
  if(!knownEmbedding(report.provenance.embedding_sha256,report.provenance.embedding_recipe_id,report.provenance.embedding_dimension))throw Error('unknown_linkcheck_embedding_recipe');
  for(const [i,row]of report.observations.entries()){
    const expected=corpus.cases[range.start+i];
    if(row.id!==expected.id||row.language!==expected.language||row.group!==expected.group||!counter(row.elapsed_ms)||
      !row.calls||['ner','canonicalize','generalize','embeddings','answers','errors'].some(k=>!counter(row.calls[k]))||
      !Array.isArray(row.calls.linkage_ranks)||row.calls.linkage_ranks.length<row.remote_turns||row.calls.linkage_ranks.length>expected.turns.length*2||
      row.calls.linkage_ranks.some(rank=>!counter(rank.candidates)||rank.candidates<51||rank.candidates>257||!counter(rank.rank_min)||rank.rank_min<1||!counter(rank.rank_max)||rank.rank_max<rank.rank_min||rank.rank_max>rank.candidates||
        !Number.isInteger(rank.user_score)||Math.abs(rank.user_score)>1000000||!Number.isInteger(rank.best_decoy_score)||Math.abs(rank.best_decoy_score)>1000000||
        !Number.isInteger(rank.background_score)||Math.abs(rank.background_score)>1000000||typeof rank.risky!=='boolean')||
      !Array.isArray(row.local_reasons)||row.local_reasons.some(r=>r!==null&&!['entity_verification_unavailable','missing_dossier','verification_unavailable','generalization_failed','independent_split_unavailable'].includes(r))||
      row.local_turns+row.remote_turns>expected.turns.length||row.local_reasons.length>expected.turns.length||
      row.utility!==null&&row.local_reasons.length!==expected.turns.length||
      row.remote_turns===0&&row.literal_attack!==null)throw Error('invalid_linkcheck_measurement');
  }
  return range;
}
export function summarizeLinkcheckReport(report,corpus,corpusHash){
  validateLinkcheckReport(report,corpus,corpusHash);
  const model=summarizeLinkcheck(report.observations,{candidates:corpus.candidates});
  const literal=summarizeLinkcheck(report.observations.map(row=>({...row,attack:row.literal_attack,raw_attack:row.raw_literal_attack})),{candidates:corpus.candidates});
  return {partition:report.partition,acceptance:'not_evaluated_requires_frozen_held_out_provenance',
    utility_scope:corpus.utility_scope,attackers:{model,literal},
    canary_findings:report.observations.filter(r=>r.canary_leaks).map(r=>r.id),
    review_cases:report.observations.filter(r=>r.attack?.top1_correct||r.literal_attack?.top1_correct).map(r=>r.id)};
}
export function checkDevelopmentReport(report,corpus,corpusHash){
  const summary=summarizeLinkcheckReport(report,corpus,corpusHash);
  if(report.partition!=='development'||report.case_count<300)throw Error('development_measurement_too_small');
  for(const result of Object.values(summary.attackers)){
    if(result.all.canary_leaks||result.all.chance_gate!=='passes_test'||
      Object.values(result.by_language).some(language=>language.chance_gate!=='passes_test')||
      Object.entries(result.by_group).some(([group,subset])=>group!=='public_control'&&
        (subset.raw_private.invalid||subset.raw_private.no_significant_excess!==false))||
      Object.values(result.by_language_group).some(subsets=>Object.entries(subsets).some(([group,subset])=>group!=='public_control'&&
        (subset.raw_private.invalid||subset.raw_private.no_significant_excess!==false))))throw Error('development_linkcheck_quality_gate_failed');
  }
  return summary;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length!==3)throw Error('usage_linkcheck_report_complete_development_json');
  const corpusPath=new URL('../tests/models/privacy-v3-dev.json',import.meta.url),corpusHash=await artifactHash(corpusPath);
  const report=JSON.parse(await readFile(resolve(process.argv[2]),'utf8')),corpus=JSON.parse(await readFile(corpusPath,'utf8'));
  const summary=checkDevelopmentReport(report,corpus,corpusHash);
  console.log(JSON.stringify({status:'development_checks_passed',held_out:false,acceptance:summary.acceptance,model:summary.attackers.model.all,literal:summary.attackers.literal.all}));
}
