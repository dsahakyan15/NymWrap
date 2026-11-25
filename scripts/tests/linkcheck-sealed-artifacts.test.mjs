// Integrity/recalculation only. CI must not silently rerun an exposed held-out.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {artifactHash} from '../evaluation-artifacts.mjs';
import {generateHeldOutCorpus,verifyIndependentSplit} from '../generate-linkcheck-held-out.mjs';
import {validateLinkcheckMeasurement} from '../linkcheck-report.mjs';
import {summarizeLinkcheck,chanceComparison} from '../linkcheck-statistics.mjs';
import {verifyFrozenProvenance} from '../linkcheck-experiment.mjs';
import {phaseMetrics} from '../linkcheck-turn-accounting.mjs';
import {pairedLinkcheck} from '../linkcheck-paired-report.mjs';
import {collectOnePass} from '../linkcheck-one-pass-report.mjs';
import {recoveryPartition} from '../linkcheck-recovery.mjs';
const root=new URL('../../',import.meta.url),at=path=>new URL(path,root);
const json=async path=>JSON.parse(await readFile(at(path),'utf8'));
const base='docs/evaluations/shield-linkcheck-task5/';
function equalStatistics(actual,expected,key=''){
  if(typeof actual==='number'&&typeof expected==='number'){
    if(Number.isInteger(actual)&&Number.isInteger(expected)){assert.equal(actual,expected);return;}
    const tolerance=key==='pvalue_greater'?1e-10*Math.max(1e-300,Math.abs(actual),Math.abs(expected)):1e-12;
    assert.ok(Math.abs(actual-expected)<=tolerance,'recorded statistical value changed');return;
  }
  if(actual&&expected&&typeof actual==='object'&&typeof expected==='object'){
    assert.deepEqual(Object.keys(actual).sort(),Object.keys(expected).sort());
    for(const name of Object.keys(actual))equalStatistics(actual[name],expected[name],name);
    return;
  }
  assert.equal(actual,expected);
}
test('sealed split and freeze bind the unchanged policy, code, actual case data and eight one-pass attempts',async()=>{
  const frozen=await json(base+'freeze.json'),freezeHash=await artifactHash(at(base+'freeze.json'));
  const manifest=await json('tests/models/privacy-v3-held-out.manifest.json');
  const devCorpus=await json('tests/models/privacy-v3-dev.json'),heldCorpus=await json('tests/models/privacy-v3-held-out.json');
  assert.equal(manifest.freeze_sha256,freezeHash);
  assert.ok(Date.parse(frozen.created_utc)<=Date.parse(manifest.generated_utc));
  assert.equal(await artifactHash(at('tests/models/privacy-v3-dev.json')),frozen.development_corpus_sha256);
  assert.equal(await artifactHash(at('tests/models/privacy-v3-held-out.json')),manifest.sha256);
  assert.equal(await artifactHash(at(base+'development.json')),frozen.development_sha256);
  for(const [path,sha]of Object.entries(frozen.scripts))assert.equal(await artifactHash(at(path)),sha);
  assert.deepEqual(heldCorpus,generateHeldOutCorpus(heldCorpus.seed));
  assert.deepEqual(verifyIndependentSplit(devCorpus,heldCorpus),manifest.independence);
  const policyHash=createHash('sha256').update(JSON.stringify(frozen.policy)+'\n').digest('hex');
  assert.equal(policyHash,frozen.expected_provenance.config_sha256);
  assert.equal(frozen.inference_source_commit,null);
  assert.equal(frozen.policy.shield.linkcheck.top_k,3);assert.equal(frozen.policy.shield.linkcheck.max_margin,.03);
  for(let index=0;index<8;index++){
    const attempt=await json(base+`attempts/held-shard-${index}.json`);
    assert.equal(attempt.freeze_sha256,freezeHash);assert.equal(attempt.corpus_sha256,manifest.sha256);
    assert.equal(attempt.shard,index);assert.equal(attempt.reruns_allowed,false);
    assert.ok(Date.parse(manifest.generated_utc)<=Date.parse(attempt.started_utc));
  }
});
test('published held-out observations recalculate without dropping refusals, L0, errors or either attacker',async()=>{
  const frozen=await json(base+'freeze.json'),manifest=await json('tests/models/privacy-v3-held-out.manifest.json');
  const corpus=await json('tests/models/privacy-v3-held-out.json'),report=await json(base+'held-out.json');
  // Reconstruct from the original fragment bytes and exclusive attempt receipts.
  // Comparing only derived statistics would miss edited or omitted observations.
  equalStatistics(report,(await collectOnePass()).report);
  assert.equal(report.freeze_sha256,await artifactHash(at(base+'freeze.json')));
  assert.equal(report.scope.one_pass,true);assert.equal(report.scope.original_protocol_fulfilled,false);assert.deepEqual(report.scope.policy,frozen.policy);
  verifyFrozenProvenance(report.scope.inference_provenance,frozen);
  for(const row of report.observations)validateLinkcheckMeasurement(row,corpus.cases.find(c=>c.id===row.id),64);
  equalStatistics(summarizeLinkcheck(report.observations,{candidates:64}),report.analysis.attackers.model);
  equalStatistics(summarizeLinkcheck(report.observations.map(row=>({...row,attack:row.literal_attack,raw_attack:row.raw_literal_attack})),{candidates:64}),report.analysis.attackers.literal);
  const known={...corpus,cases:corpus.cases.filter(c=>report.observations.some(r=>r.id===c.id))};
  assert.deepEqual(phaseMetrics(report,known),report.phase_metrics);
  const ids=[...report.observations.map(r=>r.id),...report.unmeasured.map(r=>r.id)];
  assert.equal(ids.length,360);assert.equal(new Set(ids).size,360);assert.ok(report.observations.length>=300);
  assert.ok(report.unmeasured.every(r=>r.possible_egress==='unknown'));
  assert.equal(report.analysis.acceptance,'not_accepted');
  const primary=report.analysis.attackers.model.all.private_top1;
  equalStatistics(report.analysis.privacy_best_case_for_missing,chanceComparison(primary.correct,primary.trials+report.unmeasured.length,64));
  for(const source of report.sources)assert.equal(source.sha256,await artifactHash(at(base+'fragments/'+source.file)));
  const amendment=await json(base+'infrastructure-amendment.json');
  assert.equal(amendment.source_sha256,await artifactHash(at('scripts/linkcheck-continuation.mjs')));
  assert.equal(report.amendment_sha256,await artifactHash(at(base+'infrastructure-amendment.json')));
  const recovery=await json(base+'host-restart-amendment.json'),priorClaims=new Map();
  assert.equal(recovery.source_sha256,await artifactHash(at('scripts/linkcheck-recovery.mjs')));
  assert.equal(recovery.original_amendment_sha256,report.amendment_sha256);
  assert.equal(recovery.freeze_sha256,report.freeze_sha256);
  assert.equal(recovery.outcome_based_selection,false);
  assert.equal(recovery.restart_evidence_sha256,await artifactHash(at(base+'host-restart.json')));
  assert.equal(recovery.frozen_chunk_bridge_sha256,createHash('sha256').update(await readFile(at('scripts/linkcheck-continuation.mjs'),'utf8')).update('\nexport { verifyBase, identities, chunkRun };\n').digest('hex'));
  for(const source of recovery.prior_claims){
    const settlement=recovery.settlements.find(item=>item.file===source.file),part=await json(base+'fragments/'+source.file);
    priorClaims.set(Number(source.file.match(/continuation-(\d+)\.json/)[1]),part);
    assert.equal(source.attempt_sha256,await artifactHash(at(base+'attempts/'+source.file)));
    assert.equal(await artifactHash(at(base+'fragments/'+source.file)),settlement?.after_sha256??source.fragment_sha256);
    if(settlement){
      assert.equal(settlement.before_sha256,source.fragment_sha256);
      assert.equal(settlement.before_sha256,await artifactHash(at(base+'archive/'+settlement.archive)));
      assert.deepEqual((await json(base+'archive/'+settlement.archive)).observations,part.observations);
      assert.equal(part.status,'failed');assert.equal(part.failure_code,'host_restart');
    }
  }
  assert.deepEqual(recoveryPartition(amendment.chunks,priorClaims,corpus),{pending:recovery.pending,unmeasured:recovery.unmeasured});
  const recoveryAttempt=await json(base+'attempts/host-restart-coordinator.json');
  assert.equal(recoveryAttempt.plan_sha256,await artifactHash(at(base+'host-restart-amendment.json')));
  assert.equal(recoveryAttempt.reruns_allowed,false);
  const publication=await json(base+'publication-spec-v2.json');
  assert.equal(publication.reporter_sha256,await artifactHash(at('scripts/linkcheck-one-pass-report.mjs')));
  assert.equal(publication.previous_spec_sha256,await artifactHash(at(base+'publication-spec.json')));
  const previous=await json(base+'publication-spec.json');
  assert.equal(previous.reporter_sha256,await artifactHash(at(base+'archive/publication-reporter-v1.mjs.txt')));
  assert.equal(publication.turn_accounting_sha256,await artifactHash(at('scripts/linkcheck-turn-accounting.mjs')));
  assert.equal(report.publication_spec_sha256,await artifactHash(at(base+'publication-spec-v2.json')));
  const paired=await json(base+'paired.json'),pairedSpec=await json(base+'paired-spec.json');
  assert.equal(pairedSpec.source_sha256,await artifactHash(at('scripts/linkcheck-paired-report.mjs')));
  equalStatistics(paired.phases.held_out,pairedLinkcheck(report.observations));
  equalStatistics(paired.phases.development,pairedLinkcheck((await json(base+'development.json')).observations));
});
