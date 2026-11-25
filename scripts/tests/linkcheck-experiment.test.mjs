import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateHeldOutCorpus,verifyIndependentSplit} from '../generate-linkcheck-held-out.mjs';
import {claimHeldOutAttempt,verifyFrozenProvenance,validateFreezeDevelopment} from '../linkcheck-experiment.mjs';
import {phaseMetrics} from '../linkcheck-turn-accounting.mjs';
import {artifactHash} from '../evaluation-artifacts.mjs';
import {continuationPartition} from '../linkcheck-continuation.mjs';

test('generator validation seeds are reproducible and entity/text-disjoint from development in every EN/RU/HY stratum',async()=>{
  // Throwaway unit-test seeds, never used for the real sealed experiment.
  const dev=JSON.parse(await readFile(new URL('../../tests/models/privacy-v3-dev.json',import.meta.url),'utf8'));
  const generated=generateHeldOutCorpus('a1'.repeat(32));
  assert.deepEqual(generated,generateHeldOutCorpus('a1'.repeat(32)));
  assert.notDeepEqual(generated.cases[0].profiles,generateHeldOutCorpus('a2'.repeat(32)).cases[0].profiles);
  const audit=verifyIndependentSplit(dev,generated);assert.equal(audit.held_out_cases,360);
  assert.equal(Object.keys(audit.strata).length,15);assert.ok(Object.values(audit.strata).every(n=>n===24));
  for(const item of generated.cases){
    assert.equal(item.profiles.length,64);assert.equal(new Set(item.profiles.map(p=>p.facts.join('|'))).size,64);
    const input=item.turns.map(t=>t.text).join('\n');
    for(const fact of item.profiles[item.subject].facts)assert.equal(input.includes(fact),item.group!=='public_control');
    assert.ok(item.turns.every(t=>Number.isInteger(t.expected_answer)&&t.expected_answer>0));
  }
  for(const mutate of [
    v=>v.seed=dev.seed,v=>v.cases[0].id=dev.cases[0].id,
    v=>v.cases[0].profiles[0].facts[0]=dev.cases[0].profiles[0].facts[0],
    v=>v.cases[0].profiles[0].personal_secret=dev.cases[0].profiles[0].personal_secret,
    v=>v.cases[0].turns[0].text=dev.cases[0].turns[0].text,v=>v.cases.pop(),
  ]){const bad=structuredClone(generated);mutate(bad);assert.throws(()=>verifyIndependentSplit(dev,bad));}
});
test('a held-out attempt is exclusive even after a crash, and inference thresholds cannot change',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'nw-once-'));
  try{
    const path=join(directory,'attempt.json'),record={shard:0,shards:8,reruns_allowed:false};
    await claimHeldOutAttempt(path,record);await assert.rejects(()=>claimHeldOutAttempt(path,record),{code:'EEXIST'});
    await assert.rejects(()=>claimHeldOutAttempt(join(directory,'bad.json'),{...record,reruns_allowed:true}));
    const keys=['client_sha256','defender_worker_sha256','attacker_worker_sha256','model_sha256','attacker_model_sha256','embedding_sha256','config_sha256','embedding_catalog_sha256','embedding_recipe_id','embedding_dimension','model','attacker_model','platform','arch'];
    const provenance=Object.fromEntries(keys.map(k=>[k,'fixed'])),frozen={expected_provenance:provenance};
    verifyFrozenProvenance({...provenance},frozen);
    for(const key of keys)assert.throws(()=>verifyFrozenProvenance({...provenance,[key]:'changed'},frozen));
  }finally{await rm(directory,{recursive:true,force:true});}
});
test('a measured failing development candidate can be frozen for an honest negative study; weak attackers cannot',async()=>{
  const corpusUrl=new URL('../../tests/models/privacy-v3-dev.json',import.meta.url);
  const corpus=JSON.parse(await readFile(corpusUrl,'utf8'));
  const report=JSON.parse(await readFile(new URL('../../docs/evaluations/shield-linkcheck-task5/development.json',import.meta.url),'utf8'));
  const sha=await artifactHash(corpusUrl);
  assert.equal(validateFreezeDevelopment(report,corpus,sha).attackers.model.all.chance_gate,'failed');
  const changed=structuredClone(report);changed.scope.policy.shield.linkcheck.max_margin=.04;
  assert.throws(()=>validateFreezeDevelopment(changed,corpus,sha));
  const weak=structuredClone(report);for(const row of weak.observations){row.raw_attack={valid:true,top1_correct:false};}
  assert.throws(()=>validateFreezeDevelopment(weak,corpus,sha),/calibrated/);
  const metrics=phaseMetrics(report,corpus);
  assert.equal(metrics.turns,metrics.attempted_turns+metrics.unattempted_turns);
  assert.ok(metrics.unattempted_turns>=0);
  assert.ok(metrics.l0_turn_fraction>0&&metrics.l0_turn_fraction<1);
});
test('continuation partitions only unstarted IDs; interrupted and buffered positions are never retried',async()=>{
  const corpus=JSON.parse(await readFile(new URL('../../tests/models/privacy-v3-held-out.json',import.meta.url),'utf8'));
  const sources=await Promise.all(Array.from({length:8},async(_,i)=>JSON.parse(await readFile(new URL(`../../docs/evaluations/shield-linkcheck-task5/fragments/initial-${i}.json`,import.meta.url),'utf8'))));
  const plan=continuationPartition(corpus,sources);
  const all=[...plan.observed,...plan.unmeasured.map(r=>r.id),...plan.pending];
  assert.equal(all.length,360);assert.equal(new Set(all).size,360);
  assert.equal(plan.unmeasured.length,16);assert.equal(plan.observed.length+plan.pending.length,344);
  for(const item of plan.unmeasured)assert.equal(item.possible_egress,'unknown');
  for(const mutate of [s=>s.pop(),s=>s[1].shard.index=0,s=>s[0].observations[0].id='held_9999']){
    const bad=structuredClone(sources);mutate(bad);assert.throws(()=>continuationPartition(corpus,bad));
  }
});
