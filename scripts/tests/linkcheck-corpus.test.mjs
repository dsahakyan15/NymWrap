import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {generateDevelopmentCorpus} from '../generate-linkcheck-corpus.mjs';
test('fictional conversations are reproducible, contain 64 distinct dossiers and accumulate all six facts',()=>{
  const seed='37'.repeat(32),corpus=generateDevelopmentCorpus(seed,60);
  assert.deepEqual(corpus,generateDevelopmentCorpus(seed,60));
  assert.notDeepEqual(corpus.cases[0],generateDevelopmentCorpus('38'.repeat(32),1).cases[0]);
  assert.equal(corpus.partition,'development');assert.equal(corpus.synthetic_only,true);
  const groups=new Set(),languages=new Set();
  for(const c of corpus.cases){
    groups.add(c.group);languages.add(c.language);
    assert.equal(c.profiles.length,64);assert.equal(new Set(c.profiles.map(p=>p.facts.join('|'))).size,64);
    const profile=c.profiles[c.subject],input=c.turns.map(t=>t.text).join('\n');
    for(const fact of profile.facts)assert.equal(input.includes(fact),c.group!=='public_control');
    if(c.group==='linkage_multiturn'){assert.equal(c.turns.length,2);assert.ok(!c.turns[0].text.includes(profile.facts[4]));}
    for(const t of c.turns)assert.ok(Number.isInteger(t.expected_answer)&&t.expected_answer>0);
    for(const p of c.profiles){assert.match(p.personal_secret,/^SYNTHETIC_PRIVATE_[a-f0-9]{32}$/);assert.match(p.device_secret,/^SYNTHETIC_DEVICE_[a-f0-9]{32}$/);}
  }
  assert.equal(groups.size,5);assert.equal(languages.size,3);
  for(const [seed,size]of [['bad',1],['00'.repeat(32),0],['00'.repeat(32),1025]])assert.throws(()=>generateDevelopmentCorpus(seed,size));
});
test('the committed development corpus is hashed, reproducible, multilingual and never labelled held-out',async()=>{
  const bytes=await readFile(new URL('../../tests/models/privacy-v3-dev.json',import.meta.url));
  const manifest=JSON.parse(await readFile(new URL('../../tests/models/privacy-v3-dev.manifest.json',import.meta.url),'utf8'));
  const hash=value=>createHash('sha256').update(value).digest('hex');
  assert.equal(hash(bytes),manifest.sha256);
  assert.equal(hash(await readFile(new URL('../generate-linkcheck-corpus.mjs',import.meta.url))),manifest.generator_sha256);
  const corpus=JSON.parse(bytes);assert.equal(corpus.partition,'development');assert.equal(corpus.cases.length,384);
  assert.deepEqual(corpus,generateDevelopmentCorpus(corpus.seed));
  for(const [language,count]of Object.entries(manifest.languages))assert.equal(corpus.cases.filter(c=>c.language===language).length,count);
});
