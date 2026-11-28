import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {options,successfulVet,parseExemptions,checkExemptions,manifests} from '../vet-dependencies.mjs';
import {validateTool} from '../pinned-tools.mjs';
test('a failed, partial, unlisted-exemption or missing vet result cannot turn the dependency gate green',()=>{
  const passed={conclusion:'success',vetted_fully:['synthetic'],vetted_partially:[],vetted_with_exemptions:[]};
  const exempted={...passed,vetted_with_exemptions:[{name:'synthetic',version:'1.0.0'}]};
  assert.equal(successfulVet(0,passed),true);
  assert.equal(successfulVet(0,exempted,new Set(['synthetic@1.0.0'])),true);
  for(const [code,result,allowed] of [[1,passed],[0,null],[0,{}],[0,{error:'synthetic failure'}],[0,{...passed,conclusion:'fail (vetting)'}],
    [0,{...passed,failures:[]}],[0,{...passed,vetted_partially:['synthetic']}],[0,{...passed,vetted_with_exemptions:['synthetic']}],
    [0,exempted],[0,exempted,new Set(['synthetic@1.0.1'])],[0,exempted,new Set(['other@1.0.0'])],[0,{...passed,vetted_with_exemptions:null},new Set()]])
    assert.equal(successfulVet(code,result,allowed),false);
});
const entry=(name,version,notes='ADR 0111: synthetic accepted risk.',criteria='safe-to-deploy',quote='"')=>
  `[[exemptions.${name}]]\nversion = "${version}"\ncriteria = "${criteria}"\nnotes = ${quote}${notes}${quote}\n`;
test('exemptions pass only as exact allowlisted versions with an ADR 0111 note',()=>{
  const config='[cargo-vet]\nversion = "0.10"\n\n[policy.synthetic]\naudit-as-crates-io = false\nnotes = "ADR 0109"\n\n'+
    entry('alpha','1.0.0')+'\n'+entry('beta','0.2.0+native-1','ADR 0111 literal note',undefined,"'");
  assert.deepEqual(parseExemptions(config).map(e=>e.name+'@'+e.version),['alpha@1.0.0','beta@0.2.0+native-1']);
  assert.equal(checkExemptions(config,['beta@0.2.0+native-1','alpha@1.0.0']).size,2);
  assert.equal(checkExemptions('[cargo-vet]\nversion = "0.10"\n',[]).size,0);
  for(const [text,allowlist] of [
    [config,['alpha@1.0.0']],                                   // new unaudited crate not in allowlist
    [config,['alpha@1.0.0','beta@0.2.0+native-1','gamma@1.0.0']],  // allowlist must match the config exactly
    [config,['alpha@1.0.1','beta@0.2.0+native-1']],             // version change revokes the entry
    [config,['alpha@1.0.0','alpha@1.0.0','beta@0.2.0+native-1']],
    [config,undefined],[config,{}],
    [entry('alpha','1.0.0','ADR 0073 only'),['alpha@1.0.0']],
    [entry('alpha','1.0.0','ADR 01110 typo'),['alpha@1.0.0']],
    [entry('alpha','1.0.0',undefined,'safe-to-run'),['alpha@1.0.0']],
    [entry('alpha','1.0.0')+entry('alpha','1.0.0'),['alpha@1.0.0']],
    ['[[exemptions.alpha]]\nversion = "1.0.0"\ncriteria = "safe-to-deploy"\n',['alpha@1.0.0']],
  ])assert.throws(()=>checkExemptions(text,allowlist),/adr_0111/);
  for(const text of ['[exemptions]\nalpha = []\n','exemptions.alpha = []\n','[[exemptions."alpha"]]\n',
    '[[exemptions.alpha]]\nversion = "*"\nsuggest = false\n',entry('alpha','1.0.0').replace('version','version = "2.0.0"\nversion')])
    assert.throws(()=>parseExemptions(text));
});
test('committed stores contain exactly the committed ADR 0111 allowlist',()=>{
  const allowlist=JSON.parse(readFileSync(new URL('../../supply-chain/exemptions-allowlist.json',import.meta.url),'utf8'));
  assert.deepEqual(Object.keys(allowlist).filter(k=>Object.hasOwn(manifests,k)),Object.keys(manifests));
  assert.deepEqual(allowlist.fuzz,[]);
  for(const scope of Object.keys(manifests))
    checkExemptions(readFileSync(new URL(`../../supply-chain/${scope}/config.toml`,import.meta.url),'utf8'),allowlist[scope]);
});
test('vet scopes and import refresh are explicit and cannot become arbitrary commands',()=>{
  assert.deepEqual(options([]),{scopes:['root','desktop','netd','fuzz'],update:false});
  assert.deepEqual(options(['netd','--update-imports']),{scopes:['netd'],update:true});
  for(const args of [['root','root'],['root','netd'],['--update-imports','--update-imports'],['--regenerate-exemptions'],['--certify'],['../private']])
    assert.throws(()=>options(args));
});
test('pinned tool identities reject archive traversal, malformed hashes and unsupported platforms',()=>{
  const tool={version:'0.10.4',repository:'mozilla/cargo-vet'},platform={archive:'synthetic.zip',sha256:'a'.repeat(64),member:'synthetic/tool.exe'};
  assert.doesNotThrow(()=>validateTool('cargo-vet',tool,platform));
  for(const changed of [{...platform,archive:'../synthetic.zip'},{...platform,archive:'--checkpoint=1'},
    {...platform,member:'../tool.exe'},{...platform,member:'synthetic/../../tool.exe'},{...platform,member:'synthetic\\tool.exe'},
    {...platform,sha256:'a'.repeat(63)},null])assert.throws(()=>validateTool('cargo-vet',tool,changed));
  assert.throws(()=>validateTool('../cargo-vet',tool,platform));
  assert.throws(()=>validateTool('cargo-vet',{...tool,version:'latest'},platform));
});
