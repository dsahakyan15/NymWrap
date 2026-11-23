import test from 'node:test';
import assert from 'node:assert/strict';
import {options,successfulVet} from '../vet-dependencies.mjs';
import {validateTool} from '../pinned-tools.mjs';
test('a failed, partial, exempted or missing vet result cannot turn the dependency gate green',()=>{
  const passed={conclusion:'success',vetted_fully:['synthetic'],vetted_partially:[],vetted_with_exemptions:[]};
  assert.equal(successfulVet(0,passed),true);
  for(const [code,result] of [[1,passed],[0,null],[0,{}],[0,{error:'synthetic failure'}],[0,{...passed,conclusion:'fail (vetting)'}],
    [0,{...passed,failures:[]}],[0,{...passed,vetted_partially:['synthetic']}],[0,{...passed,vetted_with_exemptions:['synthetic']}]])
    assert.equal(successfulVet(code,result),false);
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
