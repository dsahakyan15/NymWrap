import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,cp,symlink,rm,writeFile} from 'node:fs/promises';
import {resolve,sep} from 'node:path';
import {parseFuzzOptions,prepareFuzzSeeds} from '../fuzz.mjs';
test('fuzz runner accepts only bounded durations and known targets',()=>{
  assert.deepEqual(parseFuzzOptions(['--target','ipc_frames']),{target:'ipc_frames',seconds:60});
  for(const args of [[],['--target','../core'],['--target','ipc_frames','--seconds','0'],['--target','ipc_frames','--seconds','86401'],['--target','ipc_frames','--seconds','NaN'],['--target','ipc_frames','--target','audit_import']])assert.throws(()=>parseFuzzOptions(args));
});
test('synthetic corpus includes real frames and cannot follow a corpus junction',async()=>{
  const target=resolve('target');await mkdir(target,{recursive:true});const dir=await mkdtemp(resolve(target,'fuzz-tool-test-'));
  assert.ok(dir.startsWith(target+sep));
  try{
    const fixture=resolve(dir,'fuzz');await mkdir(fixture);await cp(resolve('fuzz/seeds'),resolve(fixture,'seeds'),{recursive:true});
    const paths=await prepareFuzzSeeds(fixture);
    const bytes=await readFile(resolve(paths.ipc_frames,'core.frame'));
    assert.equal(bytes.readUInt32LE(0),bytes.length-4);assert.equal(JSON.parse(bytes.subarray(4)).body.op,'status');
    const native=await readFile(resolve(paths.ipc_frames,'validate_search.frame'));
    assert.equal(native.readUInt32LE(0),native.length-4);assert.equal(JSON.parse(native.subarray(4)).command.kind,'validate_search');
    const submission=await readFile(resolve(paths.ipc_frames,'submission.frame'));
    assert.equal(JSON.parse(submission.subarray(4)).body.idempotency_key,'SYNTHETIC_FUZZ_RECEIPT_20391');
    const source=await readFile(resolve(paths.shield_roundtrip,'synthetic-roundtrip.txt'));
    await prepareFuzzSeeds(fixture);assert.deepEqual(await readFile(resolve(paths.shield_roundtrip,'synthetic-roundtrip.txt')),source);
    const blocked=resolve(dir,'blocked');await mkdir(blocked);await cp(resolve('fuzz/seeds'),resolve(blocked,'seeds'),{recursive:true});
    const outside=resolve(dir,'outside');await mkdir(outside);await writeFile(resolve(outside,'marker'),'SYNTHETIC_UNCHANGED');
    await symlink(outside,resolve(blocked,'corpus'),process.platform==='win32'?'junction':'dir');
    await assert.rejects(prepareFuzzSeeds(blocked),/unsafe_fuzz_directory/);
    assert.equal(await readFile(resolve(outside,'marker'),'utf8'),'SYNTHETIC_UNCHANGED');
  }finally{await rm(dir,{recursive:true,force:true});}
});
