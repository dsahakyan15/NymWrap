import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,writeFile,readFile,realpath,rm} from 'node:fs/promises';
import {resolve,join,sep} from 'node:path';
import {createHash} from 'node:crypto';
import {ggufPrefix,mergeModel} from '../merge-privacy-model.mjs';
const u16=n=>{const b=Buffer.alloc(2);b.writeUInt16LE(n);return b;},u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;},u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b;};
const str=s=>Buffer.concat([u64(Buffer.byteLength(s)),Buffer.from(s)]);
function shard(index,name){
  const kv=(key,type,value)=>Buffer.concat([str(key),u32(type),value]);
  const raw=Buffer.concat([Buffer.from('GGUF'),u32(3),u64(1),u64(4),kv('split.no',2,u16(index)),kv('split.count',2,u16(2)),kv('split.tensors.count',5,u32(2)),kv('general.alignment',4,u32(32)),str(name),u32(1),u64(8),u32(0),u64(0)]);
  const buffer=Buffer.alloc(Math.ceil(raw.length/32)*32+32,index+1);buffer.fill(0,0,buffer.length-32);raw.copy(buffer);return buffer;
}
test('bounded GGUF header parsing rejects truncation and unsafe counts',()=>{
  const bytes=shard(0,'fixture.a');assert.equal(ggufPrefix(bytes,bytes.length).count,1);
  assert.throws(()=>ggufPrefix(bytes.subarray(0,40),bytes.length),/bounds/);
  const bad=Buffer.from(bytes);bad.writeBigUInt64LE(0xffffffffffffffffn,8);assert.throws(()=>ggufPrefix(bad,bad.length),/oversize/);
  assert.throws(()=>ggufPrefix(bytes,NaN),/size/);
});
test('model merge preserves both payloads, checks all source hashes and rejects output traversal',async()=>{
  const base=resolve('target/model-merge-tests');await mkdir(base,{recursive:true});const dir=await mkdtemp(join(base,'model-'));
  try{
    const data=[shard(0,'fixture.a'),shard(1,'fixture.b')];
    const model={output:'merged.gguf',files:[]};for(const [i,bytes]of data.entries()){const name='part'+i+'.gguf';await writeFile(join(dir,name),bytes);model.files.push({name,bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')});}
    await assert.rejects(mergeModel(dir,{...model,output:'../outside.gguf'}),/catalog/);
    await assert.rejects(mergeModel(dir,{...model,files:[{...model.files[0],sha256:'0'.repeat(64)},model.files[1]]}),/hash_mismatch/);
    const receipt=await mergeModel(dir,model),output=await readFile(join(dir,'merged.gguf')),parsed=ggufPrefix(output,output.length);
    assert.equal(parsed.count,2);assert.equal(parsed.kv.get('split.count').value,0);assert.equal(receipt.tensors,2);
    assert.deepEqual(output.subarray(parsed.dataOffset,parsed.dataOffset+32),Buffer.alloc(32,1));assert.deepEqual(output.subarray(parsed.dataOffset+32),Buffer.alloc(32,2));
  }finally{const actual=await realpath(dir),parent=await realpath(base);if(!actual.toLowerCase().startsWith((parent+sep).toLowerCase()))throw Error('unsafe_test_cleanup');await rm(dir,{recursive:true,force:true});}
});
