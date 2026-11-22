// Bounded GGUF-v3 metadata rewrite and byte-preserving shard concatenation.
// No native model parser executes outside nw-llmd's sandbox.
import {open,lstat,mkdir,readFile,writeFile,rename,mkdtemp,realpath,rm} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,join,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
const MAX_PREFIX=64*1024*1024;
const hashRange=async(path,start=0,end)=>{const h=createHash('sha256');for await(const b of createReadStream(path,{start,end}))h.update(b);return h.digest('hex');};
export function ggufPrefix(buffer,fileSize){
  if(!Number.isSafeInteger(fileSize)||fileSize<32)throw Error('invalid_gguf_size');
  let at=0;const need=n=>{if(!Number.isSafeInteger(n)||n<0||at+n>buffer.length)throw Error('invalid_gguf_bounds');};
  const u32=()=>{need(4);const n=buffer.readUInt32LE(at);at+=4;return n;};
  const u64=()=>{need(8);const n=buffer.readBigUInt64LE(at);at+=8;if(n>BigInt(Number.MAX_SAFE_INTEGER))throw Error('oversize_gguf_integer');return Number(n);};
  const string=()=>{const n=u64();if(n>16*1024*1024)throw Error('oversize_gguf_string');need(n);const s=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(at,at+n));at+=n;return s;};
  const sizes={0:1,1:1,2:2,3:2,4:4,5:4,6:4,7:1,10:8,11:8,12:8};
  const value=(type,depth=0)=>{
    if(depth>1)throw Error('nested_gguf_array');
    if(type===8)return string();
    if(type===9){const element=u32(),count=u64();if(count>1000000)throw Error('oversize_gguf_array');if(element===9)throw Error('nested_gguf_array');if(element===8){for(let i=0;i<count;i++)value(element,depth+1);}else{const width=sizes[element];if(!width)throw Error('invalid_gguf_type');need(count*width);at+=count*width;}return null;}
    const n=sizes[type];if(!n)throw Error('invalid_gguf_type');need(n);let result=null;if(type===2)result=buffer.readUInt16LE(at);if(type===4)result=buffer.readUInt32LE(at);if(type===5)result=buffer.readInt32LE(at);at+=n;return result;
  };
  if(buffer.toString('ascii',0,4)!=='GGUF')throw Error('invalid_gguf_magic');at=4;if(u32()!==3)throw Error('unsupported_gguf_version');
  const count=u64(),entries=u64();if(count<1||count>100000||entries>100000)throw Error('oversize_gguf_counts');
  const kv=new Map();
  for(let i=0;i<entries;i++){const start=at,key=string(),type=u32(),valueOffset=at;if(kv.has(key))throw Error('duplicate_gguf_key');const parsed=value(type);kv.set(key,{type,value:parsed,valueOffset,bytes:buffer.subarray(start,at)});}
  const metadataEnd=at,tensors=[],names=new Set();
  for(let i=0;i<count;i++){const start=at,name=string(),dimensions=u32();if(names.has(name)||dimensions<1||dimensions>4)throw Error('invalid_gguf_tensor');names.add(name);for(let d=0;d<dimensions;d++){if(u64()<1)throw Error('invalid_gguf_dimension');}const type=u32();if(type>64)throw Error('invalid_gguf_tensor_type');const offsetPosition=at,offset=u64();tensors.push({name,offset,offsetPosition:offsetPosition-start,bytes:buffer.subarray(start,at)});}
  const alignment=kv.get('general.alignment')?.value??32;
  if(!Number.isInteger(alignment)||alignment<1||alignment>4096||(alignment&(alignment-1)))throw Error('invalid_gguf_alignment');
  const dataOffset=Math.ceil(at/alignment)*alignment,dataBytes=fileSize-dataOffset;
  if(dataOffset>buffer.length||dataBytes<1||tensors[0].offset!==0||tensors.some((t,i)=>t.offset%alignment||t.offset>=dataBytes||i>0&&t.offset<=tensors[i-1].offset))throw Error('invalid_gguf_tensor_offsets');
  return {count,entries,kv,metadataEnd,tensors,alignment,dataOffset,dataBytes,prefix:buffer.subarray(0,dataOffset)};
}
export async function mergeModel(base,model){
  if(!/^[a-zA-Z0-9_.-]+\.gguf$/.test(model.output)||!Array.isArray(model.files)||model.files.length<1||model.files.length>32)throw Error('invalid_model_catalog');
  const parts=[];
  for(const [i,file]of model.files.entries()){
    if(!/^[a-zA-Z0-9_.-]+\.gguf$/.test(file.name)||!/^[0-9a-f]{64}$/.test(file.sha256)||!Number.isSafeInteger(file.bytes)||file.bytes<32||file.bytes>64*1024**3)throw Error('invalid_model_catalog');
    const path=join(base,file.name),stat=await lstat(path);if(stat.isSymbolicLink()||!stat.isFile()||stat.size!==file.bytes)throw Error('invalid_model_shard');
    const handle=await open(path,'r');let prefix;try{const bytes=Buffer.alloc(Math.min(stat.size,MAX_PREFIX));let read=0;while(read<bytes.length){const result=await handle.read(bytes,read,bytes.length-read,read);if(!result.bytesRead)throw Error('truncated_model_shard');read+=result.bytesRead;}prefix=ggufPrefix(bytes,stat.size);}finally{await handle.close();}
    if(prefix.kv.get('split.no')?.value!==i||prefix.kv.get('split.count')?.value!==model.files.length||prefix.kv.get('split.count')?.type!==2)throw Error('invalid_gguf_split');parts.push({...prefix,path,source:file});
  }
  const total=parts.reduce((n,p)=>n+p.count,0),first=parts[0];
  if(parts.some(p=>p.alignment!==first.alignment||p.kv.get('split.tensors.count')?.value!==total))throw Error('inconsistent_gguf_split');
  const names=new Set();let dataBytes=0;
  for(const part of parts){
    for(const [key,v]of part.kv){if(!key.startsWith('split.')&&!v.bytes.equals(first.kv.get(key)?.bytes??Buffer.alloc(0)))throw Error('inconsistent_gguf_metadata');}
    part.outputOffset=dataBytes;dataBytes+=Math.ceil(part.dataBytes/first.alignment)*first.alignment;
    for(const t of part.tensors){if(names.has(t.name))throw Error('duplicate_merged_tensor');names.add(t.name);}
  }
  const meta=Buffer.from(first.prefix.subarray(0,first.metadataEnd));meta.writeBigUInt64LE(BigInt(total),8);meta.writeUInt16LE(0,first.kv.get('split.count').valueOffset);
  const infos=parts.flatMap(p=>p.tensors.map(t=>{const bytes=Buffer.from(t.bytes);bytes.writeBigUInt64LE(BigInt(p.outputOffset+t.offset),t.offsetPosition);return bytes;}));
  const raw=Buffer.concat([meta,...infos]),header=Buffer.alloc(Math.ceil(raw.length/first.alignment)*first.alignment);raw.copy(header);
  const fixture=await mkdtemp(join(base,'merge-')),output=join(fixture,'merged.gguf');
  try{
    const handle=await open(output,'wx'),blocks=[];
    const write=async(bytes,position)=>{let n=0;while(n<bytes.length){const r=await handle.write(bytes,n,bytes.length-n,position+n);if(!r.bytesWritten)throw Error('merge_write_failed');n+=r.bytesWritten;}};
    try{
      await write(header,0);
      for(const part of parts){const inputHash=createHash('sha256').update(part.prefix),bodyHash=createHash('sha256');let position=header.length+part.outputOffset;
        for await(const chunk of createReadStream(part.path,{start:part.dataOffset,highWaterMark:1024*1024})){inputHash.update(chunk);bodyHash.update(chunk);await write(chunk,position);position+=chunk.length;}
        if(inputHash.digest('hex')!==part.source.sha256)throw Error('model_shard_hash_mismatch');
        const padding=(first.alignment-part.dataBytes%first.alignment)%first.alignment;if(padding)await write(Buffer.alloc(padding),position);
        blocks.push({start:header.length+part.outputOffset,bytes:part.dataBytes,sha256:bodyHash.digest('hex')});
      }
      await handle.sync();
    }finally{await handle.close();}
    for(const block of blocks){if(await hashRange(output,block.start,block.start+block.bytes-1)!==block.sha256)throw Error('merged_tensor_bytes_changed');}
    const sha256=await hashRange(output),receipt={file:model.output,sha256,bytes:(await lstat(output)).size,tensors:total,source:model,method:'bounded GGUF-v3 metadata; split.count=0; unchanged shard data and padding; no native parser',merger_sha256:await hashRange(fileURLToPath(import.meta.url))};
    const destination=join(base,model.output);try{await lstat(destination);throw Error('merged_model_already_exists');}catch(e){if(e.code!=='ENOENT')throw e;}
    await rename(output,destination);return receipt;
  }finally{const actual=await realpath(fixture),parent=await realpath(base),normal=v=>process.platform==='win32'?v.toLowerCase():v;if(!normal(actual).startsWith(normal(parent+sep))||(await lstat(fixture)).isSymbolicLink())throw Error('unsafe_merge_cleanup');await rm(fixture,{recursive:true,force:true});}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),catalog=JSON.parse(await readFile(new URL('./privacy-models.json',import.meta.url),'utf8')),id=process.argv[2];
  if(process.argv.length!==3||!Object.hasOwn(catalog,id))throw Error('invalid_model_id');const base=join(root,'target/test-models');await mkdir(base,{recursive:true});
  const receipt=await mergeModel(base,catalog[id]);await writeFile(join(base,id+'.merged.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify({file:receipt.file,sha256:receipt.sha256,tensors:receipt.tensors}));
}
