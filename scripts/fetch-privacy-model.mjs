// Explicit developer command: downloads only the pinned synthetic-evaluation model.
import {readFile,mkdir,lstat,rename,writeFile,open} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const catalog=JSON.parse(await readFile(new URL('./privacy-models.json',import.meta.url),'utf8'));
const id=process.argv[2];if(process.argv.length!==3||!Object.hasOwn(catalog,id))throw Error('usage: node scripts/fetch-privacy-model.mjs qwen2.5-7b-q4_k_m');
const model=catalog[id],base=join(root,'target/test-models');await mkdir(base,{recursive:true});
const directory=await lstat(base);if(directory.isSymbolicLink()||!directory.isDirectory())throw Error('unsafe_model_directory');
async function checksum(path){const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);return hash.digest('hex');}
await Promise.all(model.files.map(async file=>{
  const path=join(base,file.name);let existing;try{existing=await lstat(path);}catch(e){if(e.code!=='ENOENT')throw e;}
  if(existing){if(existing.isSymbolicLink()||!existing.isFile()||existing.size!==file.bytes||await checksum(path)!==file.sha256)throw Error('cached_model_hash_mismatch');return;}
  const partial=path+'.part';
  const stat=await lstat(partial).catch(e=>{if(e.code!=='ENOENT')throw e;return null;});
  if(stat&&(stat.isSymbolicLink()||!stat.isFile()))throw Error('unsafe_partial_model');
  const handle=await open(partial,stat?'r+':'wx');let next=0,done=0;const size=8*1024*1024;
  try{
    await handle.truncate(file.bytes);
    await Promise.all(Array.from({length:3},async()=>{
      while(next<file.bytes){
        const start=next,end=Math.min(file.bytes-1,start+size-1);next=end+1;
        let bytes;
        for(let attempt=0;attempt<3;++attempt){
          try{
            const response=await fetch(`https://huggingface.co/${model.repo}/resolve/${model.revision}/${file.name}?download=true`,{headers:{Range:`bytes=${start}-${end}`},signal:AbortSignal.timeout(60000)});
            if(response.status!==206||response.headers.get('content-range')!==`bytes ${start}-${end}/${file.bytes}`||Number(response.headers.get('content-length'))!==end-start+1)throw Error('invalid_model_range');
            bytes=Buffer.from(await response.arrayBuffer());if(bytes.length!==end-start+1)throw Error('incomplete_model_range');break;
          }catch(error){if(attempt===2)throw error;}
        }
        let written=0;while(written<bytes.length){const result=await handle.write(bytes,written,bytes.length-written,start+written);if(!result.bytesWritten)throw Error('model_write_failed');written+=result.bytesWritten;}
        done+=bytes.length;
        if(Math.floor(done/(256*1024*1024))!==Math.floor((done-bytes.length)/(256*1024*1024)))console.log('Model download: '+file.name+' '+Math.round(done/file.bytes*100)+'%');
      }
    }));
  }finally{await handle.close();}
  if(await checksum(partial)!==file.sha256)throw Error('model_download_hash_mismatch');
  await rename(partial,path);console.log('Verified model shard: '+file.name);
}));
await writeFile(join(base,id+'.source.json'),JSON.stringify(model,null,2)+'\n');
