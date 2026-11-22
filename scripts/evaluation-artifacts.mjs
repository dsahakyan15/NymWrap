import {createHash} from 'node:crypto';
import {createReadStream,constants} from 'node:fs';
import {mkdir,lstat,copyFile,readFile} from 'node:fs/promises';
import {join} from 'node:path';
export async function artifactHash(path){const hash=createHash('sha256');for await(const chunk of createReadStream(path))hash.update(chunk);return hash.digest('hex');}
// The Rust examples parse an include_str! literal. Reject a stale evaluator after
// editing the JSON without rebuilding; don't attribute old input to a new hash.
export async function verifyEmbeddedCorpus(binary,corpus){
  const bytes=await readFile(corpus);if(!bytes.length||bytes.length>1024**2||!(await readFile(binary)).includes(bytes))throw Error('evaluation_corpus_mismatch_rebuild_example');
}
export async function cachedBinary(reports,name,sha256){
  if(!/^[a-z_-]+$/.test(name)||!/^[a-f0-9]{64}$/.test(sha256))throw Error('invalid_evaluation_binary_identity');
  const bin=join(reports,'bin'),path=join(bin,name+'-'+sha256+(process.platform==='win32'?'.exe':''));
  if((await lstat(bin)).isSymbolicLink()||(await lstat(path)).isSymbolicLink()||await artifactHash(path)!==sha256)throw Error('benchmark_binary_hash_mismatch');return path;
}
export async function pinnedBinary(reports,source,name){
  if(!/^[a-z_-]+$/.test(name))throw Error('invalid_evaluation_binary_name');
  const info=await lstat(source);if(info.isSymbolicLink()||!info.isFile()||info.size>256*1024**2)throw Error('unsafe_evaluation_binary');
  const sha256=await artifactHash(source),bin=join(reports,'bin');await mkdir(bin,{recursive:true});
  if((await lstat(bin)).isSymbolicLink())throw Error('unsafe_benchmark_binary_directory');
  const path=join(bin,name+'-'+sha256+(process.platform==='win32'?'.exe':''));
  try{await copyFile(source,path,constants.COPYFILE_EXCL);}catch(e){if(e.code!=='EEXIST')throw e;}
  return cachedBinary(reports,name,sha256);
}
