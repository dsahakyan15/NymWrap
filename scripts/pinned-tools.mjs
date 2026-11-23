// Build/CI tools only; this module never opens application data.
import {readFile,writeFile,mkdir,lstat,realpath,chmod} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),run=promisify(execFile),limit=64*1024*1024;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const normal=path=>process.platform==='win32'?path.toLowerCase():path;
async function directory(parent,name){
  const path=join(parent,name);try{await mkdir(path);}catch(error){if(error.code!=='EEXIST')throw error;}
  const info=await lstat(path);
  if(!info.isDirectory()||info.isSymbolicLink()||normal(await realpath(path))!==normal(path))throw Error('unsafe_workflow_tool_directory');
  return path;
}
async function regular(path){
  const info=await lstat(path);if(!info.isFile()||info.isSymbolicLink()||info.size>limit)throw Error('unsafe_workflow_tool_file');
  return readFile(path);
}
export function validateTool(name,tool,platform){
  if(!/^[a-z][a-z0-9-]{0,39}$/.test(name)||!tool||!/^\d+\.\d+\.\d+$/.test(tool.version)||
    !/^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(tool.repository)||!platform||
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,150}$/.test(platform.archive)||!/^[a-f0-9]{64}$/.test(platform.sha256)||
    !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(platform.member)||platform.member.split('/').some(p=>p==='.'||p==='..'))throw Error('invalid_pinned_tool');
}
async function download(url){
  const response=await fetch(url,{signal:AbortSignal.timeout(60000)});
  if(!response.ok||Number(response.headers.get('content-length'))>limit||!response.body)throw Error('workflow_tool_download_failed');
  const chunks=[];let length=0;
  for await(const chunk of response.body){length+=chunk.length;if(length>limit)throw Error('workflow_tool_download_too_large');chunks.push(chunk);}
  return Buffer.concat(chunks,length);
}
export async function pinnedTool(name){
  const catalog=JSON.parse(await readFile(join(root,'scripts/workflow-tools.lock.json'),'utf8'));
  const tool=catalog[name],platform=tool?.platforms?.[process.platform+'-'+process.arch];
  validateTool(name,tool,platform);
  const target=await directory(root,'target'),tools=await directory(target,'tools'),base=await directory(tools,name+'-'+tool.version);
  const archive=join(base,platform.archive);let bytes;
  try{bytes=await regular(archive);}catch(error){
    if(error.code!=='ENOENT')throw error;
    bytes=await download(`https://github.com/${tool.repository}/releases/download/v${tool.version}/${platform.archive}`);
    if(digest(bytes)!==platform.sha256)throw Error('workflow_tool_archive_hash_mismatch');
    await writeFile(archive,bytes,{flag:'wx'});
  }
  if(digest(bytes)!==platform.sha256)throw Error('workflow_tool_archive_hash_mismatch');
  // Only one pinned member reaches memory; archive paths are never unpacked.
  const result=await run('tar',['-xOf',archive,platform.member],{encoding:'buffer',maxBuffer:limit,windowsHide:true});
  const expected=digest(result.stdout);if(!result.stdout.length)throw Error('workflow_tool_member_missing');
  const binary=join(base,name+(process.platform==='win32'?'.exe':''));
  try{if(digest(await regular(binary))!==expected)throw Error('workflow_tool_binary_hash_mismatch');}
  catch(error){if(error.code!=='ENOENT')throw error;await writeFile(binary,result.stdout,{flag:'wx'});}
  if(process.platform!=='win32')await chmod(binary,0o700);
  return {path:binary,version:tool.version,sha256:expected,archive_sha256:platform.sha256};
}
