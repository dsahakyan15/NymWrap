// Development/CI tool only. No application data is read or sent.
import {readFile,writeFile,mkdir,lstat,realpath,chmod} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),run=promisify(execFile);
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const normal=path=>process.platform==='win32'?path.toLowerCase():path;
async function directory(parent,name){
  const path=join(parent,name);try{await mkdir(path);}catch(error){if(error.code!=='EEXIST')throw error;}
  const info=await lstat(path);
  if(!info.isDirectory()||info.isSymbolicLink()||normal(await realpath(path))!==normal(path))throw Error('unsafe_workflow_tool_directory');
  return path;
}
async function regular(path){
  const info=await lstat(path);if(!info.isFile()||info.isSymbolicLink()||info.size>64*1024*1024)throw Error('unsafe_workflow_tool_file');
  return readFile(path);
}
export async function main(){
  const tool=JSON.parse(await readFile(join(root,'scripts/workflow-tools.lock.json'),'utf8')).actionlint;
  const platform=tool.platforms[process.platform+'-'+process.arch];
  if(!platform)throw Error('unsupported_workflow_tool_platform');
  const target=await directory(root,'target'),tools=await directory(target,'tools'),base=await directory(tools,'actionlint-'+tool.version);
  const archive=join(base,platform.archive);let bytes;
  try{bytes=await regular(archive);}catch(error){
    if(error.code!=='ENOENT')throw error;
    const response=await fetch(`https://github.com/rhysd/actionlint/releases/download/v${tool.version}/${platform.archive}`,{signal:AbortSignal.timeout(60000)});
    if(!response.ok||Number(response.headers.get('content-length'))>64*1024*1024)throw Error('workflow_tool_download_failed');
    bytes=Buffer.from(await response.arrayBuffer());if(bytes.length>64*1024*1024||digest(bytes)!==platform.sha256)throw Error('workflow_tool_archive_hash_mismatch');
    await writeFile(archive,bytes,{flag:'wx'});
  }
  if(digest(bytes)!==platform.sha256)throw Error('workflow_tool_archive_hash_mismatch');
  // Extract only the fixed member to memory. Never unpack archive paths to disk.
  const result=await run('tar',['-xOf',archive,platform.member],{encoding:'buffer',maxBuffer:64*1024*1024,windowsHide:true});
  const expected=digest(result.stdout);if(!result.stdout.length)throw Error('workflow_tool_member_missing');
  const binary=join(base,platform.member);
  try{if(digest(await regular(binary))!==expected)throw Error('workflow_tool_binary_hash_mismatch');}
  catch(error){if(error.code!=='ENOENT')throw error;await writeFile(binary,result.stdout,{flag:'wx'});}
  if(process.platform!=='win32')await chmod(binary,0o700);
  // Optional Python/shell linters are deliberately separate; this checks YAML,
  // workflow schemas, action inputs and GitHub expression types consistently.
  const checked=await run(binary,['-no-color','-shellcheck=','-pyflakes='],{cwd:root,windowsHide:true,maxBuffer:1024*1024});
  if(checked.stdout)process.stdout.write(checked.stdout);if(checked.stderr)process.stderr.write(checked.stderr);
  process.stdout.write('workflow_schema_checks_passed\n');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
