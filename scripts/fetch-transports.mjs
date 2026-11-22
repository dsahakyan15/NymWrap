// Build-time only. Runtime never downloads or searches PATH for a transport.
import{readFile,writeFile,mkdir,lstat,realpath}from'node:fs/promises';
import{createHash}from'node:crypto';
import{gunzipSync}from'node:zlib';
import{resolve,dirname,join,relative,sep,isAbsolute}from'node:path';
import{fileURLToPath,pathToFileURL}from'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
export const manifest=JSON.parse(await readFile(new URL('./transport-binaries.json',import.meta.url),'utf8'));
export function selectArtifact(platform){
  const artifact=manifest.artifacts.find(row=>row.platform===platform);
  if(!artifact)throw Error('unsupported_transport_platform');
  return artifact;
}
export function buildDestination(workspace,destination){
  const target=resolve(destination),allowed=['target','daemons/nw-netd/target','app/src-tauri/target'].map(path=>resolve(workspace,path));
  if(!allowed.some(base=>{const rel=relative(base,target);return rel!==''&&!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep);}))throw Error('unsafe_transport_destination');
  return target;
}
async function directory(path){
  const rel=relative(root,path);if(rel==='..'||rel.startsWith('..'+sep)||isAbsolute(rel))throw Error('unsafe_transport_directory');
  let current=root;
  for(const part of rel.split(sep).filter(Boolean)){
    current=join(current,part);await mkdir(current).catch(error=>{if(error.code!=='EEXIST')throw error;});
    const stat=await lstat(current),actual=await realpath(current);
    const normalized=value=>process.platform==='win32'?value.toLowerCase():value;
    if(stat.isSymbolicLink()||!stat.isDirectory()||normalized(actual)!==normalized(current))throw Error('unsafe_transport_directory');
  }
}
async function regular(path){const stat=await lstat(path);if(!stat.isFile()||stat.isSymbolicLink())throw Error('unsafe_transport_file');return readFile(path);}
export function extractTransport(archive,artifact){
  if(sha256(archive)!==artifact.archive_sha256)throw Error('transport_archive_hash_mismatch');
  const tar=gunzipSync(archive,{maxOutputLength:256*1024*1024});let selected;
  for(let offset=0;offset+512<=tar.length;){
    const header=tar.subarray(offset,offset+512);if(header.every(byte=>byte===0))break;
    const field=(start,length)=>header.subarray(start,start+length).toString('utf8').replace(/\0.*$/s,'');
    const octal=text=>{const value=text.replace(/\0.*$/s,'').trim();if(!/^[0-7]+$/.test(value))throw Error('invalid_transport_archive');return parseInt(value,8);};
    const size=octal(field(124,12)),checksum=octal(field(148,8));
    const computed=header.reduce((sum,byte,index)=>sum+(index>=148&&index<156?32:byte),0);
    if(computed!==checksum||!Number.isSafeInteger(size)||offset+512+size>tar.length)throw Error('invalid_transport_archive');
    const name=[field(345,155),field(0,100)].filter(Boolean).join('/');
    if(name===artifact.member){
      if(selected||![0,48].includes(header[156]))throw Error('unsafe_transport_member');
      selected=tar.subarray(offset+512,offset+512+size);
    }
    offset+=512+Math.ceil(size/512)*512;
  }
  if(!selected||selected.length!==artifact.bytes||sha256(selected)!==artifact.binary_sha256)throw Error('transport_binary_hash_mismatch');
  return selected;
}
export async function installTransport(platform,destination){
  const artifact=selectArtifact(platform),output=buildDestination(root,destination);
  await directory(output);
  const binary=join(output,platform.startsWith('windows-')?'lyrebird.exe':'lyrebird');
  try{
    const installed=await regular(binary);
    if(installed.length!==artifact.bytes||sha256(installed)!==artifact.binary_sha256)throw Error('existing_transport_binary_untrusted');
    return binary;
  }catch(error){if(error.code!=='ENOENT')throw error;}
  const cache=join(root,'target/tools',`tor-expert-${manifest.release}`);await directory(cache);
  const path=join(cache,artifact.archive);let archive;
  try{archive=await regular(path);}catch(error){if(error.code!=='ENOENT')throw error;}
  if(!archive){
    const response=await fetch(manifest.base_url+artifact.archive,{signal:AbortSignal.timeout(180000),redirect:'error'});
    if(!response.ok)throw Error('transport_download_failed');
    const chunks=[];let size=0;
    for await(const chunk of response.body){size+=chunk.length;if(size>64*1024*1024)throw Error('transport_archive_too_large');chunks.push(chunk);}
    archive=Buffer.concat(chunks);
    if(sha256(archive)!==artifact.archive_sha256)throw Error('transport_archive_hash_mismatch');
    await writeFile(path,archive,{flag:'wx'});
  }
  const bytes=extractTransport(archive,artifact);
  await writeFile(binary,bytes,{flag:'wx',mode:0o755});
  return binary;
}
async function main(){
  const args=process.argv.slice(2),options={platform:`${process.platform==='win32'?'windows':process.platform==='darwin'?'macos':process.platform}-${process.arch==='arm64'?'aarch64':process.arch==='x64'?'x86_64':process.arch}`,output:join(root,'daemons/nw-netd/target/debug/transports')};
  const seen=new Set();while(args.length){const key=args.shift();if(!['--platform','--output'].includes(key)||seen.has(key)||!args.length)throw Error('invalid_transport_arguments');seen.add(key);options[key.slice(2)]=args.shift();}
  console.log(await installTransport(options.platform,options.output));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().catch(error=>{process.stderr.write(error.message+'\n');process.exitCode=1;});
