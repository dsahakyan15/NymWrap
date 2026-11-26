// Explicit installation/build tool. The application never downloads executables.
import {readFile,writeFile,mkdir,mkdtemp,lstat,realpath,chmod} from 'node:fs/promises';
import {spawnSync,execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const digest=b=>createHash('sha256').update(b).digest('hex');
const normalized=p=>process.platform==='win32'?p.toLowerCase():p;
export async function directory(parent,name) {
  const path=join(parent,name);await mkdir(path).catch(e=>{if(e.code!=='EEXIST')throw e;});
  const info=await lstat(path);
  if(!info.isDirectory()||info.isSymbolicLink()||normalized(await realpath(path))!==normalized(path))throw Error('unsafe_microvm_tool_directory');
  return path;
}
async function regular(path) {
  const info=await lstat(path);if(!info.isFile()||info.isSymbolicLink()||info.size>128*1024*1024)throw Error('unsafe_microvm_tool_file');
  return readFile(path);
}
export function verify(bytes,asset) {
  if(bytes.length!==asset.bytes||!/^[a-f0-9]{64}$/.test(asset.sha256)||digest(bytes)!==asset.sha256)throw Error('microvm_tool_hash_mismatch');
  return bytes;
}
async function download(asset) {
  const response=await fetch(asset.url,{signal:AbortSignal.timeout(180000)});
  if(!response.ok||!response.body)throw Error('microvm_tool_download_failed');
  const chunks=[];let n=0;
  for await(const chunk of response.body) {n+=chunk.length;if(n>asset.bytes)throw Error('microvm_tool_download_too_large');chunks.push(chunk);}
  return verify(Buffer.concat(chunks),asset);
}
async function assetFile(base,asset,bytes) {
  const path=join(base,asset.name??asset.archive);
  try {verify(await regular(path),asset);return path;}catch(e){if(e.code!=='ENOENT')throw e;}
  await writeFile(path,verify(bytes??await download(asset),asset),{flag:'wx',mode:0o500});
  return path;
}
export async function main() {
  if(process.argv.slice(2).join(' ')!=='--prepare')throw Error('usage: node scripts/fetch-microvm.mjs --prepare');
  const manifest=JSON.parse(await readFile(join(root,'scripts/microvm-binaries.json'),'utf8'));
  const platform=manifest.compiler.platforms[process.platform+'-'+process.arch];
  if(!platform)throw Error('microvm_build_platform_unsupported');
  const target=await directory(root,'target'),tools=await directory(target,'tools'),base=await directory(tools,'microvm');
  for(const archive of manifest.archives)await assetFile(base,archive);
  for(const asset of manifest.files.filter(a=>!a.source)) {
    let bytes;
    if(asset.member)bytes=execFileSync('tar',['-xOf',join(base,asset.archive),asset.member],{windowsHide:true,maxBuffer:128*1024*1024});
    await assetFile(base,asset,bytes);
  }
  const build=await directory(tools,'microvm-build');
  const archive=await assetFile(build,platform);
  // The entire official compiler archive is pinned. Only this public tool is
  // unpacked; no guest or project archive is ever extracted on the host.
  const listing=execFileSync('tar',['-tf',archive],{encoding:'utf8',maxBuffer:4*1024*1024});
  if(listing.trim().split(/\r?\n/).some(p=>!p.startsWith(platform.directory+'/')||p.includes('..')||p.includes('\\')))throw Error('unsafe_compiler_archive');
  const unpack=await mkdtemp(join(build,'compiler-'));
  execFileSync('tar',['-xf',archive,'-C',unpack],{windowsHide:true});
  const compiler=join(unpack,platform.directory,process.platform==='win32'?'zig.exe':'zig');
  if(process.platform!=='win32')await chmod(compiler,0o700);
  const source=await readFile(join(root,'scripts/microvm/guest-init.c'));
  const output=join(unpack,'guest-init');
  // stdin source, stripped ELF and a fixed target keep host paths out of the guest.
  const result=spawnSync(compiler,['cc','-target','x86_64-linux-musl','-static','-O2','-s','-fno-ident','-Werror','-Wall','-Wextra','-Wl,--build-id=none','-x','c','-','-o',output],{input:source,windowsHide:true,timeout:180000,maxBuffer:1024*1024,env:{...process.env,SOURCE_DATE_EPOCH:'0'}});
  if(result.status!==0)throw Error('microvm_guest_build_failed: '+result.stderr);
  const guest=manifest.files.find(a=>a.name==='guest-init');
  await assetFile(base,guest,verify(await regular(output),guest));
  console.log('microvm_tools_verified '+base);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
