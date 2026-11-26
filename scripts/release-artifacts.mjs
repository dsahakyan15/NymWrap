// Build-time release inventory/comparison; no signing key or application data is accessed.
import {execFileSync} from 'node:child_process';
import {readFile,writeFile,readdir,lstat,mkdir,copyFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {checksums} from './release-signature.mjs';
export const releaseNames=['nymwrap-linux-x86_64.cdx.json','nymwrap-linux-x86_64.files.sha256','nymwrap-linux-x86_64.tar.gz','nymwrap-linux-x86_64.buildinfo.json'].sort();
const command=(program,args)=>execFileSync(program,args,{encoding:'utf8'}).trim();
export async function validate(directory,commit){
  const names=(await readdir(directory)).sort();
  if(JSON.stringify(names)!==JSON.stringify([...releaseNames,'SHA256SUMS'].sort()))throw Error('release_file_set_mismatch');
  for(const name of names){const stat=await lstat(join(directory,name));if(!stat.isFile()||stat.isSymbolicLink())throw Error('release_entry_not_regular_file');}
  const sums=await checksums(directory);
  if(sums!==await readFile(join(directory,'SHA256SUMS'),'utf8'))throw Error('release_hash_mismatch');
  const info=JSON.parse(await readFile(join(directory,'nymwrap-linux-x86_64.buildinfo.json'),'utf8'));
  if(info.commit!==commit||info.target!=='x86_64-unknown-linux-gnu')throw Error('release_revision_mismatch');
  return sums;
}
export async function compare(first,second,output,commit){
  if(!/^[0-9a-f]{40}$/.test(commit))throw Error('invalid_source_revision');
  const a=await validate(first,commit),b=await validate(second,commit);
  if(a!==b)throw Error('release_not_reproducible');
  if(output){
    await mkdir(output,{recursive:true});if((await readdir(output)).length)throw Error('release_output_not_empty');
    for(const name of [...releaseNames,'SHA256SUMS'])await copyFile(join(first,name),join(output,name));
  }
  return {commit,target:'x86_64-unknown-linux-gnu',algorithm:'SHA-256',identical:true,files:releaseNames};
}
async function record(directory){
  const info={format:1,commit:process.env.NW_RELEASE_COMMIT,target:'x86_64-unknown-linux-gnu',sourceDateEpoch:process.env.SOURCE_DATE_EPOCH,
    rust:command('rustc',['--version','--verbose']),node:process.version,
    packages:command('dpkg-query',['-W','-f=${Package}=${Version}\n']).split('\n').sort(),
    rustflags:process.env.RUSTFLAGS,cflags:process.env.CFLAGS,cxxflags:process.env.CXXFLAGS,
    recipe:await readFile(new URL('./release/Dockerfile',import.meta.url),'utf8')};
  await writeFile(join(directory,'nymwrap-linux-x86_64.buildinfo.json'),JSON.stringify(info,null,2)+'\n');
  await writeFile(join(directory,'SHA256SUMS'),await checksums(directory));
  await validate(directory,info.commit);
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  const [mode,...args]=process.argv.slice(2);
  try{
    if(mode==='record'&&args.length===1)await record(resolve(args[0]));
    else if(mode==='compare'&&args.length===4)console.log(JSON.stringify(await compare(...args.map((arg,i)=>i<3?resolve(arg):arg)),null,2));
    else throw Error('usage: release-artifacts.mjs record DIR | compare FIRST SECOND OUTPUT COMMIT');
  }catch(error){console.error(error.message);process.exitCode=1;}
}
