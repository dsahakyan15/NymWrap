// Explicit test-tool installation. Never changes a user's Firefox installation or profile.
import {readFile,writeFile,mkdir,mkdtemp,lstat,rename,realpath,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {resolve,dirname,join,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {readdir} from 'node:fs/promises';
import {assets,archivePaths,sevenZipPayload} from '../../scripts/linux-isolation-probe.mjs';
if(process.platform!=='win32')throw Error('stock_firefox_fixture_installer_windows_only');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..'),base=join(root,'target/tools/privacy-browser');await mkdir(base,{recursive:true});
const version='160.0.1',expected='e0356669960e73528d53c194ae2e3f46d663483073da16d58ba318cd67036d4023a10a23f47e1b733554dce88d8b7c299d806e06bbe31c590286ded20886eaea';
const destination=join(base,'firefox-'+version),receiptPath=join(base,'firefox-'+version+'.source.json');
async function treeDigest(directory){
  const digest=createHash('sha256').update('NymWrap-test-tool-tree-v1\0');let count=0;
  async function walk(path,prefix=''){
    if((await lstat(path)).isSymbolicLink())throw Error('unsafe_firefox_tool_tree');
    for(const entry of (await readdir(path,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){
      if(++count>10000||entry.isSymbolicLink())throw Error('unsafe_firefox_tool_tree');
      const file=join(path,entry.name),name=prefix+entry.name;
      if(entry.isDirectory())await walk(file,name+'/');
      else if(entry.isFile()){
        if((await lstat(file)).size>1024**3)throw Error('oversize_firefox_tool');
        const hash=createHash('sha256');for await(const chunk of createReadStream(file))hash.update(chunk);
        digest.update(name).update('\0').update(hash.digest('hex')).update('\0');
      }else throw Error('unsafe_firefox_tool_tree');
    }
  }
  await walk(directory);return digest.digest('hex');
}
let installed=false;try{const receipt=JSON.parse(await readFile(receiptPath,'utf8'));if(receipt.installer_sha512!==expected||await treeDigest(destination)!==receipt.tree_sha256)throw Error('firefox_tool_hash_mismatch');installed=true;}catch(e){if(e.code!=='ENOENT')throw e;}
if(!installed){
  const installer=join(base,'firefox-'+version+'.exe');let bytes;
  try{if((await lstat(installer)).isSymbolicLink())throw Error('unsafe_firefox_installer');bytes=await readFile(installer);}catch(e){if(e.code!=='ENOENT')throw e;}
  if(!bytes){const r=await fetch(`https://archive.mozilla.org/pub/firefox/releases/${version}/win64/en-US/Firefox%20Setup%20${version}.exe`,{signal:AbortSignal.timeout(180000)});if(!r.ok)throw Error('firefox_download_failed');bytes=Buffer.from(await r.arrayBuffer());}
  if(createHash('sha512').update(bytes).digest('hex')!==expected)throw Error('firefox_installer_hash_mismatch');
  await writeFile(installer,bytes);
  const zr=assets.find(a=>a.name==='7zr.exe'),zrPath=join(base,'7zr-26.06.exe');let tool;
  try{if((await lstat(zrPath)).isSymbolicLink())throw Error('unsafe_7zr');tool=await readFile(zrPath);}catch(e){if(e.code!=='ENOENT')throw e;}
  if(!tool){const r=await fetch(zr.url,{signal:AbortSignal.timeout(30000)});if(!r.ok)throw Error('7zr_download_failed');tool=Buffer.from(await r.arrayBuffer());}
  if(createHash('sha256').update(tool).digest('hex')!==zr.hash)throw Error('7zr_hash_mismatch');await writeFile(zrPath,tool);
  const fixture=await mkdtemp(join(base,'firefox-extract-'));
  try{
    const archive=join(fixture,'firefox.7z');await writeFile(archive,sevenZipPayload(bytes));const run=promisify(execFile),opts={windowsHide:true,encoding:'utf8',maxBuffer:4*1024*1024};
    archivePaths((await run(zrPath,['l','-slt',archive],opts)).stdout);
    await run(zrPath,['x','-y','-bso0','-bsp0','-o'+fixture,archive],opts);
    const actual=await realpath(join(fixture,'core')),parent=await realpath(base);if(!actual.toLowerCase().startsWith((parent+sep).toLowerCase())||!resolve(destination,'core').toLowerCase().startsWith((parent+sep).toLowerCase()))throw Error('unsafe_firefox_move');
    // A killed first installation may have moved the verified tree before writing its receipt.
    // Reuse it only after comparing every byte with a freshly verified extraction.
    let exists=false;try{const info=await lstat(destination);if(info.isSymbolicLink()||!info.isDirectory())throw Error('unsafe_firefox_destination');exists=true;}catch(e){if(e.code!=='ENOENT')throw e;}
    if(exists){
      const entries=await readdir(destination);if(entries.length!==1||entries[0]!=='core'||await treeDigest(join(destination,'core'))!==await treeDigest(actual))throw Error('unverified_firefox_destination');
    }else{await mkdir(destination);await rename(actual,join(destination,'core'));}
    await writeFile(receiptPath,JSON.stringify({version,installer_sha512:expected,tree_sha256:await treeDigest(destination)},null,2)+'\n');
  }finally{const actual=await realpath(fixture),parent=await realpath(base);if((await lstat(fixture)).isSymbolicLink()||!actual.toLowerCase().startsWith((parent+sep).toLowerCase()))throw Error('unsafe_firefox_extraction_cleanup');await rm(fixture,{recursive:true,force:true});}
}
console.log('Verified stock Firefox '+version+' test tool');
