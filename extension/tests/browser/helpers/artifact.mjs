import {readFile,readdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
export async function extensionDigest(directory){
  const hash=createHash('sha256').update('NymWrap-extension-artifact-v1\0');
  for(const entry of (await readdir(directory,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){
    if(!entry.isFile()||entry.isSymbolicLink())throw Error('unexpected_extension_artifact');
    hash.update(entry.name).update('\0').update(createHash('sha256').update(await readFile(join(directory,entry.name))).digest('hex')).update('\0');
  }
  return hash.digest('hex');
}
