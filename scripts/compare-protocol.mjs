import {readFile,writeFile,lstat} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
export function compareProtocol(evidence){
  const hashes={};
  for(const name of ['provider-http.hex','provider-tls.hex']){
    const values=['Windows','Linux','macOS'].map(os=>evidence[os]?.[name]);
    if(values.some(value=>typeof value!=='string'||!/^([a-f0-9]{2})+\n$/.test(value)||value.length>16384)||new Set(values).size!==1)throw Error('protocol_bytes_differ_or_evidence_missing');
    hashes[name]=createHash('sha256').update(Buffer.from(values[0].trim(),'hex')).digest('hex');
  }
  return {complete:true,platforms:['Windows','Linux','macOS'],hashes};
}
async function main(){
  const root=resolve(process.argv[2]??'target/protocol-comparison'),evidence={};
  for(const os of ['Windows','Linux','macOS']){
    evidence[os]={};for(const name of ['provider-http.hex','provider-tls.hex']){
      const path=join(root,'protocol-golden-'+os,name),info=await lstat(path);
      if(!info.isFile()||info.isSymbolicLink()||info.size>16384)throw Error('invalid_protocol_evidence');
      evidence[os][name]=await readFile(path,'utf8');
    }
  }
  const report=compareProtocol(evidence);
  await writeFile(join(root,'report.json'),JSON.stringify(report,null,2)+'\n');
  console.log('cross_platform_protocol_bytes_match');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
