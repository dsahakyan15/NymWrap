// ADR 0040: before/after comparisons use exactly the same outgoing cases.
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chanceComparison} from './linkcheck-statistics.mjs';
export function pairedLinkcheck(rows){
  const result={};
  for(const [attacker,before,after]of [['model','raw_attack','attack'],['literal','raw_literal_attack','literal_attack']]){
    result[attacker]={};
    for(const language of ['all','en','ru','hy']){
      const outgoing=rows.filter(r=>r.group!=='public_control'&&r.remote_turns>0&&(language==='all'||r.language===language));
      const paired=outgoing.filter(r=>r[before]?.valid===true&&r[after]?.valid===true);
      result[attacker][language]={private_outgoing:outgoing.length,paired:paired.length,unmeasured_pairs:outgoing.length-paired.length,
        case_ids:paired.map(r=>r.id),before:chanceComparison(paired.filter(r=>r[before].top1_correct).length,paired.length,64),after:chanceComparison(paired.filter(r=>r[after].top1_correct).length,paired.length,64)};
    }
  }
  return result;
}
async function main(){
  const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),base=join(root,'docs/evaluations/shield-linkcheck-task5');
  const data={version:1,scope:'same measured private outgoing conversations with both valid attacks; not L0 or public controls',phases:{}};
  for(const [name,file]of [['development','development.json'],['held_out','held-out.json']])data.phases[name]=pairedLinkcheck(JSON.parse(await readFile(join(base,file),'utf8')).observations);
  await writeFile(join(base,'paired.json'),JSON.stringify(data,null,2)+'\n',{flag:'wx'});
  console.log('same_case_paired_comparison_written');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
