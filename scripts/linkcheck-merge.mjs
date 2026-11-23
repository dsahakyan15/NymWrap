import {readFile,readdir,lstat,mkdir,writeFile,rename} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {artifactHash} from './evaluation-artifacts.mjs';
import {validateLinkcheckReport,summarizeLinkcheckReport} from './linkcheck-report.mjs';

export function mergeShardReports(sources,corpus,corpusHash){
  if(corpus?.partition!=='development'||!Array.isArray(sources)||sources.length<2||sources.length>16)throw Error('incomplete_linkcheck_shards');
  const ordered=[...sources].sort((a,b)=>(a.report?.shard?.index??-1)-(b.report?.shard?.index??-1));
  const first=ordered[0].report;
  const evidence=first?.evidence;
  if(!evidence||Object.keys(evidence).sort().join(',')!=='commit,workflow_run'||
    !(evidence.commit===null&&evidence.workflow_run===null||typeof evidence.commit==='string'&&/^[a-f0-9]{40}$/.test(evidence.commit)&&
      typeof evidence.workflow_run==='string'&&/^[0-9]{1,24}$/.test(evidence.workflow_run)))throw Error('missing_linkcheck_run_evidence');
  for(const [index,source]of ordered.entries()){
    const report=source.report;
    validateLinkcheckReport(report,corpus,corpusHash,{allowShard:true});
    if(!/^[a-f0-9]{64}$/.test(source.sha256)||!report.shard||report.shard.index!==index||report.shard.count!==sources.length||
      !isDeepStrictEqual(report.provenance,first.provenance)||!isDeepStrictEqual(report.scope,first.scope)||
      !isDeepStrictEqual(report.evidence,first.evidence))throw Error('incompatible_or_missing_linkcheck_shard');
  }
  const result={version:3,status:'complete',partition:first.partition,case_count:corpus.cases.length,
    provenance:first.provenance,scope:first.scope,evidence:first.evidence,
    shards:ordered.map(source=>({...source.report.shard,sha256:source.sha256})),
    observations:ordered.flatMap(source=>source.report.observations)};
  result.analysis=summarizeLinkcheckReport(result,corpus,corpusHash);
  return result;
}
export async function main(args=process.argv.slice(2)){
  if(args.length!==4||args[0]!=='--input'||args[2]!=='--out')throw Error('usage_linkcheck_merge_input_directory_out_json');
  const input=resolve(args[1]),output=resolve(args[3]),info=await lstat(input);
  if(info.isSymbolicLink()||!info.isDirectory())throw Error('unsafe_linkcheck_shard_directory');
  const entries=await readdir(input,{withFileTypes:true});
  if(entries.length<2||entries.length>16)throw Error('incomplete_linkcheck_shards');
  const sources=[];
  for(const entry of entries){
    if(!entry.isFile()||!/^development-[a-z0-9_.-]+-shard-\d+-of-\d+\.json$/.test(entry.name))throw Error('unexpected_linkcheck_shard_file');
    const path=join(input,entry.name),stat=await lstat(path);
    if(stat.isSymbolicLink()||!stat.isFile()||stat.size>4*1024*1024)throw Error('unsafe_linkcheck_shard_file');
    sources.push({report:JSON.parse(await readFile(path,'utf8')),sha256:await artifactHash(path)});
  }
  const corpusPath=new URL('../tests/models/privacy-v3-dev.json',import.meta.url),corpusHash=await artifactHash(corpusPath);
  const result=mergeShardReports(sources,JSON.parse(await readFile(corpusPath,'utf8')),corpusHash);
  await mkdir(dirname(output),{recursive:true});
  try{await lstat(output);throw Error('linkcheck_merged_report_already_exists');}catch(e){if(e.code!=='ENOENT')throw e;}
  await writeFile(output+'.part',JSON.stringify(result,null,2)+'\n',{flag:'wx'});await rename(output+'.part',output);
  console.log(JSON.stringify({report:output,status:result.status,cases:result.case_count,shards:result.shards.length,held_out:false}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
