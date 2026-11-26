// The same clean Linux builder is used by both CI jobs and the release owner.
// Only committed source is exported. No host Cargo/npm caches, keys or environment enter it.
import {spawn} from 'node:child_process';
import {mkdir,mkdtemp,writeFile,readdir} from 'node:fs/promises';
import {resolve,dirname,join,basename} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
function run(program,args,capture=false){
  return new Promise((done,fail)=>{
    const child=spawn(program,args,{cwd:root,stdio:['ignore',capture?'pipe':'inherit','inherit'],windowsHide:true});
    const chunks=[];if(capture)child.stdout.on('data',chunk=>chunks.push(chunk));
    child.once('error',fail);child.once('exit',code=>code===0?done(Buffer.concat(chunks)):fail(Error(`${program}_failed`)));
  });
}
export async function build(directory){
  const output=resolve(directory);
  // Never reuse a populated output directory, or stale artifacts could be signed.
  await mkdir(output,{recursive:true});if((await readdir(output)).length)throw Error('release_output_not_empty');
  const commit=(await run('git',['rev-parse','HEAD'],true)).toString().trim();
  const epoch=(await run('git',['show','-s','--format=%ct','HEAD'],true)).toString().trim();
  if(!/^[0-9a-f]{40}$/.test(commit)||!/^\d+$/.test(epoch))throw Error('invalid_source_revision');
  const temporary=join(root,'target');await mkdir(temporary,{recursive:true});
  const work=await mkdtemp(join(temporary,'repro-build-')),context=join(work,'context');await mkdir(context);
  for(const name of ['Dockerfile','build.sh'])await writeFile(join(context,name),await run('git',['show',`HEAD:scripts/release/${name}`],true));
  const source=join(work,'source.tar');await run('git',['archive','--format=tar','--output',source,'HEAD']);
  const image='nymwrap-release:'+basename(work);
  await run('docker',['build','--pull','--no-cache','--platform','linux/amd64','--tag',image,context]);
  await run('docker',['run','--rm','--platform','linux/amd64','--hostname','nymwrap-builder',
    '--mount',`type=bind,source=${source},target=/input/source.tar,readonly`,
    '--mount',`type=bind,source=${output},target=/out`,
    '--env',`NW_RELEASE_COMMIT=${commit}`,'--env',`SOURCE_DATE_EPOCH=${epoch}`,image]);
  console.log('unsigned_release_built '+output);
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  if(process.argv.length!==3){console.error('usage: node scripts/repro-build.mjs OUTPUT_DIRECTORY');process.exitCode=1;}
  else await build(process.argv[2]);
}
