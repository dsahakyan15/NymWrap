// Deterministic CycloneDX 1.6 inventory from the three locked Cargo graphs.
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFile,readdir,lstat,writeFile,mkdir} from 'node:fs/promises';
import {dirname,resolve,relative,isAbsolute,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sha256=value=>createHash('sha256').update(value).digest('hex');
const slash=value=>value.split(sep).join('/');
const registry='registry+https://github.com/rust-lang/crates.io-index';

export function lockChecksums(text){
  const checksums=new Map();
  for(const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)){
    const field=name=>{const found=block.match(new RegExp('^'+name+' = ("[^"\\r\\n]*")$','m'));return found?JSON.parse(found[1]):undefined;};
    const name=field('name'),version=field('version'),source=field('source');
    if(!name||!version)throw Error('invalid_lockfile');
    if(source){
      const checksum=field('checksum');
      if(source!==registry||!checksum||!/^[0-9a-f]{64}$/.test(checksum))throw Error('unsupported_or_unhashed_dependency');
      const key=JSON.stringify([name,version,source]);
      if(checksums.has(key))throw Error('duplicate_lock_entry');
      checksums.set(key,checksum);
    }
  }
  return checksums;
}
export async function sourceDigest(directory){
  const digest=createHash('sha256');digest.update('NymWrap-source-tree-v1\0');
  const ignored=new Set(['target','node_modules','.git','dist','dist-firefox']);
  async function walk(path){
    const entries=(await readdir(path,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
    for(const entry of entries){
      if(ignored.has(entry.name)&&entry.isDirectory())continue;
      const file=resolve(path,entry.name);
      if(entry.isSymbolicLink())throw Error('source_symlink_not_supported');
      if(entry.isDirectory())await walk(file);
      else if(entry.isFile()){
        const info=await lstat(file);if(!info.isFile()||info.isSymbolicLink()||info.size>64*1024*1024)throw Error('invalid_source_file');
        digest.update(slash(relative(directory,file)));digest.update('\0');digest.update(sha256(await readFile(file)));digest.update('\0');
      }else throw Error('invalid_source_file');
    }
  }
  await walk(directory);return digest.digest('hex');
}
export async function inventory(graphs,workspace=root){
  const components=new Map(),dependencies=new Map(),roots=new Set();
  for(const {metadata,checksums,rootNames}of graphs){
    if(!metadata.resolve)throw Error('missing_resolved_graph');
    const packages=new Map(metadata.packages.map(p=>[p.id,p]));
    const nodes=new Map(metadata.resolve.nodes.map(n=>[n.id,n]));
    const visited=new Set();
    function descriptor(id){
      const pkg=packages.get(id);if(!pkg)throw Error('incomplete_package_graph');
      let source=pkg.source;
      if(!source){
        const path=slash(relative(workspace,dirname(pkg.manifest_path)));
        if(!path||path==='..'||path.startsWith('../')||isAbsolute(path))throw Error('external_path_dependency');
        source='workspace:'+path;
      }else if(source!==registry)throw Error('unsupported_dependency_source');
      const ref='cargo:'+sha256(JSON.stringify([pkg.name,pkg.version,source]));
      return {pkg,source,ref};
    }
    async function visit(id){
      const {pkg,source,ref}=descriptor(id);
      if(visited.has(id))return ref;visited.add(id);
      let hash,basis;
      if(pkg.source){
        hash=checksums.get(JSON.stringify([pkg.name,pkg.version,pkg.source]));
        if(!hash)throw Error('missing_archive_checksum');basis='Cargo.lock registry archive';
      }else{hash=await sourceDigest(dirname(pkg.manifest_path));basis='NymWrap-source-tree-v1';}
      const component={type:pkg.targets?.some(t=>t.kind.includes('bin'))?'application':'library','bom-ref':ref,name:pkg.name,version:pkg.version,purl:`pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`,hashes:[{alg:'SHA-256',content:hash}],properties:[{name:'nymwrap:source',value:source},{name:'nymwrap:hash-basis',value:basis}]};
      if(pkg.license)component.licenses=[{expression:pkg.license.replaceAll('/',' OR ')}];
      else if(pkg.license_file)component.licenses=[{license:{name:'License file in pinned source archive'}}];
      const previous=components.get(ref);
      if(previous&&JSON.stringify(previous)!==JSON.stringify(component))throw Error('conflicting_component_identity');
      components.set(ref,component);
      const node=nodes.get(id);if(!node)throw Error('incomplete_dependency_graph');
      const edges=dependencies.get(ref)??new Set();dependencies.set(ref,edges);
      for(const dep of node.deps){
        if(dep.dep_kinds.some(kind=>kind.kind!=='dev'))edges.add(await visit(dep.pkg));
      }
      return ref;
    }
    for(const name of rootNames){
      const candidates=metadata.workspace_members.map(id=>packages.get(id)).filter(p=>p?.name===name);
      if(candidates.length!==1)throw Error('missing_product_root');
      roots.add(await visit(candidates[0].id));
    }
  }
  return {components:[...components.values()].sort((a,b)=>a['bom-ref'].localeCompare(b['bom-ref'])),dependencies:[...dependencies].sort(([a],[b])=>a.localeCompare(b)).map(([ref,edges])=>({ref,dependsOn:[...edges].sort()})),roots:[...roots].sort()};
}
function cargo(args){
  return execFileSync('cargo',args,{cwd:root,encoding:'utf8',maxBuffer:64*1024*1024,timeout:120000,stdio:['ignore','pipe','pipe']});
}
export async function generate(target){
  if(!/^[a-z0-9_]+(?:-[a-z0-9_]+){2,5}$/.test(target))throw Error('invalid_target');
  const graphs=[];
  for(const [manifest,rootNames]of [
    ['Cargo.toml',['nw-core','nw-api','nw-llmd','nw-drift-host','nw-audit']],
    ['app/src-tauri/Cargo.toml',['nymwrap-app']],
    ['daemons/nw-netd/Cargo.toml',['nw-netd']],
  ]){
    const metadata=JSON.parse(cargo(['metadata','--manifest-path',manifest,'--format-version','1','--locked','--offline','--all-features','--filter-platform',target]));
    const checksums=lockChecksums(await readFile(resolve(root,dirname(manifest),'Cargo.lock'),'utf8'));
    graphs.push({metadata,checksums,rootNames});
  }
  const result=await inventory(graphs);
  const version=graphs[0].metadata.packages.find(p=>p.name==='nw-core'&&p.source===null).version;
  for(const [name,directory]of [['nymwrap-desktop-ui','app'],['nymwrap-extension','extension']]){
    const ref=`pkg:generic/${name}@${version}`;
    result.components.push({type:'application','bom-ref':ref,name,version,purl:ref,hashes:[{alg:'SHA-256',content:await sourceDigest(resolve(root,directory))}],properties:[{name:'nymwrap:hash-basis',value:'NymWrap-source-tree-v1'}]});
    result.dependencies.push({ref,dependsOn:[]});result.roots.push(ref);
  }
  const product='pkg:generic/nymwrap@'+version;
  return {bomFormat:'CycloneDX',specVersion:'1.6',version:1,metadata:{component:{type:'application','bom-ref':product,name:'NymWrap',version},lifecycles:[{phase:'pre-build'}],properties:[{name:'nymwrap:target',value:target},{name:'nymwrap:scope',value:'All project features; non-dev normal/build dependency closure. Archive hashes identify locked source, not compiled binaries.'}]},components:result.components.sort((a,b)=>a['bom-ref'].localeCompare(b['bom-ref'])),dependencies:[{ref:product,dependsOn:result.roots.sort()},...result.dependencies].sort((a,b)=>a.ref.localeCompare(b.ref))};
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  try{
    const args=process.argv.slice(2);
    if(args.length!==4||args[0]!=='--target'||args[2]!=='--out')throw Error('usage: node scripts/sbom.mjs --target TARGET --out FILE');
    const bom=await generate(args[1]),output=resolve(args[3]);await mkdir(dirname(output),{recursive:true});await writeFile(output,JSON.stringify(bom,null,2)+'\n');
    process.stdout.write(`SBOM: ${bom.components.length} components, ${bom.dependencies.length} dependency nodes\n`);
  }catch(error){process.stderr.write((error instanceof Error&&/^[a-z_: -]+$/.test(error.message)?error.message:'sbom_generation_failed')+'\n');process.exitCode=1;}
}
