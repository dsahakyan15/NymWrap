// Opt-in Windows developer check. The guest receives only synthetic test executables.
import {spawn,execFile} from 'node:child_process';
import {createServer} from 'node:http';
import {readFile,writeFile,mkdir,mkdtemp,lstat,realpath,rm} from 'node:fs/promises';
import {resolve,join,sep,dirname,win32} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {promisify,stripVTControlCharacters} from 'node:util';
import {sourceDigest} from './sbom.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const run=promisify(execFile),digest=(bytes,algorithm='sha256')=>createHash(algorithm).update(bytes).digest('hex');
export function probePackageAssets(lock){
  if(lock?.version!==1||lock.alpine!=='v3.24'||lock.arch!=='x86_64'||!Array.isArray(lock.packages)||lock.packages.length!==2)throw Error('invalid_probe_package_lock');
  return lock.packages.map((pkg,index)=>{
    const expected=['python3','bubblewrap'][index];
    if(!pkg||Object.keys(pkg).sort().join(',')!=='archive,bytes,license,name,repository,sha256,version'||pkg.name!==expected||
      !/^\d+\.\d+\.\d+-r\d+$/.test(pkg.version)||!['main','community'].includes(pkg.repository)||
      pkg.archive!==pkg.name+'-'+pkg.version+'.apk'||!Number.isInteger(pkg.bytes)||pkg.bytes<1||pkg.bytes>32*1024*1024||
      !/^[a-f0-9]{64}$/.test(pkg.sha256)||typeof pkg.license!=='string'||!pkg.license)throw Error('invalid_probe_package_lock');
    return {name:pkg.archive,package:pkg.name,version:pkg.version,repository:pkg.repository,url:'https://dl-cdn.alpinelinux.org/alpine/'+lock.alpine+'/'+pkg.repository+'/'+lock.arch+'/'+pkg.archive,hash:pkg.sha256,bytes:pkg.bytes};
  });
}
const packageManifestPath=fileURLToPath(new URL('./linux-probe-packages.lock.json',import.meta.url));
const packageManifestBytes=await readFile(packageManifestPath);
const packages=probePackageAssets(JSON.parse(packageManifestBytes));
export const assets=[
  {name:'qemu-w64-setup-20260811.exe',url:'https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.exe',algorithm:'sha512',hash:'5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543'},
  {name:'alpine-virt-3.24.4-x86_64.iso',url:'https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.4-x86_64.iso',hash:'157d353f8e54252cad2d9812a0d56bb7fa2231fc154a110e1d180d7480ef8b4f'},
  {name:'7z2606-x64.exe',url:'https://github.com/ip7z/7zip/releases/download/26.06/7z2606-x64.exe',hash:'9b697f65ecc2d9b0152f5ee96d72dde522a7827690349d9307935dacf40f42ec'},
  {name:'7zr.exe',url:'https://github.com/ip7z/7zip/releases/download/26.06/7zr.exe',hash:'e80db2dad715a6c5adabe292d31ed54e11f4e9b99ca349827b50573b175891bc'},
  ...packages,
];
const options={windowsHide:true,encoding:'utf8',maxBuffer:16*1024*1024,timeout:180000,cwd:root};
const normalized=value=>process.platform==='win32'?value.toLowerCase():value;
async function directory(parent,name){
  const path=join(parent,name);await mkdir(path,{recursive:false}).catch(e=>{if(e.code!=='EEXIST')throw e;});
  const stat=await lstat(path);
  if(stat.isSymbolicLink()||!stat.isDirectory()||normalized(await realpath(path))!==normalized(resolve(path)))throw Error('unsafe_probe_directory');
  return path;
}
async function regular(path){const stat=await lstat(path);if(stat.isSymbolicLink()||!stat.isFile())throw Error('unsafe_probe_file');return readFile(path);}
export function archivePaths(listing){
  const separator=listing.indexOf('----------');if(separator<0)throw Error('invalid_archive_listing');
  const paths=listing.slice(separator).split(/\r?\n/).filter(l=>l.startsWith('Path = ')).map(l=>l.slice(7));
  if(!paths.length||paths.some(p=>!p||win32.isAbsolute(p)||p.includes(':')||p.split(/[\\/]/).some(v=>v==='..'||v===''))||/^(Symbolic Link|Hard Link) =/m.test(listing))throw Error('unsafe_archive_entry');
  return paths;
}
function crc32(bytes){let crc=0xffffffff;for(const byte of bytes){crc^=byte;for(let i=0;i<8;i++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return (crc^0xffffffff)>>>0;}
export function sevenZipPayload(bytes){
  const magic=Buffer.from([0x37,0x7a,0xbc,0xaf,0x27,0x1c]);
  for(let from=0;;){
    const i=bytes.indexOf(magic,from);if(i<0)throw Error('missing_7zip_payload');from=i+magic.length;
    if(i+32<=bytes.length&&bytes.readUInt32LE(i+8)===crc32(bytes.subarray(i+12,i+32)))return bytes.subarray(i);
  }
}
async function cachedAsset(base,asset,prepare){
  const path=join(base,asset.name);let bytes;
  try{bytes=await regular(path);}catch(e){if(e.code!=='ENOENT')throw e;}
  if(!bytes){
    if(!prepare)throw Error('missing_probe_tools_run_with_prepare');
    const response=await fetch(asset.url,{signal:AbortSignal.timeout(180000)});if(!response.ok)throw Error('probe_download_failed');
    bytes=Buffer.from(await response.arrayBuffer());
    if(digest(bytes,asset.algorithm)!==asset.hash)throw Error('probe_asset_hash_mismatch');
    await writeFile(path,bytes,{flag:'wx'});
  }
  if(digest(bytes,asset.algorithm)!==asset.hash)throw Error('probe_asset_hash_mismatch');
  if(asset.bytes!==undefined&&bytes.length!==asset.bytes)throw Error('probe_asset_size_mismatch');
  return path;
}
async function main(){
  if(process.platform!=='win32')throw Error('windows_probe_only_use_check_sh_on_linux');
  if(process.argv.slice(2).some(a=>a!=='--prepare'))throw Error('usage: node scripts/linux-isolation-probe.mjs [--prepare]');
  const prepare=process.argv.includes('--prepare');
  const target=await directory(root,'target'),tools=await directory(target,'tools'),base=await directory(tools,'linux-probe');
  const reports=await directory(target,'linux-isolation');
  for(const name of ['serial.log','report.json']){try{await regular(join(reports,name));}catch(error){if(error.code!=='ENOENT')throw error;}}
  await writeFile(join(reports,'report.json'),JSON.stringify({version:2,status:'running',namespace_identity_tested:false,harness_sha256:digest(await regular(fileURLToPath(import.meta.url))),package_lock_sha256:digest(packageManifestBytes)},null,2)+'\n');
  await writeFile(join(reports,'serial.log'),'');
  if(digest(await regular(packageManifestPath))!==digest(packageManifestBytes))throw Error('probe_package_lock_changed');
  const paths=await Promise.all(assets.map(asset=>cachedAsset(base,asset,prepare)));
  if(prepare)await run('rustup',['target','add','x86_64-unknown-linux-musl'],options);
  const before=await sourceDigest(join(root,'crates')),lock=digest(await regular(join(root,'Cargo.lock')));
  const testSources=await sourceDigest(join(root,'tests/leak')),harness=digest(await regular(fileURLToPath(import.meta.url))),packageLock=digest(packageManifestBytes);
  const build=await run('cargo',['test','-p','nw-platform','-p','nw-sandbox','-p','nw-probe','--target','x86_64-unknown-linux-musl','--no-run','--locked','--message-format','json','--target-dir',join(reports,'build')],{...options,env:{...process.env,CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:'rust-lld'}});
  const launcherBuild=await run('cargo',['build','-p','nw-net','--example','linux-process-egress','--target','x86_64-unknown-linux-musl','--locked','--message-format','json','--target-dir',join(reports,'build')],{...options,env:{...process.env,CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:'rust-lld'}});
  const artifacts=(build.stdout+'\n'+launcherBuild.stdout).split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line)).filter(m=>m.reason==='compiler-artifact'&&m.executable);
  const files=new Map(),binaries={};
  for(const [name,kind,test] of [['nw_platform','lib',true],['nw_sandbox','lib',true],['agent','test',true],['nw_probe','lib',true],['worker','test',true],['nw-probe','bin',false],['linux-process-egress','example',false]]){
    const found=artifacts.filter(m=>m.target.name===name&&m.target.kind.includes(kind)&&m.profile.test===test);if(found.length!==1)throw Error('missing_probe_binary');
    const path=await realpath(found[0].executable);
    if(!normalized(path).startsWith(normalized(join(reports,'build')+sep)))throw Error('unsafe_probe_binary');
    const bytes=await regular(path);if(bytes.toString('hex',0,4)!=='7f454c46')throw Error('not_linux_elf');
    files.set('/'+name,bytes);binaries[name]=digest(bytes);
  }
  const repositoryIndexes={};
  for(const repository of [...new Set(packages.map(tool=>tool.repository))]){
    const response=await fetch('https://dl-cdn.alpinelinux.org/alpine/v3.24/'+repository+'/x86_64/APKINDEX.tar.gz',{signal:AbortSignal.timeout(60000)});
    if(!response.ok)throw Error('official_apk_index_unavailable');
    const bytes=Buffer.from(await response.arrayBuffer());if(bytes.length>8*1024*1024)throw Error('oversize_apk_index');
    repositoryIndexes[repository]=digest(bytes);
    files.set('/apk/'+repository+'/x86_64/APKINDEX.tar.gz',bytes);
    const path=join(reports,'apk-index-'+repository+'.tar.gz');
    try{await regular(path);}catch(error){if(error.code!=='ENOENT')throw error;}
    await writeFile(path,bytes);
  }
  for(const [index,tool]of packages.entries()){
    const bytes=await regular(paths[4+index]);files.set('/tool-'+tool.package+'.apk',bytes);
    files.set('/apk/'+tool.repository+'/x86_64/'+tool.name,bytes);
  }
  const fixture=await mkdtemp(join(base,'extract-'));
  let child,server,timer,log='',passed=false;
  try{
    const sevenDir=await directory(fixture,'7zip'),payload=join(fixture,'7zip.7z');
    await writeFile(payload,sevenZipPayload(await regular(paths[2])),{flag:'wx'});
    await run(paths[3],['e','-y','-bso0','-bsp0','-o'+sevenDir,payload,'7z.exe','7z.dll','License.txt'],options);
    const seven=join(sevenDir,'7z.exe');
    archivePaths((await run(seven,['l','-slt',paths[0]],options)).stdout);
    const qemu=await directory(fixture,'qemu');
    await run(seven,['x','-y','-bso0','-bsp0','-o'+qemu,paths[0]],options);
    const alpine=await directory(fixture,'alpine');
    await run('tar',['-xf',paths[1],'-C',alpine,'boot/vmlinuz-virt','boot/initramfs-virt'],options);
    server=createServer((request,response)=>{
      const bytes=request.method==='GET'?files.get(request.url):undefined;
      const packagePath=request.method==='GET'?/^\/apk\/(main|community)\/x86_64\/([A-Za-z0-9][A-Za-z0-9+_.-]*\.apk)$/.exec(request.url):null;
      if(!bytes&&packagePath&&Object.hasOwn(repositoryIndexes,packagePath[1])){
        response.writeHead(302,{'Location':'https://dl-cdn.alpinelinux.org/alpine/v3.24/'+packagePath[1]+'/x86_64/'+packagePath[2],'Content-Length':0,'Connection':'close'});response.end();return;
      }
      response.writeHead(bytes?200:404,{'Content-Length':bytes?.length??0,'Connection':'close'});response.end(bytes);
    });
    await new Promise((accept,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',accept);});
    const port=server.address().port;
    const commands=`set -eu
trap 'code=$?; echo NW_VM_TEST_EXIT:$code; poweroff -f' EXIT
export HISTFILE=/dev/null TERM=dumb NO_COLOR=1
ip link set lo up
printf '%s\\n' http://10.0.2.2:${port}/apk/main > /etc/apk/repositories
wget -q http://10.0.2.2:${port}/tool-python3.apk -O /tmp/python3.apk
echo '${packages[0].hash}  /tmp/python3.apk' | sha256sum -c -
wget -q http://10.0.2.2:${port}/tool-bubblewrap.apk -O /tmp/bubblewrap.apk
echo '${packages[1].hash}  /tmp/bubblewrap.apk' | sha256sum -c -
apk add --no-cache --no-progress python3=${packages[0].version} bubblewrap=${packages[1].version}
mkdir -p /opt/nw-probes
${[...files].filter(([path])=>Object.hasOwn(binaries,path.slice(1))).map(([path,bytes])=>`wget -q http://10.0.2.2:${port}${path} -O /opt/nw-probes${path}\necho '${digest(bytes)}  /opt/nw-probes${path}' | sha256sum -c -\nchmod 755 /opt/nw-probes${path}`).join('\n')}
adduser -D -h /home/nw-fixture nwtest
hostname nw-synthetic-host
echo NW_VM_KERNEL:$(uname -r)
bwrap --version
python3 --version
su -s /bin/sh -c 'test "$(id -u)" = 1000 && echo NW_VM_UID:$(id -u) && /opt/nw-probes/nw_platform --nocapture --color never && /opt/nw-probes/nw_sandbox --nocapture --color never && /opt/nw-probes/agent actual_agent --ignored --nocapture --color never && /opt/nw-probes/nw_probe --nocapture --color never && NW_PROBE_TEST_BINARY=/opt/nw-probes/nw-probe /opt/nw-probes/worker actual_device_probe --ignored --nocapture --color never' nwtest
/opt/nw-probes/nw_platform --exact sys::namespace_tests::actual_child_network_namespace_and_identity_cannot_escalate --ignored --test-threads=1 --nocapture --color never
mkdir /tmp/nw-launcher
chown 1000:1000 /tmp/nw-launcher
unshare -n sleep 300 &
keeper=$!
sleep 1
for mode in --failure-probe --cancel-probe; do
  GITHUB_ACTIONS=true /opt/nw-probes/linux-process-egress "$mode" /tmp/nw-launcher "/proc/$keeper/ns/net" 1000 1000
done
kill "$keeper"
wait "$keeper" || test "$?" = 143
`;
    files.set('/script',Buffer.from(commands));
    child=spawn(join(qemu,'qemu-system-x86_64.exe'),['-no-user-config','-nodefaults','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','1536','-display','none','-monitor','none','-serial','stdio','-no-reboot','-kernel',join(alpine,'boot/vmlinuz-virt'),'-initrd',join(alpine,'boot/initramfs-virt'),'-append','console=ttyS0,115200 modules=loop,squashfs,sd-mod,usb-storage quiet','-cdrom',paths[1],'-nic','user,model=virtio-net-pci'],{cwd:fixture,windowsHide:true,stdio:['pipe','pipe','pipe']});
    child.stdin.on('error',()=>{});
    timer=setTimeout(()=>child.kill(),360000);
    let state='boot',sends=Promise.resolve();
    // A paced UART avoids dropping input while the guest's tiny FIFO is being drained.
    const send=text=>{sends=sends.then(async()=>{for(let i=0;i<text.length;i+=8){if(child.exitCode!==null)return;child.stdin.write(text.slice(i,i+8));await new Promise(r=>setTimeout(r,10));}}).catch(()=>child.kill());};
    const collect=chunk=>{
      log+=chunk.toString('utf8');if(log.length>2*1024*1024){child.kill();return;}
      if(state==='boot'&&/login:/.test(log)){state='login';send('root\n');}
      if(state==='login'&&/localhost:~#/.test(log)){
        state='script';send(`stty -echo; ip link set eth0 up; udhcpc -i eth0 -n -q; wget -q http://10.0.2.2:${port}/script -O /tmp/nw-probe.sh && sh /tmp/nw-probe.sh\n`);
      }
    };
    child.stdout.on('data',collect);child.stderr.on('data',collect);
    const code=await new Promise((accept,reject)=>{child.once('error',reject);child.once('exit',accept);});
    log=stripVTControlCharacters(log);
    const succeeded=code===0&&/NW_VM_TEST_EXIT:0\r?\n/.test(log)&&log.includes('NW_VM_UID:1000')
      && ['seccomp_denies_ip_sockets_but_keeps_private_ipc','seccomp_covers_existing_and_future_threads','actual_agent_sees_only_http_socket_and_cannot_open_external_sockets','actual_child_network_namespace_and_identity_cannot_escalate'].every(name=>new RegExp(name+'[^\\r\\n]* \\.\\.\\. ok').test(log));
    if(digest(await regular(packageManifestPath))!==packageLock||await sourceDigest(join(root,'crates'))!==before||await sourceDigest(join(root,'tests/leak'))!==testSources||digest(await regular(fileURLToPath(import.meta.url)))!==harness||digest(await regular(join(root,'Cargo.lock')))!==lock)throw Error('probe_sources_changed');
    if(!succeeded||!log.includes('actual_device_probe_is_confined_and_uses_only_bounded_shadow_frames ... ok')||
      !['--failure-probe','--cancel-probe'].every(mode=>log.includes('NW_LAUNCHER_PROBE_VERIFIED:'+mode)))throw Error('linux_isolation_probe_failed');
    passed=true;
  }finally{
    clearTimeout(timer);
    if(child&&child.exitCode===null&&!child.killed){child.kill();await new Promise(accept=>{child.once('exit',accept);setTimeout(accept,5000).unref();});}
    server?.closeAllConnections();if(server?.listening)await new Promise(accept=>server.close(accept));
    await writeFile(join(reports,'serial.log'),stripVTControlCharacters(log));
    await writeFile(join(reports,'report.json'),JSON.stringify({version:3,repository_index_sha256:repositoryIndexes,package_lock_sha256:packageLock,test_sources_sha256:testSources,harness_sha256:harness,namespace_identity_tested:passed,production_launcher_failure_and_cancellation_tested:passed,administrative_fixture: true,status:passed?'passed':'failed',target:'x86_64-unknown-linux-musl',unprivileged_uid:passed?1000:null,kernel:log.match(/NW_VM_KERNEL:([^\r\n]+)/)?.[1]??null,source_sha256:before,lock_sha256:lock,binaries,assets:assets.map(({name,hash,algorithm})=>({name,hash,algorithm:algorithm??'sha256'}))},null,2)+'\n');
    const actual=await realpath(fixture),parent=await realpath(base),stat=await lstat(fixture);
    if(stat.isSymbolicLink()||!normalized(actual).startsWith(normalized(parent+sep)))throw Error('unsafe_probe_cleanup');
    await rm(fixture,{recursive:true,force:true});
  }
  console.log('Linux isolation probe passed: target/linux-isolation/report.json');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
