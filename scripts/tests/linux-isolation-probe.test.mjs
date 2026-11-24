import {test} from 'node:test';
import assert from 'node:assert/strict';
import {archivePaths,sevenZipPayload,probePackageAssets} from '../linux-isolation-probe.mjs';

test('guest package lock fixes official archives and rejects path or version substitutions',()=>{
  const lock={version:1,alpine:'v3.24',arch:'x86_64',packages:[
    {name:'python3',version:'3.14.10-r2',repository:'main',archive:'python3-3.14.10-r2.apk',sha256:'a'.repeat(64),bytes:100,license:'PSF-2.0'},
    {name:'bubblewrap',version:'0.12.0-r0',repository:'main',archive:'bubblewrap-0.12.0-r0.apk',sha256:'b'.repeat(64),bytes:100,license:'LGPL-2.1-or-later'}]};
  const assets=probePackageAssets(lock);
  assert.equal(assets[0].url,'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/python3-3.14.10-r2.apk');
  for(const change of [x=>x.arch='../x86_64',x=>x.alpine='latest',x=>x.packages.pop(),x=>x.packages.reverse(),
    x=>x.packages[0].version='latest',x=>x.packages[0].archive='../../program',x=>x.packages[0].repository='main/../outside',
    x=>x.packages[0].sha256='',x=>x.packages[0].bytes=33*1024*1024,x=>x.packages[0].url='https://example.test/payload']){
    const altered=structuredClone(lock);change(altered);assert.throws(()=>probePackageAssets(altered),/invalid_probe_package_lock/);
  }
});

test('VM tool extraction rejects traversal, absolute paths and archive links',()=>{
  for(const path of ['../worker.exe','..\\worker.exe','C:\\worker.exe','/tmp/worker','\\\\server\\file','directory:stream','safe\\..\\worker','safe//worker']){
    assert.throws(()=>archivePaths('----------\nPath = '+path+'\n'),/unsafe_archive_entry/);
  }
  for(const type of ['Symbolic Link','Hard Link'])assert.throws(()=>archivePaths('----------\nPath = worker\n'+type+' = /outside\n'),/unsafe_archive_entry/);
  assert.deepEqual(archivePaths('Path = installer.exe\n----------\nPath = share\\qemu\\bios.bin\n\nPath = qemu-system-x86_64.exe\n'),['share\\qemu\\bios.bin','qemu-system-x86_64.exe']);
});
test('SFX payload scanning skips magic constants without a valid start-header CRC',()=>{
  const magic=Buffer.from([0x37,0x7a,0xbc,0xaf,0x27,0x1c]);
  assert.throws(()=>sevenZipPayload(Buffer.concat([magic,Buffer.alloc(26)])),/missing_7zip_payload/);
  // CRC-32 of twenty zero bytes is 0x0fd59b8d; an earlier magic is only a stub constant.
  const header=Buffer.alloc(32);magic.copy(header);header.writeUInt32LE(0x0fd59b8d,8);
  const body=Buffer.concat([magic,Buffer.alloc(5),header,Buffer.from('fixture')]);
  assert.equal(sevenZipPayload(body).length,header.length+7);
});
