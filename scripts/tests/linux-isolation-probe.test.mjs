import {test} from 'node:test';
import assert from 'node:assert/strict';
import {archivePaths,sevenZipPayload} from '../linux-isolation-probe.mjs';

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
