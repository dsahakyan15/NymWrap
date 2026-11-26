import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {verify} from '../fetch-microvm.mjs';
test('MicroVM tool bytes and digest are mandatory',()=>{
  const bytes=Buffer.from('synthetic-pinned-tool');const asset={bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};
  assert.equal(verify(bytes,asset),bytes);
  assert.throws(()=>verify(Buffer.from('replacement'),asset),/hash_mismatch/);
  assert.throws(()=>verify(bytes,{...asset,bytes:1}),/hash_mismatch/);
});
test('MicroVM tools have fixed versions, HTTPS URLs, lengths and SHA256',async()=>{
  const manifest=JSON.parse(await readFile(new URL('../microvm-binaries.json',import.meta.url)));
  assert.equal(manifest.platform,'linux-x86_64');
  for(const asset of [...manifest.archives,...manifest.files,...Object.values(manifest.compiler.platforms)]) {
    assert.match(asset.sha256,/^[a-f0-9]{64}$/);assert.ok(asset.bytes>0);
    if(asset.url)assert.match(asset.url,/^https:\/\//);
  }
});
