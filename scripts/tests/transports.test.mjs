import{test}from'node:test';
import assert from'node:assert/strict';
import{gzipSync}from'node:zlib';
import{createHash}from'node:crypto';
import{resolve}from'node:path';
import{manifest,selectArtifact,buildDestination,extractTransport}from'../fetch-transports.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(type='0',duplicate=false){
  const binary=Buffer.from('SYNTHETIC_TRANSPORT_BINARY_34912'),header=Buffer.alloc(512);
  header.write('tor/pluggable_transports/lyrebird');header.write(binary.length.toString(8).padStart(11,'0'),124);header.fill(32,148,156);header.write(type,156);
  header.write(header.reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148);
  const entry=Buffer.concat([header,binary,Buffer.alloc(512-binary.length)]),archive=gzipSync(Buffer.concat([entry,...(duplicate?[entry]:[]),Buffer.alloc(1024)]));
  return {archive,artifact:{archive_sha256:hash(archive),member:'tor/pluggable_transports/lyrebird',bytes:binary.length,binary_sha256:hash(binary)},binary};
}
test('transport selection pins five desktop platforms and refuses arbitrary paths',()=>{
  assert.equal(manifest.artifacts.length,5);assert.equal(selectArtifact('windows-x86_64').bytes,19086848);
  assert.throws(()=>selectArtifact('../host-program'));const workspace=resolve('synthetic-build');
  assert.equal(buildDestination(workspace,resolve(workspace,'target/debug/transports')),resolve(workspace,'target/debug/transports'));
  for(const path of ['../outside','target/../secret','target'])assert.throws(()=>buildDestination(workspace,resolve(workspace,path)));
});
test('only a regular member with matching archive and executable hashes can be installed',()=>{
  const {archive,artifact,binary}=fixture();assert.deepEqual(extractTransport(archive,artifact),binary);
  assert.throws(()=>extractTransport(Buffer.from('not an archive'),artifact));
  assert.throws(()=>extractTransport(archive,{...artifact,binary_sha256:'0'.repeat(64)}));
  for(const [type,duplicate]of [['2',false],['1',false],['0',true]]){const bad=fixture(type,duplicate);assert.throws(()=>extractTransport(bad.archive,bad.artifact));}
});
