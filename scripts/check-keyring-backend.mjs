// Resolve Linux features even on Windows: the host tree cannot check Secret Service.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync,statSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const manifests={root:'Cargo.toml',desktop:'app/src-tauri/Cargo.toml'};
const scopes=process.argv.slice(2);
assert(scopes.every(scope=>Object.hasOwn(manifests,scope)), 'invalid_keyring_check_scope');
for(const scope of scopes.length?scopes:Object.keys(manifests)){
  const manifest=manifests[scope];
  for(const features of [[],['--all-features']]){
    const tree=execFileSync('cargo',['tree','--manifest-path',resolve(root,manifest),
      '--locked','--offline','--target','x86_64-unknown-linux-gnu','-e','features',
      '--prefix','none','-i','dbus-secret-service',...features],{cwd:root,encoding:'utf8',windowsHide:true});
    assert.match(tree,/dbus-secret-service feature "crypto-openssl"/);
    assert.match(tree,/dbus-secret-service feature "vendored"/);
    assert.doesNotMatch(tree,/feature "crypto-rust"/);
    assert.match(tree,/dbus-secret-service v4\.1\.0 \([^\n]*[\\/]vendor[\\/]dbus-secret-service\)/);
  }
  const metadata=JSON.parse(execFileSync('cargo',['metadata','--manifest-path',resolve(root,manifest),
    '--locked','--offline','--format-version','1'],{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:64*1024*1024}));
  // Cargo's offline flag does not sandbox build scripts. Check the exact input
  // that would otherwise cause libdbus-sys to run `git submodule update`.
  for(const [name,version,sentinel,archiveSha] of [
    ['libdbus-sys','0.2.7','vendor/dbus/dbus','328c4789d42200f1eeec05bd86c9c13c7f091d2ba9a6ea35acdf51f31bc0f043'],
    ['openssl-src','300.6.1+3.6.3','openssl/Configure','46eb8fb9fb3b61ce1c0f8a026c4c1a0714d3a9e138e7fbde78753ce2babc3846'],
  ]){
    const pkg=metadata.packages.find(pkg=>pkg.name===name&&pkg.version===version);
    assert(pkg,`missing_vendored_package: ${name}`);
    const base=dirname(pkg.manifest_path);
    const input=statSync(join(base,sentinel));
    assert(name==='libdbus-sys'?input.isDirectory():input.isFile(),`missing_vendored_input: ${name}`);
    const archive=join(base,'../../../cache',dirname(base).split(/[\\/]/).at(-1),`${name}-${version}.crate`);
    const actual=createHash('sha256').update(readFileSync(archive)).digest('hex');
    assert.equal(actual,archiveSha,`vendored_archive_changed: ${name}`);
  }
  console.log(`${manifest}: Linux Secret Service selects crypto-openssl + vendored`);
}
