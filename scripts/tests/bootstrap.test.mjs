import{test}from'node:test';
import assert from'node:assert/strict';
import{readFileSync,existsSync}from'node:fs';
import{spawnSync}from'node:child_process';
import{fileURLToPath}from'node:url';
const root=fileURLToPath(new URL('../..',import.meta.url));
const scripts=[['bootstrap-perl.ps1','strawberry-perl-5.40.5.1.zip'],['bootstrap-libclang.ps1','libclang-18.1.1-win-amd64.whl']];
test('bootstrap scripts load ZipFile before use so Windows PowerShell 5.1 can run them',()=>{
  for(const [name] of scripts){
    const text=readFileSync(new URL(`../${name}`,import.meta.url),'utf8');
    const load=text.indexOf('Add-Type -AssemblyName System.IO.Compression.FileSystem'),use=text.indexOf('[System.IO.Compression.ZipFile]');
    assert.ok(load>=0&&use>load,name);
  }
});
test('bootstrap scripts run under Windows PowerShell 5.1 with cached pinned archives',{skip:process.platform!=='win32'},t=>{
  for(const [name,archive] of scripts){
    if(!existsSync(`${root}/target/tools/${archive}`)){t.diagnostic(`${name}: archive not cached`);continue;}
    const run=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',`${root}/scripts/${name}`],{encoding:'utf8',windowsHide:true});
    assert.equal(run.status,0,`${name}: ${run.stderr}`);
  }
});
