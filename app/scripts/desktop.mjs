import {existsSync,copyFileSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {resolve,delimiter} from "node:path";
import {spawn} from "node:child_process";
import {installTransport} from "../../scripts/fetch-transports.mjs";
const app=fileURLToPath(new URL("..",import.meta.url));
const root=resolve(app,"..");
const env={...process.env};
if(process.platform==="win32"){
  const environmentKey=name=>Object.keys(env).find(key=>key.toLowerCase()===name.toLowerCase())??name;
  const perl=resolve(root,"target/tools/strawberry-perl-5.40.5.1/perl/bin/perl.exe");
  if(!env[environmentKey("OPENSSL_SRC_PERL")]&&existsSync(perl))env[environmentKey("OPENSSL_SRC_PERL")]=perl;
  const clang=resolve(root,"target/tools/libclang-18.1.1");
  if(!env[environmentKey("LIBCLANG_PATH")]&&existsSync(resolve(clang,"libclang.dll")))env[environmentKey("LIBCLANG_PATH")]=clang;
  const cmake="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin";
  if(existsSync(resolve(cmake,"cmake.exe"))){
    const pathKey=environmentKey("PATH");
    env[pathKey]=cmake+delimiter+(env[pathKey]??"");
  }
}
const release=process.argv.includes("--build");
function run(program,args,cwd){return new Promise((resolve,reject)=>{
  const child=spawn(program,args,{cwd,env,stdio:"inherit",windowsHide:true});
  child.once("error",reject);child.once("exit",code=>code===0?resolve():reject(new Error("desktop_build_failed")));
});}
try{
  await run("cargo",["build","--workspace","--bins","--locked",...(release?["--release"]:[])],root);
  await run("cargo",["build","--manifest-path","daemons/nw-netd/Cargo.toml","--locked",...(release?["--release"]:[])],root);
  const platform=`${process.platform==="win32"?"windows":process.platform==="darwin"?"macos":process.platform}-${process.arch==="arm64"?"aarch64":process.arch==="x64"?"x86_64":process.arch}`;
  await installTransport(platform,resolve(root,`daemons/nw-netd/target/${release?"release":"debug"}/transports`));
  await run(process.execPath,[resolve(app,"node_modules/@tauri-apps/cli/tauri.js"),...(release?["build","--no-bundle"]:["dev"])],app);
  if(release)for(const name of ["nymwrap","nymwrapd","nw-api","nw-llmd","nw-drift-host","nw-audit-worker","nw-probe"]){
    const file=name+(process.platform==="win32"?".exe":"");
    copyFileSync(resolve(root,"target/release",file),resolve(app,"src-tauri/target/release",file));
  }
  if(release){const file="nw-netd"+(process.platform==="win32"?".exe":"");copyFileSync(resolve(root,"daemons/nw-netd/target/release",file),resolve(app,"src-tauri/target/release",file));}
  if(release)await installTransport(platform,resolve(app,"src-tauri/target/release/transports"));
}catch{process.stderr.write("desktop_build_failed\n");process.exitCode=1;}
