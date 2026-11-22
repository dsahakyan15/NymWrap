import {lstat} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../../..');
export async function fixtureCertificate(){
  const portable=resolve(root,'target/tools/powershell-7.7.0/pwsh.exe');
  const pwsh=process.platform==='win32'&&await lstat(portable).catch(()=>false)?portable:'pwsh';
  // Ephemeral key material stays in child stdout/parent memory, never the OS store or a file.
  const script=`$ErrorActionPreference='Stop'
$rsa=[System.Security.Cryptography.RSA]::Create(2048)
$cert=$null
try {
  $request=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=NymWrap Synthetic',$rsa,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1),[DateTimeOffset]::UtcNow.AddDays(1))
  $certificate=[Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
  $private=[Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey())
  @{cert="-----BEGIN CERTIFICATE-----\n$certificate\n-----END CERTIFICATE-----";key="-----BEGIN PRIVATE KEY-----\n$private\n-----END PRIVATE KEY-----"}|ConvertTo-Json -Compress
} finally {if($null -ne $cert){$cert.Dispose()};$rsa.Dispose()}`;
  const {stdout}=await promisify(execFile)(pwsh,['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,env:{...process.env,POWERSHELL_TELEMETRY_OPTOUT:'1'},timeout:15000});
  return JSON.parse(stdout);
}
