param(
    [ValidateSet('Chrome','Edge','Firefox')][string]$Browser='Chrome',
    [string]$ExtensionId,
    [string]$BinaryPath,
    [switch]$Unregister
)
$ErrorActionPreference='Stop'
$workspacePath=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$hostName='org.nymwrap.drift'
$manifestDirectory=Join-Path $env:LOCALAPPDATA 'NymWrap\native-host'
$manifestPath=Join-Path $manifestDirectory ($Browser.ToLowerInvariant()+'.json')
$registryPath=switch($Browser){
    'Chrome' {'HKCU:\Software\Google\Chrome\NativeMessagingHosts\'+$hostName}
    'Edge' {'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\'+$hostName}
    'Firefox' {'HKCU:\Software\Mozilla\NativeMessagingHosts\'+$hostName}
}
if($Unregister){
    if(Test-Path -LiteralPath $registryPath){Remove-Item -LiteralPath $registryPath}
    if(Test-Path -LiteralPath $manifestPath){
        $existing=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
        if($existing.name -ne $hostName){throw 'Unexpected native manifest; refusing removal'}
        Remove-Item -LiteralPath $manifestPath
    }
    Write-Output 'Native host registration removed';return
}
if(-not $BinaryPath){$BinaryPath=Join-Path $workspacePath 'target\release\nw-drift-host.exe'}
$binary=(Resolve-Path -LiteralPath $BinaryPath).Path
if([System.IO.Path]::GetFileName($binary) -ne 'nw-drift-host.exe'){throw 'Expected nw-drift-host.exe'}
$manifest=@{name=$hostName;description='NymWrap cover lane only';path=$binary;type='stdio'}
if($Browser -eq 'Firefox'){
    if(-not $ExtensionId){$ExtensionId='nymwrap@example.invalid'}
    if($ExtensionId -notmatch '^[a-zA-Z0-9@._{}-]{3,128}$'){throw 'Invalid Firefox extension ID'}
    $manifest.allowed_extensions=@($ExtensionId)
}else{
    if($ExtensionId -notmatch '^[a-p]{32}$'){throw 'Pass the 32-letter extension ID shown by your browser'}
    $manifest.allowed_origins=@('chrome-extension://'+$ExtensionId+'/')
}
New-Item -ItemType Directory -Path $manifestDirectory -Force|Out-Null
if(Test-Path -LiteralPath $manifestPath){
    $existing=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    if($existing.name -ne $hostName){throw 'Unexpected native manifest; refusing overwrite'}
}
$manifest|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
New-Item -Path $registryPath -Force|Out-Null
Set-Item -LiteralPath $registryPath -Value $manifestPath
Write-Output ('Registered '+$Browser+' native host: '+$manifestPath)
