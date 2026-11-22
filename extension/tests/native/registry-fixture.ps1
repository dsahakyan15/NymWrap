#Requires -Version 7.0
param(
    [Parameter(Mandatory)][ValidateSet('Register','Remove')][string]$Mode,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Manifest
)
$ErrorActionPreference='Stop'
if($Name -notmatch '^org\.nymwrap\.fixture[a-f0-9]{24}$'){throw 'invalid_fixture_host'}
$manifestPath=[IO.Path]::GetFullPath($Manifest)
$description=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if($description.name -ne $Name -or $description.type -ne 'stdio'){throw 'unexpected_fixture_manifest'}
$parentPaths=@('HKCU:\Software\Mozilla','HKCU:\Software\Mozilla\NativeMessagingHosts')
$entry=Join-Path $parentPaths[-1] $Name
$statePath=Join-Path (Split-Path -Parent $manifestPath) 'registry-state.json'
if($Mode -eq 'Register'){
    if(Test-Path -LiteralPath $entry){throw 'fixture_registry_entry_exists'}
    $created=@()
    foreach($parent in $parentPaths){
        if(!(Test-Path -LiteralPath $parent)){
            New-Item -Path $parent | Out-Null
            $created+=,$parent
        }
    }
    @{name=$Name;manifest=$manifestPath;parents=$created} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8NoBOM
    New-Item -Path $entry | Out-Null
    Set-Item -LiteralPath $entry -Value $manifestPath
}else{
    if(!(Test-Path -LiteralPath $statePath)){return}
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if($state.name -ne $Name -or $state.manifest -ne $manifestPath -or @($state.parents | Where-Object {$_ -notin $parentPaths}).Count){throw 'unexpected_fixture_registry_state'}
    if(Test-Path -LiteralPath $entry){
        $key=Get-Item -LiteralPath $entry
        try{if($key.GetValue('') -ne $manifestPath -or $key.GetSubKeyNames().Length){throw 'fixture_registry_changed'}}finally{$key.Close()}
        Remove-Item -LiteralPath $entry -Confirm:$false
    }
    $parents=@($state.parents);[array]::Reverse($parents)
    foreach($parent in $parents){
        if(Test-Path -LiteralPath $parent){
            $key=Get-Item -LiteralPath $parent
            try{$empty=($key.GetSubKeyNames().Length -eq 0 -and $key.GetValueNames().Length -eq 0)}finally{$key.Close()}
            if($empty){Remove-Item -LiteralPath $parent -Confirm:$false}
        }
    }
}
