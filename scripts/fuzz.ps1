param(
    [Parameter(Mandatory)][ValidateSet('audit_import','ipc_frames','shield_roundtrip')][string]$Target,
    [ValidateRange(1,86400)][int]$Seconds = 60
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-env.ps1')
# The runtime DLL must be visible to the fuzz child, without changing user PATH.
$msvcRoot = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC'
$asanBin = Get-ChildItem -LiteralPath $msvcRoot -Directory | Sort-Object { [version]$_.Name } -Descending | ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64' } | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'clang_rt.asan_dynamic-x86_64.dll') } | Select-Object -First 1
if (!$asanBin) { throw 'msvc_address_sanitizer_required' }
$env:PATH = $asanBin + ';' + $env:PATH
node (Join-Path $PSScriptRoot 'fuzz.mjs') --target $Target --seconds $Seconds
if ($LASTEXITCODE) { throw 'fuzz_failed' }
