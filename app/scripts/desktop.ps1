param([switch]$Build)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../scripts/build-env.ps1')
Push-Location (Join-Path $PSScriptRoot '..')
try {
    if ($Build) { npx tauri build --no-bundle } else { npx tauri dev }
    if ($LASTEXITCODE) { throw 'Tauri build failed' }
} finally { Pop-Location }
