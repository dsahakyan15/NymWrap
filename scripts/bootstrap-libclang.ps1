# Build-only libclang, unpacked locally. No Python or system installation required.
$ErrorActionPreference = 'Stop'
$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolsPath = Join-Path $workspacePath 'target\tools'
$archivePath = Join-Path $toolsPath 'libclang-18.1.1-win-amd64.whl'
$extractPath = Join-Path $toolsPath 'libclang-18.1.1'
New-Item -ItemType Directory -Path $toolsPath -Force | Out-Null
$expectedHash = '4dd2d3b82fab35e2bf9ca717d7b63ac990a3519c7e312f19fa8e86dcc712f7fb'
if (-not (Test-Path -LiteralPath $archivePath)) {
    Invoke-WebRequest -Uri 'https://files.pythonhosted.org/packages/0b/2d/3f480b1e1d31eb3d6de5e3ef641954e5c67430d5ac93b7fa7e07589576c7/libclang-18.1.1-py2.py3-none-win_amd64.whl' -OutFile $archivePath
}
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'libclang archive hash mismatch' }
# Windows PowerShell 5.1 does not load ZipFile by default.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($entry in $archive.Entries) {
        if ($entry.FullName -notin @('libclang-18.1.1.data/platlib/clang/native/libclang.dll', 'libclang-18.1.1.dist-info/LICENSE.TXT')) { continue }
        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $extractPath ([System.IO.Path]::GetFileName($entry.FullName))), $true)
    }
} finally { $archive.Dispose() }
if (-not (Test-Path -LiteralPath (Join-Path $extractPath 'libclang.dll'))) { throw 'libclang missing from archive' }
Write-Output $extractPath
