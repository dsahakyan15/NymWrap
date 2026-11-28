# Build-only dependency for vendored OpenSSL on Windows. No system installation.
$ErrorActionPreference = 'Stop'
$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolsPath = Join-Path $workspacePath 'target\tools'
$archivePath = Join-Path $toolsPath 'strawberry-perl-5.40.5.1.zip'
$extractPath = Join-Path $toolsPath 'strawberry-perl-5.40.5.1'
New-Item -ItemType Directory -Path $toolsPath -Force | Out-Null
$expectedHash = '6619fe7eeef921ccddb4aac3972fb602a0c690a3074205b863ade998d7bc79a6'
if (-not (Test-Path -LiteralPath $archivePath)) {
    Invoke-WebRequest -Uri 'https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54051_64bit/strawberry-perl-5.40.5.1-64bit-portable.zip' -OutFile $archivePath
}
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'Perl archive hash mismatch' }
# Windows PowerShell 5.1 does not load ZipFile by default.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($entry in $archive.Entries) {
        if ($entry.FullName -notmatch '^perl/(bin|lib)/' -or $entry.FullName.EndsWith('/')) { continue }
        $destination = [System.IO.Path]::GetFullPath((Join-Path $extractPath $entry.FullName))
        $allowedRoot = [System.IO.Path]::GetFullPath($extractPath) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $destination.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid archive path' }
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destination, $true)
    }
} finally { $archive.Dispose() }
Write-Output (Join-Path $extractPath 'perl\bin\perl.exe')
