# Dot-source before Cargo on Windows. Installs nothing; bootstraps are explicit.
$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$perlPath = Join-Path $workspacePath 'target\tools\strawberry-perl-5.40.5.1\perl\bin\perl.exe'
if (-not $env:OPENSSL_SRC_PERL -and (Test-Path -LiteralPath $perlPath)) { $env:OPENSSL_SRC_PERL = $perlPath }
$clangPath = Join-Path $workspacePath 'target\tools\libclang-18.1.1'
if (-not $env:LIBCLANG_PATH -and (Test-Path -LiteralPath (Join-Path $clangPath 'libclang.dll'))) { $env:LIBCLANG_PATH = $clangPath }
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    $cmakePath = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
    if (Test-Path -LiteralPath (Join-Path $cmakePath 'cmake.exe')) { $env:PATH = $cmakePath + ';' + $env:PATH }
}
