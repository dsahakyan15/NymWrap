# Explicit developer command. The application never downloads models itself.
$ErrorActionPreference = 'Stop'
$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modelPath = Join-Path $workspacePath 'target\test-models'
New-Item -ItemType Directory -Path $modelPath -Force | Out-Null
$models = @(
    @{ Name='qwen2.5-0.5b-instruct-q4_k_m.gguf'; Repo='Qwen/Qwen2.5-0.5B-Instruct-GGUF'; Revision='9217f5db79a29953eb74d5343926648285ec7e67'; Hash='74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db' },
    @{ Name='nomic-embed-text-v1.5.Q4_K_M.gguf'; Repo='nomic-ai/nomic-embed-text-v1.5-GGUF'; Revision='0188c9bf409793f810680a5a431e7b899c46104c'; Hash='d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac' }
)
foreach ($model in $models) {
    $destination = Join-Path $modelPath $model.Name
    if (-not (Test-Path -LiteralPath $destination)) {
        $partial = $destination + '.part'
        Invoke-WebRequest -Uri ('https://huggingface.co/' + $model.Repo + '/resolve/' + $model.Revision + '/' + $model.Name) -OutFile $partial
        if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $model.Hash) { throw 'Model hash mismatch' }
        Move-Item -LiteralPath $partial -Destination $destination
    }
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $model.Hash) { throw 'Model hash mismatch' }
    Write-Output ($model.Name + ' verified')
}
