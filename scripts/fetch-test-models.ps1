# Explicit developer command. The application never downloads models itself.
param([switch]$IncludeMultilingualEmbedding, [switch]$IncludeMidSizeChat)
$ErrorActionPreference = 'Stop'
$workspacePath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modelPath = Join-Path $workspacePath 'target\test-models'
New-Item -ItemType Directory -Path $modelPath -Force | Out-Null
$models = @(
    @{ Name='qwen2.5-0.5b-instruct-q4_k_m.gguf'; Repo='Qwen/Qwen2.5-0.5B-Instruct-GGUF'; Revision='9217f5db79a29953eb74d5343926648285ec7e67'; Hash='74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db' },
    @{ Name='nomic-embed-text-v1.5.Q4_K_M.gguf'; Repo='nomic-ai/nomic-embed-text-v1.5-GGUF'; Revision='0188c9bf409793f810680a5a431e7b899c46104c'; Hash='d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac' }
)
# Mid-size official Qwen2.5 instruct GGUFs for Drift planning checks (tests/e2e/local.mjs --model-1.5b|--model-3b).
if ($IncludeMidSizeChat) {
    $models += @{ Name='qwen2.5-1.5b-instruct-q4_k_m.gguf'; Repo='Qwen/Qwen2.5-1.5B-Instruct-GGUF'; Revision='91cad51170dc346986eccefdc2dd33a9da36ead9'; Hash='6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e' }
    $models += @{ Name='qwen2.5-3b-instruct-q4_k_m.gguf'; Repo='Qwen/Qwen2.5-3B-Instruct-GGUF'; Revision='7dabda4d13d513e3e842b20f0d435c732f172cbe'; Hash='626b4a6678b86442240e33df819e00132d3ba7dddfe1cdc4fbb18e0a9615c62d' }
}
if ($IncludeMultilingualEmbedding) {
    $models += @{ Name='Qwen3-Embedding-0.6B-Q8_0.gguf'; Repo='Qwen/Qwen3-Embedding-0.6B-GGUF'; Revision='370f27d7550e0def9b39c1f16d3fbaa13aa67728'; Hash='06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439' }
}
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
