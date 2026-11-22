#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-env.ps1')
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    cargo fmt --all -- --check
    if ($LASTEXITCODE) { throw 'rustfmt failed' }
    cargo test --workspace --locked
    if ($LASTEXITCODE) { throw 'workspace tests failed' }
    cargo test -p nw-llm --example privacy_eval --locked
    if ($LASTEXITCODE) { throw 'privacy evaluation scorer checks failed' }
    cargo test -p nw-core --example privacy_pipeline --locked
    if ($LASTEXITCODE) { throw 'privacy pipeline scorer checks failed' }
    if ($IsWindows) {
        cargo test -p nw-platform --test appcontainer actual_ --locked -- --ignored
        if ($LASTEXITCODE) { throw 'AppContainer isolation failed' }
        cargo test -p nw-probe --test worker actual_device_probe --locked -- --ignored
        if ($LASTEXITCODE) { throw 'device probe isolation failed' }
    }
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    if ($LASTEXITCODE) { throw 'clippy failed' }
    cargo test -p nw-leak-tests --locked
    if ($LASTEXITCODE) { throw 'leak tests failed' }
    cargo deny check --hide-inclusion-graph
    if ($LASTEXITCODE) { throw 'dependency checks failed' }
    cargo deny --manifest-path app/src-tauri/Cargo.toml check --hide-inclusion-graph
    if ($LASTEXITCODE) { throw 'desktop dependency checks failed' }
    cargo fmt --manifest-path daemons/nw-netd/Cargo.toml -- --check
    if ($LASTEXITCODE) { throw 'network rustfmt failed' }
    cargo test --manifest-path daemons/nw-netd/Cargo.toml --locked
    if ($LASTEXITCODE) { throw 'network tests failed' }
    cargo clippy --manifest-path daemons/nw-netd/Cargo.toml --all-targets --locked -- -D warnings
    if ($LASTEXITCODE) { throw 'network clippy failed' }
    cargo deny --manifest-path daemons/nw-netd/Cargo.toml check --hide-inclusion-graph
    if ($LASTEXITCODE) { throw 'network dependency checks failed' }
    cargo fmt --manifest-path fuzz/Cargo.toml -- --check
    if ($LASTEXITCODE) { throw 'fuzz rustfmt failed' }
    cargo check --manifest-path fuzz/Cargo.toml --all-targets --all-features --locked
    if ($LASTEXITCODE) { throw 'fuzz harness checks failed' }
    cargo deny --manifest-path fuzz/Cargo.toml --all-features check --hide-inclusion-graph
    if ($LASTEXITCODE) { throw 'fuzz dependency checks failed' }
    foreach ($frontend in @('extension', 'app')) {
        Push-Location $frontend
        try {
            npm ci
            if ($LASTEXITCODE) { throw 'npm ci failed' }
            npm test
            if ($LASTEXITCODE) { throw 'frontend checks failed' }
        } finally { Pop-Location }
    }
    node --test scripts/tests/*.test.mjs
    if ($LASTEXITCODE) { throw 'build tooling tests failed' }
    $sbomTarget=(rustc -vV | Select-String '^host: (.+)$').Matches.Groups[1].Value
    node scripts/sbom.mjs --target $sbomTarget --out target/sbom/nymwrap.cdx.json
    if ($LASTEXITCODE) { throw 'SBOM generation failed' }
    ./scripts/validate-sbom.ps1 -Path target/sbom/nymwrap.cdx.json
} finally { Pop-Location }
