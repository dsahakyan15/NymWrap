#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo test --workspace --locked
cargo build -p nw-api -p nw-core --bins --locked
cargo test -p nw-core --test rpc_process actual_ --locked -- --ignored
cargo test -p nw-llm --example privacy_eval --locked
cargo test -p nw-core --example privacy_pipeline --locked
cargo test -p nw-core --example privacy_linkcheck --locked
if [ "$(uname -s)" = Linux ]; then
  cargo test -p nw-sandbox --test agent actual_agent --locked -- --ignored
fi
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p nw-leak-tests --locked
cargo deny check --hide-inclusion-graph
cargo deny --manifest-path app/src-tauri/Cargo.toml check --hide-inclusion-graph
cargo fmt --manifest-path daemons/nw-netd/Cargo.toml -- --check
cargo test --manifest-path daemons/nw-netd/Cargo.toml --locked
cargo clippy --manifest-path daemons/nw-netd/Cargo.toml --all-targets --locked -- -D warnings
cargo deny --manifest-path daemons/nw-netd/Cargo.toml check --hide-inclusion-graph
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo check --manifest-path fuzz/Cargo.toml --all-targets --all-features --locked
cargo deny --manifest-path fuzz/Cargo.toml --all-features check --hide-inclusion-graph
(cd extension && npm ci && npm test)
(cd app && npm ci && npm test)
node --test scripts/tests/*.test.mjs
node scripts/vet-dependencies.mjs
