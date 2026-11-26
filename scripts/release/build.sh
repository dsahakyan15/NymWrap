#!/usr/bin/env bash
set -euo pipefail
umask 022
[[ ${NW_RELEASE_COMMIT:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${SOURCE_DATE_EPOCH:?} =~ ^[0-9]+$ ]]
mkdir -p /build/source /build/payload/transports
tar -xf /input/source.tar -C /build/source
cd /build/source

# Lockfiles verify every downloaded crate/npm archive. No compiled cache is mounted.
for manifest in Cargo.toml daemons/nw-netd/Cargo.toml app/src-tauri/Cargo.toml; do
  cargo fetch --manifest-path "$manifest" --locked
done
# Inventory the pristine exported source before Tauri writes generated schemas.
node scripts/sbom.mjs --target x86_64-unknown-linux-gnu --out /out/nymwrap-linux-x86_64.cdx.json
(cd app && npm ci --ignore-scripts --no-audit --no-fund && npm run build)
(cd extension && npm ci --ignore-scripts --no-audit --no-fund && npm run build)
cargo build --workspace --bins --release --frozen
cargo build --manifest-path daemons/nw-netd/Cargo.toml --release --frozen
# Match `tauri build --no-bundle`: custom-protocol embeds the built UI.
cargo build --manifest-path app/src-tauri/Cargo.toml --bin nymwrap-app --features tauri/custom-protocol --release --frozen
for binary in nymwrap-app nymwrap nymwrapd nw-api nw-llmd nw-drift-host nw-audit-worker nw-probe nw-netd; do
  install -m 0755 "/build/target/release/$binary" "/build/payload/$binary"
done
node scripts/fetch-transports.mjs --platform linux-x86_64 --output target/release-transports
install -m 0755 target/release-transports/lyrebird /build/payload/transports/lyrebird
cp -r extension/dist /build/payload/extension-chromium
cp -r extension/dist-firefox /build/payload/extension-firefox

(cd /build/payload && find . -type f -print0 | sort -z | xargs -0 sha256sum) > /out/nymwrap-linux-x86_64.files.sha256
tar --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  --mode='u+rwX,go+rX,go-w' -C /build/payload -cf - . | gzip -n -9 > /out/nymwrap-linux-x86_64.tar.gz
node scripts/release-artifacts.mjs record /out
