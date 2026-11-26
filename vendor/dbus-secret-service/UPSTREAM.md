# NymWrap Secret Service OpenSSL patch

Base: dbus-secret-service 4.1.0, from brotskydotcom/dbus-secret-service.
Published archive SHA-256:
708b509edf7889e53d7efb0ffadd994cc6c2345ccb62f55cfd6b0682165e4fa6.
Archive, sparse index and exact-version crates.io API were checked before copying.
MIT/Apache-2.0 licenses, source and example are retained from that archive.

Patch (ADR 0109): this fork supports crypto-openssl only; crypto-rust or no crypto
is a compile error. Removed the legacy fastrand/BigUint backend and its optional
dependencies. Added crypto_openssl.rs using OpenSSL DH/RAND/HKDF/AES, zeroizing
Rust secret buffers, peer/IV validation and Result propagation. Session uses
references to its zeroized key; collection/item propagate encryption errors.
error.rs no longer mentions the removed AES dependency. Cargo.toml pins existing
dbus 0.9.12, openssl 0.10.82, zeroize 1.9.2, and the project Rust 1.100 toolchain.
The wire group, padding and KDF/cipher choices remain Secret Service compatible.

This is patched code, not an audit certificate for the upstream crate, D-Bus
protocol or native libraries. Both stores explicitly keep audit-as-crates-io=true
for this package, so changing to a path dependency cannot hide the base audit gap.
Only root and desktop patch tables select this fork. Keep its regression tests
linked to the actual source file.
