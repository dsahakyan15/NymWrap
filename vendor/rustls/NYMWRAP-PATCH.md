# NymWrap patch (ADR 0044)

Upstream: crates.io rustls 0.23.46, archive SHA-256
`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`.

Three changes: public `ClientConfig::extension_order_seed: Option<u16>`;
builder initializes it to `None`; ClientHello extension serialization uses
the configured seed when present. No other upstream source is changed.
The seed chooses ordering only. All cryptographic entropy remains upstream.
`nw-netd` sets `Some(0)` only for its provider-facing TLS configuration.
Keep upstream licenses. Re-audit this delta on every upstream update.
