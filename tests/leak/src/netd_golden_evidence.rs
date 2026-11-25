//! Test-only, synthetic normalized bytes. Production builds have no output hook.
pub(crate) fn write(name: &str, hex: &str) {
    let Some(directory) = std::env::var_os("NW_PROTOCOL_EVIDENCE_DIR") else {
        return;
    };
    assert!(["provider-http.hex", "provider-tls.hex"].contains(&name));
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&base).unwrap();
    let directory = std::path::PathBuf::from(directory);
    assert!(directory.is_absolute());
    std::fs::create_dir_all(&directory).unwrap();
    assert!(
        directory
            .canonicalize()
            .unwrap()
            .starts_with(base.canonicalize().unwrap())
    );
    std::fs::write(directory.join(name), format!("{hex}\n")).unwrap();
}
