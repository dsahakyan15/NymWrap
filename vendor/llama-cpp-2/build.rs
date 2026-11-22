//! Builds the Windows read-handle CRT bridge with the target CRT.
fn main() {
    println!("cargo:rerun-if-changed=src/model/sys.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        cc::Build::new()
            .file("src/model/sys.c")
            .warnings(true)
            .compile("nymwrap_model_file");
    }
}
