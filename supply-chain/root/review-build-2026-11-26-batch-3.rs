// Only synthetic key strings and trusted numeric Rust expressions are emitted.
fn main() {
    let path =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("review-generated.rs");
    let mut builder = phf_codegen::Map::new();
    builder.entry("\"}; compile_error!(\"data\"); //", "41u32");
    builder.entry("ordinary", "42u32");
    std::fs::write(
        path,
        format!(
            "static GENERATED: phf::Map<&str, u32> = {};",
            builder.build()
        ),
    )
    .unwrap();
}
