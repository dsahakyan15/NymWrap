//! Writes only synthetic, in-memory generated SQLite/ZIP inputs to the fuzz corpus.
use std::{
    fs::OpenOptions,
    io::{Cursor, Write},
    path::Path,
};
fn write_seed(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file.write_all(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.is_file() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(std::io::Error::other("unsafe_fuzz_seed"))
            }
        }
        Err(error) => Err(error),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/audit_import");
    std::fs::create_dir_all(&root)?;
    let mut db = rusqlite::Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE urls(id INTEGER PRIMARY KEY,title TEXT,url TEXT,last_visit_time INTEGER); INSERT INTO urls VALUES(1,'Synthetic pottery','https://example.test/',0);
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY,title TEXT,url TEXT,last_visit_date INTEGER); INSERT INTO moz_places VALUES(1,'Synthetic garden','https://example.test/',0);
        CREATE TABLE history_items(id INTEGER PRIMARY KEY,url TEXT); INSERT INTO history_items VALUES(1,'https://example.test/');
        CREATE TABLE history_visits(id INTEGER PRIMARY KEY,history_item INTEGER,title TEXT,visit_time REAL); INSERT INTO history_visits VALUES(1,1,'Synthetic lesson',0);")?;
    let bytes = db.serialize(rusqlite::MAIN_DB)?;
    write_seed(&root.join("synthetic_browsers.sqlite"), &bytes)?;
    let json = br#"[{"title":"Synthetic <script>data</script>","titleUrl":"https://example.test/","time":"2026-01-01T12:00:00Z"}]"#;
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        "Takeout/history.json",
        zip::write::SimpleFileOptions::default(),
    )?;
    zip.write_all(json)?;
    let archive = zip.finish()?.into_inner();
    write_seed(&root.join("synthetic_takeout.zip"), &archive)?;
    let mut nested = zip::ZipWriter::new(Cursor::new(Vec::new()));
    nested.start_file("history.json", zip::write::SimpleFileOptions::default())?;
    nested.write_all(b"\xef\xbb\xbf")?;
    nested.write_all(&archive)?;
    let nested = nested.finish()?.into_inner();
    assert_eq!(
        nw_audit::import(&nested, nw_audit::Format::Takeout).err(),
        Some(nw_audit::ImportError::Invalid)
    );
    write_seed(&root.join("synthetic_rejected_nested_bom.zip"), &nested)?;
    for format in [
        nw_audit::Format::ChromeSqlite,
        nw_audit::Format::FirefoxSqlite,
        nw_audit::Format::SafariSqlite,
    ] {
        assert_eq!(nw_audit::import(&bytes, format)?.records, 1);
    }
    assert_eq!(
        nw_audit::import(&archive, nw_audit::Format::Takeout)?.records,
        1
    );
    Ok(())
}
