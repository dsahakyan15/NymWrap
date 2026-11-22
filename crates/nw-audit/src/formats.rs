use super::*;
use std::io::{Cursor, Read};
const MAX_ARCHIVE_FILES: usize = 2000;
const MAX_EXPANDED: u64 = 32 * 1024 * 1024;
fn merge(target: &mut Summary, mut value: Summary) -> Result<(), ImportError> {
    target.skipped_files += value.skipped_files;
    target.records = target
        .records
        .checked_add(value.records)
        .filter(|n| *n <= MAX_RECORDS)
        .ok_or(ImportError::TooLarge)?;
    for (k, v) in value.domains {
        *target.domains.entry(k).or_default() += v;
    }
    for (k, v) in value.activity_hours {
        *target.activity_hours.entry(k).or_default() += v;
    }
    target.titles.extend(
        value
            .titles
            .drain(..)
            .take(300usize.saturating_sub(target.titles.len())),
    );
    target.searches.extend(
        value
            .searches
            .drain(..)
            .take(300usize.saturating_sub(target.searches.len())),
    );
    target.prompt_samples.extend(
        value
            .prompt_samples
            .drain(..)
            .take(30usize.saturating_sub(target.prompt_samples.len())),
    );
    Ok(())
}
pub fn archive(bytes: &[u8], format: Format) -> Result<Summary, ImportError> {
    // Bound the central directory before the library can reserve its file table.
    let tail = bytes.len().saturating_sub(65_557);
    let footer = (tail..bytes.len().saturating_sub(21))
        .rev()
        .find(|i| {
            bytes.get(*i..*i + 4) == Some(b"PK\x05\x06")
                && bytes.len()
                    == *i + 22 + usize::from(u16::from_le_bytes([bytes[*i + 20], bytes[*i + 21]]))
        })
        .ok_or(ImportError::Invalid)?;
    if footer >= 20 && bytes.get(footer - 20..footer - 16) == Some(b"PK\x06\x07") {
        return Err(ImportError::TooLarge);
    }
    let count = usize::from(u16::from_le_bytes([bytes[footer + 10], bytes[footer + 11]]));
    let directory_size = u32::from_le_bytes(
        bytes[footer + 12..footer + 16]
            .try_into()
            .map_err(|_| ImportError::Invalid)?,
    ) as usize;
    let directory_offset = u32::from_le_bytes(
        bytes[footer + 16..footer + 20]
            .try_into()
            .map_err(|_| ImportError::Invalid)?,
    ) as usize;
    if count > MAX_ARCHIVE_FILES || directory_size > bytes.len() {
        return Err(ImportError::TooLarge);
    }
    if directory_offset
        .checked_add(directory_size)
        .is_none_or(|n| n > footer)
        || bytes[footer + 4..footer + 8] != [0, 0, 0, 0]
    {
        return Err(ImportError::Invalid);
    }
    let mut zip = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        Cursor::new(bytes),
    )
    .map_err(|_| ImportError::Invalid)?;
    if zip.len() > MAX_ARCHIVE_FILES {
        return Err(ImportError::TooLarge);
    }
    if zip.has_duplicate_names()
        || zip
            .has_overlapping_entries()
            .map_err(|_| ImportError::Invalid)?
    {
        return Err(ImportError::Invalid);
    }
    let mut total = 0u64;
    let mut names = vec![];
    for i in 0..zip.len() {
        let file = zip.by_index(i).map_err(|_| ImportError::Invalid)?;
        let name = file.name().map_err(|_| ImportError::Invalid)?.into_owned();
        if file.enclosed_name().is_none()
            || file.is_symlink()
            || name.contains('\\')
            || name.contains(':')
        {
            return Err(ImportError::Invalid);
        }
        total = total
            .checked_add(file.size())
            .filter(|n| *n <= MAX_EXPANDED)
            .ok_or(ImportError::TooLarge)?;
        if file.is_file() {
            names.push((name, i));
        }
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let mut summary = Summary::default();
    let mut imported = 0;
    for (name, index) in names {
        let name = name.to_lowercase();
        let chosen = match format {
            Format::Chatgpt | Format::Claude => name.ends_with("conversations.json"),
            _ => {
                name.ends_with(".json")
                    || name.ends_with(".html")
                    || name.ends_with(".htm")
                    || name.ends_with(".sqlite")
                    || name.ends_with(".db")
                    || name.ends_with("/history")
            }
        };
        if !chosen || name.ends_with("manifest.json") || name.ends_with("archive_browser.html") {
            summary.skipped_files += 1;
            continue;
        }
        let file = zip.by_index(index).map_err(|_| ImportError::Invalid)?;
        if file.size() > MAX_IMPORT_BYTES as u64 {
            return Err(ImportError::TooLarge);
        }
        let mut data = Zeroizing::new(Vec::new());
        file.take(MAX_IMPORT_BYTES as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|_| ImportError::Invalid)?;
        if data.len() > MAX_IMPORT_BYTES {
            return Err(ImportError::TooLarge);
        }
        // Match the top-level sniffer: a UTF-8 BOM must not hide a nested archive.
        let sniffed = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&data);
        if sniffed.starts_with(b"PK") {
            return Err(ImportError::Invalid);
        }
        let source = if name.ends_with("browserhistory.json") {
            Format::BrowserJson
        } else {
            format
        };
        match super::import(&data, source) {
            Ok(value) => {
                merge(&mut summary, value)?;
                imported += 1;
            }
            Err(ImportError::Invalid) if matches!(format, Format::Takeout | Format::Gemini) => {
                summary.skipped_files += 1;
            }
            Err(e) => return Err(e),
        }
    }
    if imported == 0 {
        return Err(ImportError::Invalid);
    }
    Ok(summary)
}
pub fn html(bytes: &[u8], format: Format) -> Result<Summary, ImportError> {
    if !matches!(format, Format::Takeout | Format::Gemini) {
        return Err(ImportError::Invalid);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ImportError::Invalid)?;
    if text.bytes().filter(|b| *b == b'<').count() > 200_000 {
        return Err(ImportError::TooLarge);
    }
    let doc = scraper::Html::parse_document(text);
    let cells = scraper::Selector::parse(".content-cell").map_err(|_| ImportError::Invalid)?;
    let links = scraper::Selector::parse("a[href]").map_err(|_| ImportError::Invalid)?;
    let mut summary = Summary::default();
    let mut count = 0;
    for cell in doc.select(&cells) {
        count += 1;
        if count > MAX_RECORDS {
            return Err(ImportError::TooLarge);
        }
        let text = cell.text().collect::<Vec<_>>().join(" ");
        if let Some(link) = cell
            .select(&links)
            .find(|a| a.value().attr("href").is_some_and(|u| domain(u).is_some()))
        {
            let title = clipped(&link.text().collect::<Vec<_>>().join(" "), 1024);
            let title = if text.contains("Searched for ") {
                format!("Searched for {title}")
            } else if text.contains("Искали:") {
                format!("Искали: {title}")
            } else {
                title
            };
            summary.record(&title, link.value().attr("href").unwrap_or(""), None)?;
            if matches!(format, Format::Gemini) {
                summary.prompt(&title);
            }
        } else if matches!(format, Format::Gemini) && !text.trim().is_empty() {
            summary.record("Gemini conversation", "https://gemini.google.com/", None)?;
            summary.prompt(text.trim());
        }
    }
    if count == 0 {
        return Err(ImportError::Invalid);
    }
    Ok(summary)
}
pub fn sqlite(bytes: &[u8], format: Format) -> Result<Summary, ImportError> {
    use rusqlite::{Connection, MAIN_DB, config::DbConfig, limits::Limit};
    if bytes.len() < 100 {
        return Err(ImportError::Invalid);
    }
    if bytes[18] == 2 || bytes[19] == 2 {
        return Err(ImportError::WalSnapshot);
    }
    if bytes[18] != 1 || bytes[19] != 1 {
        return Err(ImportError::Invalid);
    }
    let mut conn = Connection::open_in_memory().map_err(|_| ImportError::Io)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024),
        (Limit::SQLITE_LIMIT_COLUMN, 256),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 64),
    ] {
        conn.set_limit(limit, value)
            .map_err(|_| ImportError::Invalid)?;
    }
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| ImportError::Invalid)?;
    conn.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-4096;",
    )
    .map_err(|_| ImportError::Invalid)?;
    conn.deserialize_read_exact(MAIN_DB, Cursor::new(bytes), bytes.len(), true)
        .map_err(|_| ImportError::Invalid)?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| ImportError::Invalid)?;
    let mut steps = 0u32;
    conn.progress_handler(
        1000,
        Some(move || {
            steps += 1;
            steps > 10_000
        }),
    )
    .map_err(|_| ImportError::Invalid)?;
    let candidates = match format {
        Format::ChromeSqlite => vec![("urls", 0)],
        Format::FirefoxSqlite => vec![("moz_places", 1)],
        Format::SafariSqlite => vec![("history_items", 2)],
        Format::BrowserJson | Format::Takeout => {
            vec![("urls", 0), ("moz_places", 1), ("history_items", 2)]
        }
        _ => return Err(ImportError::Invalid),
    };
    let mut selected = None;
    for (name, kind) in candidates {
        let is_table = conn
            .query_row(
                "SELECT type='table' FROM sqlite_schema WHERE name=?1",
                [name],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false);
        if is_table {
            selected = Some(kind);
            break;
        }
    }
    let kind = selected.ok_or(ImportError::Invalid)?;
    let sql = match kind {
        0 => {
            "SELECT coalesce(title,''),url,coalesce(last_visit_time,0) FROM urls ORDER BY last_visit_time DESC,id DESC LIMIT 50001"
        }
        1 => {
            "SELECT coalesce(title,''),url,coalesce(last_visit_date,0) FROM moz_places ORDER BY last_visit_date DESC,id DESC LIMIT 50001"
        }
        _ => {
            "SELECT coalesce(v.title,''),i.url,v.visit_time FROM history_items i JOIN history_visits v ON v.history_item=i.id ORDER BY v.visit_time DESC,v.id DESC LIMIT 50001"
        }
    };
    if kind == 2
        && !conn
            .query_row(
                "SELECT type='table' FROM sqlite_schema WHERE name='history_visits'",
                [],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false)
    {
        return Err(ImportError::Invalid);
    }
    let mut statement = conn.prepare(sql).map_err(|_| ImportError::Invalid)?;
    let mut rows = statement.query([]).map_err(|_| ImportError::Invalid)?;
    let mut summary = Summary::default();
    while let Some(row) = rows.next().map_err(|_| ImportError::Invalid)? {
        let title: String = row.get(0).map_err(|_| ImportError::Invalid)?;
        let url: String = row.get(1).map_err(|_| ImportError::Invalid)?;
        let seconds = if kind == 2 {
            let t: f64 = row.get(2).map_err(|_| ImportError::Invalid)?;
            if !t.is_finite() || !(0.0..=10_000_000_000.0).contains(&t) {
                return Err(ImportError::Invalid);
            }
            Some(t as i64 + 978_307_200)
        } else {
            let t: i64 = row.get(2).map_err(|_| ImportError::Invalid)?;
            if kind == 0 {
                t.checked_sub(11_644_473_600_000_000)
                    .filter(|v| *v >= 0)
                    .map(|v| v / 1_000_000)
            } else {
                (t > 0).then_some(t / 1_000_000)
            }
        };
        summary.record(if title.is_empty() { &url } else { &title }, &url, None)?;
        if let Some(seconds) = seconds {
            *summary
                .activity_hours
                .entry((seconds / 3600).rem_euclid(24) as u8)
                .or_default() += 1;
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn zip_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in files {
            zip.start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
    #[test]
    fn bom_wrapped_archives_cannot_bypass_the_nested_archive_rejection() {
        let json = br#"[{"title":"Synthetic nested archive","titleUrl":"https://example.test/"}]"#;
        let inner = zip_files(&[("history.json", json)]);
        let mut wrapped = b"\xef\xbb\xbf".to_vec();
        wrapped.extend_from_slice(&inner);
        // The top-level import still accepts the supported leading UTF-8 BOM.
        assert_eq!(
            super::super::import(&wrapped, Format::Takeout)
                .unwrap()
                .records,
            1
        );
        for data in [&inner, &wrapped] {
            let outer = zip_files(&[("history.json", data)]);
            assert_eq!(
                super::super::import(&outer, Format::Takeout).err(),
                Some(ImportError::Invalid)
            );
        }
    }
    #[test]
    fn html_and_zip_remain_bounded_and_do_not_extract() {
        let html=br#"<html><div class="content-cell">Searched for <a href="https://www.google.com/search?q=synthetic">synthetic &lt;script&gt;garden&lt;/script&gt;</a><img src="https://example.test/tracker"></div></html>"#;
        assert_eq!(
            super::html(html, Format::Takeout).unwrap().searches,
            ["synthetic <script>garden</script>"]
        );
        let archive = zip_files(&[("Takeout/My Activity/Search/MyActivity.html", html)]);
        assert_eq!(
            super::archive(&archive, Format::Takeout).unwrap().records,
            1
        );
        assert!(super::archive(&zip_files(&[("../escape.json", b"[]")]), Format::Takeout).is_err());
        assert!(
            super::archive(
                &zip_files(&[("data.json", &vec![b' '; MAX_IMPORT_BYTES + 1])]),
                Format::Takeout
            )
            .is_err()
        );
    }
    #[test]
    fn browser_images_are_read_only_and_wal_is_rejected() {
        for (format, sql) in [
            (
                Format::ChromeSqlite,
                "CREATE TABLE urls(id INTEGER PRIMARY KEY,title TEXT,url TEXT,last_visit_time INTEGER); INSERT INTO urls VALUES(1,'synthetic garden','https://example.test/',13380163200000000);",
            ),
            (
                Format::FirefoxSqlite,
                "CREATE TABLE moz_places(id INTEGER PRIMARY KEY,title TEXT,url TEXT,last_visit_date INTEGER); INSERT INTO moz_places VALUES(1,'synthetic garden','https://example.test/',1735689600000000);",
            ),
            (
                Format::SafariSqlite,
                "CREATE TABLE history_items(id INTEGER PRIMARY KEY,url TEXT); CREATE TABLE history_visits(id INTEGER PRIMARY KEY,history_item INTEGER,title TEXT,visit_time REAL); INSERT INTO history_items VALUES(1,'https://example.test/'); INSERT INTO history_visits VALUES(1,1,'synthetic garden',757382400.0);",
            ),
        ] {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute_batch(sql).unwrap();
            let bytes = conn.serialize(rusqlite::MAIN_DB).unwrap().to_vec();
            assert_eq!(sqlite(&bytes, format).unwrap().records, 1);
            let mut wal = bytes;
            wal[18] = 2;
            assert!(sqlite(&wal, format).is_err());
        }
    }
}
