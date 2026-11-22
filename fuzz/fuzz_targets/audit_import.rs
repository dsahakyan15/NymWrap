#![no_main]
use libfuzzer_sys::fuzz_target;
use nw_audit::{Format, MAX_IMPORT_BYTES, import};
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_IMPORT_BYTES + 1 {
        return;
    }
    for format in [
        Format::Takeout,
        Format::Chatgpt,
        Format::Claude,
        Format::Gemini,
        Format::BrowserJson,
        Format::ChromeSqlite,
        Format::FirefoxSqlite,
        Format::SafariSqlite,
    ] {
        if let Ok(summary) = import(data, format) {
            assert!(summary.records <= 50_000);
            assert!(
                summary.titles.len() <= 300
                    && summary.searches.len() <= 300
                    && summary.prompt_samples.len() <= 30
            );
            assert!(summary.domains.values().all(|n| *n <= summary.records));
            assert!(
                summary
                    .activity_hours
                    .iter()
                    .all(|(h, n)| *h < 24 && *n <= summary.records)
            );
            for (texts, limit) in [
                (&summary.titles, 1024),
                (&summary.searches, 1024),
                (&summary.prompt_samples, 2048),
            ] {
                assert!(
                    texts
                        .iter()
                        .all(|s| s.chars().count() <= limit && !s.chars().any(char::is_control))
                );
            }
            let repeated =
                import(data, format).expect("successful import must remain deterministic");
            assert_eq!(
                serde_json::to_vec(&summary).unwrap(),
                serde_json::to_vec(&repeated).unwrap()
            );
        }
    }
});
