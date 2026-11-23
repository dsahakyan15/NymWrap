//! Inspect bounded decoded payloads, not only encodings of an isolated secret.
//! Base64 groups change when an attacker adds a prefix or suffix around a value.
use super::*;

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{8,}={0,2}").unwrap());

pub(super) fn base64_views(text: &str) -> Result<Zeroizing<Vec<String>>, Block> {
    let mut views = Zeroizing::new(Vec::new());
    let mut previous = Zeroizing::new(text.to_owned());
    for _ in 0..2 {
        let collapsed = Zeroizing::new(
            previous
                .chars()
                .filter(|ch| {
                    !ch.is_whitespace()
                        && !matches!(
                            *ch,
                            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
                        )
                })
                .collect::<String>(),
        );
        let mut decoded = Zeroizing::new(String::new());
        for (index, input) in [previous.as_str(), collapsed.as_str()]
            .into_iter()
            .enumerate()
        {
            if index == 1 && previous.as_str() == collapsed.as_str() {
                continue;
            }
            for token in TOKEN.find_iter(input) {
                let mut bytes = Zeroizing::new(vec![0u8; token.len().div_ceil(4) * 3]);
                for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                    if let Ok(length) = engine.decode_slice(token.as_str(), &mut bytes) {
                        // Binary wrappers must not hide an otherwise valid UTF-8 secret.
                        let plain =
                            Zeroizing::new(String::from_utf8_lossy(&bytes[..length]).into_owned());
                        if decoded.len() + plain.len() + 1 > MAX_TEXT_BYTES {
                            return Err(Block::TooLarge);
                        }
                        decoded.push('\0');
                        decoded.push_str(&plain);
                        break;
                    }
                }
            }
        }
        if decoded.is_empty() {
            break;
        }
        previous = decoded;
        views.push(previous.to_string());
    }
    Ok(views)
}
