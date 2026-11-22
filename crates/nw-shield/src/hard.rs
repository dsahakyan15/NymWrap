//! Bounded format detectors. These recognize syntax, never infer identity.
use super::SecretKind;
use regex::Regex;
use std::sync::LazyLock;

static MAC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"(?i)\b(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})\b"
).unwrap()
});
static GUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
});
static IMEI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[0-9]{15}\b").unwrap());
static USER_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:(?:[a-z]:\\{1,2}|/(?:mnt/)?[a-z]/)users[\\/]+|/(?:home|users)/)([^\\/\s"'<>]+)"#,
    )
    .unwrap()
});
static TZ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"(?i)\b(?:(?:Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|Europe|Indian|Pacific|Etc)/[a-z_+0-9-]+(?:/[a-z_+-]+)?|[a-z]+(?: [a-z]+){0,4} (?:Standard|Daylight) Time|(?:UTC|GMT)\s*[+-][0-9]{1,2}(?::?[0-9]{2})?)\b|[+-](?:0[0-9]|1[0-4]):?[0-5][0-9]\b"
).unwrap()
});
static DATETIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:[Zz]|[+-][0-9]{2}:?[0-9]{2})?\b"
).unwrap()
});
static PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(-?[0-9]{1,3}\.[0-9]{3,})\s*[,;]\s*(-?[0-9]{1,3}\.[0-9]{3,})").unwrap()
});
static GEO_URI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)geo:(-?[0-9]{1,3}(?:\.[0-9]+)?),\s*(-?[0-9]{1,3}(?:\.[0-9]+)?)").unwrap()
});
static DMS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b([0-9]{1,3})°\s*([0-9]{1,2})['′]\s*([0-9]{1,2}(?:\.[0-9]+)?)["″]\s*([NSEW])\b"#,
    )
    .unwrap()
});
static PLUS_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[23456789CFGHJMPQRVWX]{2,8}\+[23456789CFGHJMPQRVWX]{2,3}\b").unwrap()
});

pub(super) fn spans(text: &str) -> Vec<(usize, usize, SecretKind)> {
    let mut result = vec![];
    for (pattern, kind) in [
        (&*DATETIME, SecretKind::Datetime),
        (&*MAC, SecretKind::Mac),
        (&*GUID, SecretKind::Guid),
        (&*TZ, SecretKind::Tz),
        (&*PLUS_CODE, SecretKind::Geo),
    ] {
        result.extend(pattern.find_iter(text).map(|m| (m.start(), m.end(), kind)));
    }
    for captures in USER_PATH.captures_iter(text) {
        let value = captures.get(1).unwrap();
        result.push((value.start(), value.end(), SecretKind::UserPath));
    }
    for found in IMEI.find_iter(text) {
        let sum: u32 = found
            .as_str()
            .bytes()
            .enumerate()
            .map(|(i, b)| {
                let value = u32::from(b - b'0') * if i % 2 == 1 { 2 } else { 1 };
                value / 10 + value % 10
            })
            .sum();
        if sum.is_multiple_of(10) {
            result.push((found.start(), found.end(), SecretKind::Imei));
        }
    }
    for pattern in [&*PAIR, &*GEO_URI] {
        for c in pattern.captures_iter(text) {
            let lat = c[1].parse::<f64>().unwrap_or(f64::INFINITY);
            let lon = c[2].parse::<f64>().unwrap_or(f64::INFINITY);
            if lat.abs() <= 90.0 && lon.abs() <= 180.0 {
                let m = c.get(0).unwrap();
                result.push((m.start(), m.end(), SecretKind::Geo));
            }
        }
    }
    for c in DMS.captures_iter(text) {
        let degrees = c[1].parse::<u16>().unwrap();
        let minutes = c[2].parse::<u16>().unwrap();
        let seconds = c[3].parse::<f64>().unwrap();
        let maximum = if c[4].eq_ignore_ascii_case("N") || c[4].eq_ignore_ascii_case("S") {
            90
        } else {
            180
        };
        if degrees <= maximum
            && minutes < 60
            && seconds < 60.0
            && (degrees != maximum || minutes == 0 && seconds == 0.0)
        {
            let m = c.get(0).unwrap();
            result.push((m.start(), m.end(), SecretKind::Geo));
        }
    }
    result
}

/// UTC hour displayed inside a rehydratable placeholder; no host timezone lookup.
pub(super) fn utc_hour(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !text.is_ascii() {
        return None;
    }
    let number = |a, b| text.get(a..b)?.parse::<i32>().ok();
    let (mut year, mut month, mut day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=month_days(year, month)).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return None;
    }
    let suffix = &text[19..];
    let offset_at = suffix.find(['+', '-', 'Z', 'z'])?;
    let offset = &suffix[offset_at..];
    let shift = if matches!(offset, "Z" | "z") {
        0
    } else {
        let digits = offset[1..].replace(':', "");
        if digits.len() != 4 {
            return None;
        }
        let h = digits[..2].parse::<i32>().ok()?;
        let m = digits[2..].parse::<i32>().ok()?;
        if h > 14 || m >= 60 || h == 14 && m != 0 {
            return None;
        }
        (h * 60 + m) * if offset.starts_with('+') { 1 } else { -1 }
    };
    let minutes = hour * 60 + minute - shift;
    day += minutes.div_euclid(1440);
    if day < 1 {
        month -= 1;
        if month < 1 {
            year -= 1;
            month = 12;
        }
        day += month_days(year, month);
    } else if day > month_days(year, month) {
        day = 1;
        month += 1;
        if month > 12 {
            year += 1;
            month = 1;
        }
    }
    if !(1..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}{month:02}{day:02}T{:02}00Z",
        minutes.rem_euclid(1440) / 60
    ))
}
fn month_days(year: i32, month: i32) -> i32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_rounding_handles_offsets_leap_days_and_year_boundaries() {
        for (input, expected) in [
            ("2026-11-23T12:34:56+04:00", "20261123T0800Z"),
            ("2024-03-01T00:20:30+0400", "20240229T2000Z"),
            ("2025-01-01T00:20:30+0400", "20241231T2000Z"),
            ("2025-12-31T23:20:30-0400", "20260101T0300Z"),
            ("2026-11-23T12:34:56.123Z", "20261123T1200Z"),
        ] {
            assert_eq!(utc_hour(input).as_deref(), Some(expected));
        }
        for invalid in [
            "2025-02-29T12:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T12:00:00",
            "0001-01-01T00:00:00+1400",
        ] {
            assert!(utc_hour(invalid).is_none());
        }
    }
    #[test]
    fn validates_geo_ranges_and_imei_checksum() {
        assert!(spans("91.1234, 44.1234; 40.1234, 181.1234; 40°60'00\"N").is_empty());
        assert!(
            spans("490154203237518")
                .iter()
                .any(|s| matches!(s.2, SecretKind::Imei))
        );
        assert!(
            !spans("490154203237519")
                .iter()
                .any(|s| matches!(s.2, SecretKind::Imei))
        );
    }
}
