// Synthetic review probes for ADR 0104, desktop pass 3.
// Compile with pinned rustc --edition=2021 --test and --extern entries for
// the SHA-verified locked cesu8, dtoa-short, endi, secrecy and zeroize libraries.
// Exact normalized commands and release-library rebuild flags are in the JSON report.
// No real files, home-directory lookups, network or OS property values are read.

extern crate dtoa_short;
extern crate endi;
extern crate secrecy;
extern crate zeroize;
use secrecy::{ExposeSecret, ExposeSecretMut};
use std::{cell::Cell, rc::Rc};
#[test]
fn endi_io_and_short_buffers() {
    use endi::{Endian, ReadBytes, WriteBytes};
    let mut b = Vec::new();
    b.write_u128(Endian::Big, u128::MAX - 9).unwrap();
    assert_eq!(b.as_slice().read_u128(Endian::Big).unwrap(), u128::MAX - 9);
    assert_eq!(
        [1u8]
            .as_slice()
            .read_u64(Endian::Little)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert!(std::panic::catch_unwind(|| Endian::Big.read_u32(&[1])).is_err());
    let mut small = [0u8; 1];
    assert!(small.as_mut_slice().write_u16(Endian::Big, 200).is_err());
}
#[test]
fn secret_redaction_and_cleanup() {
    let mut s = secrecy::SecretString::from(String::from("synthetic-review-secret"));
    assert!(!format!("{:?}", s).contains("synthetic-review-secret"));
    assert_eq!(s.clone().expose_secret(), "synthetic-review-secret");
    zeroize::Zeroize::zeroize(&mut s);
    assert!(s.expose_secret().bytes().all(|b| b == 0));
    s.expose_secret_mut().make_ascii_uppercase();
    struct Marker(Rc<Cell<u32>>);
    impl zeroize::Zeroize for Marker {
        fn zeroize(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let n = Rc::new(Cell::new(0));
    {
        let _s = secrecy::SecretBox::new(Box::new(Marker(n.clone())));
    }
    assert_eq!(n.get(), 1);
}
#[test]
fn dtoa_rounding_carries_and_writer_errors() {
    for (value, expected) in [
        (9.9999999f64, "9.9999999"),
        (999999999999999.9, "1000000000000000"),
        (-0.0, "0"),
        (1.25, "1.25"),
    ] {
        let mut out = String::new();
        dtoa_short::write(&mut out, value).unwrap();
        assert_eq!(out, expected);
    }
    struct Fail;
    impl std::fmt::Write for Fail {
        fn write_str(&mut self, _: &str) -> std::fmt::Result {
            Err(std::fmt::Error)
        }
    }
    assert!(dtoa_short::write(&mut Fail, 1.25).is_err());
}
#[test]
fn dtoa_finite_extremes_and_generated_bits() {
    let mut bits = 0x5eedcafe12345678u64;
    for i in 0..100000 {
        bits = bits.wrapping_mul(6364136223846793005).wrapping_add(1);
        let v = match i {
            0 => f64::MAX,
            1 => f64::MIN_POSITIVE,
            2 => f64::from_bits(1),
            3 => -f64::MAX,
            _ => f64::from_bits(bits),
        };
        let mut out = String::new();
        dtoa_short::write(&mut out, v).unwrap();
        assert!(out.is_ascii());
        let rounded = out.parse::<f64>().unwrap();
        if v.is_finite() && v != 0.0 && rounded.is_finite() {
            assert!((rounded / v - 1.0).abs() < 2e-14 || v.abs() < f64::MIN_POSITIVE);
        }
        let v = f32::from_bits(bits as u32);
        let mut out = String::new();
        dtoa_short::write(&mut out, v).unwrap();
        assert!(out.is_ascii());
        let rounded = out.parse::<f32>().unwrap();
        if v.is_finite() && v != 0.0 && rounded.is_finite() {
            assert!((rounded / v - 1.0).abs() < 2e-5 || v.abs() < f32::MIN_POSITIVE);
        }
    }
}

extern crate cesu8;
#[test]
fn every_unicode_scalar_roundtrips() {
    for c in (0..=0x10ffff).filter_map(char::from_u32) {
        let mut bytes = [0; 4];
        let value: &str = c.encode_utf8(&mut bytes);
        assert_eq!(cesu8::from_cesu8(&cesu8::to_cesu8(value)).unwrap(), value);
        assert_eq!(
            cesu8::from_java_cesu8(&cesu8::to_java_cesu8(value)).unwrap(),
            value
        );
    }
}
#[test]
fn short_inputs_and_converter_semantics() {
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            for decode in [cesu8::from_cesu8, cesu8::from_java_cesu8] {
                if let Ok(s) = decode(&[a, b]) {
                    assert!(std::str::from_utf8(s.as_bytes()).is_ok());
                }
            }
        }
    }
    for v in [
        &[0xed, 0xa0, 0x80][..],
        &[0xed, 0xb0, 0x80][..],
        &[0xed, 0xa0, 0x80, 0xed, 0xa0, 0x80][..],
        &[0xe0, 0x80, 0x80][..],
    ] {
        assert!(cesu8::from_cesu8(v).is_err());
    }
    assert_eq!(cesu8::from_java_cesu8(b"\0").unwrap(), "\0");
    assert_eq!(
        cesu8::from_cesu8("\u{10000}".as_bytes()).unwrap(),
        "\u{10000}"
    );
}
