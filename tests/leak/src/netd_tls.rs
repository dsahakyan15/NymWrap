use super::provider_tls;
use std::sync::Arc;

fn hello() -> Vec<u8> {
    let mut client = rustls::ClientConnection::new(
        Arc::new(provider_tls().unwrap()),
        "api.example.test".try_into().unwrap(),
    )
    .unwrap();
    let mut wire = vec![];
    client.write_tls(&mut wire).unwrap();
    wire
}
fn u16_at(bytes: &[u8], at: usize) -> usize {
    usize::from(u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()))
}
fn normalized(mut wire: Vec<u8>) -> Vec<u8> {
    assert_eq!(wire[0], 22);
    assert_eq!(wire[5], 1);
    assert_eq!(wire.len(), 5 + u16_at(&wire, 3));
    wire[11..43].fill(0);
    let sid_len = usize::from(wire[43]);
    assert_eq!(sid_len, 32);
    wire[44..44 + sid_len].fill(0);
    let mut at = 44 + sid_len;
    at += 2 + u16_at(&wire, at);
    at += 1 + usize::from(wire[at]);
    let end = at + 2 + u16_at(&wire, at);
    assert_eq!(end, wire.len());
    at += 2;
    let mut found_key_share = false;
    while at < end {
        let kind = u16_at(&wire, at);
        let size = u16_at(&wire, at + 2);
        at += 4;
        if kind == 51 {
            found_key_share = true;
            let share_end = at + 2 + u16_at(&wire, at);
            assert_eq!(share_end, at + size);
            let mut key = at + 2;
            while key < share_end {
                let length = u16_at(&wire, key + 2);
                wire[key + 4..key + 4 + length].fill(0);
                key += 4 + length;
            }
            assert_eq!(key, share_end);
        }
        assert!(
            ![42, 41].contains(&kind),
            "unexpected early data or PSK extension"
        );
        at += size;
    }
    assert!(found_key_share);
    assert_eq!(at, end);
    wire
}
#[test]
fn provider_clienthello_matches_cross_platform_golden_with_fresh_entropy() {
    let first = hello();
    let second = hello();
    assert_ne!(&first[11..43], &second[11..43]);
    assert_ne!(first, second);
    let normalized_first = normalized(first);
    assert_eq!(normalized_first, normalized(second));
    let hex: String = normalized_first
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if std::env::var_os("NW_UPDATE_PROTOCOL_GOLDEN").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/leak/fixtures/provider-tls-v1.hex"
            ),
            format!("{hex}\n"),
        )
        .unwrap();
        return;
    }
    assert_eq!(hex, include_str!("../fixtures/provider-tls-v1.hex").trim());
}
