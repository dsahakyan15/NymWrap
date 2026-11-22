#![no_main]
use libfuzzer_sys::fuzz_target;
use nw_shield::{ConversationVault, Secret, SecretKind, Shield};
use secrecy::ExposeSecret;
use std::sync::LazyLock;
const CANARY: &str = "SYNTHETIC_FUZZ_CANARY_5c4e39_SecretOnly";
static SHIELD: LazyLock<Shield> = LazyLock::new(|| {
    Shield::new(vec![
        Secret::new(SecretKind::Secret, CANARY.into(), false).unwrap(),
    ])
    .unwrap()
});
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if text.len() > nw_proto::MAX_TEXT_BYTES {
        return;
    }
    let mut vault = ConversationVault::default();
    if let Ok(prepared) = SHIELD.prepare(text, &mut vault, |s| Ok(s.into())) {
        assert_eq!(
            vault.rehydrate(prepared.text()).unwrap().expose_secret(),
            text
        );
        SHIELD.leakcheck(prepared.text(), &vault).unwrap();
    }
    let mut vault = ConversationVault::default();
    let injected = SHIELD.prepare("Explain pottery.", &mut vault, |_| {
        Ok(format!("{CANARY}{text}"))
    });
    assert!(injected.is_err(), "a model cannot authorize a canary");
});
