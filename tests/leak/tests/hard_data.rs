use base64::{Engine, engine::general_purpose::STANDARD};
use nw_shield::{ConversationVault, Secret, SecretKind, Shield};
use secrecy::ExposeSecret;

#[test]
fn every_hard_detector_masks_source_blocks_model_echo_and_rehydrates_after_reopen() {
    let shield = Shield::new(vec![]).unwrap();
    for (source, kind) in [
        ("coords 40.1772, 44.5035", "GEO"),
        ("map https://maps.example.test/@40.1772,44.5035,12z", "GEO"),
        ("geo:40,44", "GEO"),
        ("40°10'38\"N", "GEO"),
        ("8HGJ5GH3+6Q", "GEO"),
        ("aa:bb:cc:dd:ee:ff", "MAC"),
        ("aa-bb-cc-dd-ee-ff", "MAC"),
        ("aabb.ccdd.eeff", "MAC"),
        ("490154203237518", "IMEI"),
        (r"C:\Users\synthetic-device\project\code.rs", "USER_PATH"),
        (r"C:\\Users\\synthetic-device\\project", "USER_PATH"),
        ("/mnt/c/Users/synthetic-device/project", "USER_PATH"),
        ("/c/Users/synthetic-device/project", "USER_PATH"),
        ("/home/synthetic-device/project", "USER_PATH"),
        ("/Users/synthetic-device/project", "USER_PATH"),
        ("Asia/Yerevan", "TZ"),
        ("Caucasus Standard Time", "TZ"),
        ("UTC+4", "TZ"),
        ("+04:00", "TZ"),
        ("+0400", "TZ"),
        ("2026-11-23T12:34:56+04:00", "DATETIME"),
        ("2026-11-23T12:34:56", "DATETIME"),
        ("12345678-1234-4321-8000-123456789abc", "GUID"),
    ] {
        let mut vault = ConversationVault::default();
        assert!(
            shield.leakcheck(source, &vault).is_err(),
            "unrecognized {kind}"
        );
        let minimized = shield.minimize(source, &mut vault).unwrap();
        assert!(
            minimized.expose_secret().contains(&format!("⟨NW_{kind}_")),
            "wrong detector {kind}"
        );
        shield.leakcheck(minimized.expose_secret(), &vault).unwrap();
        let vault = ConversationVault::restore(vault.snapshot()).unwrap();
        assert_eq!(
            vault
                .rehydrate(minimized.expose_secret())
                .unwrap()
                .expose_secret(),
            source
        );
        assert!(
            shield
                .prepare(source, &mut ConversationVault::default(), |_| Ok(
                    source.into()
                ))
                .is_err()
        );
    }
}

#[test]
fn user_path_keeps_project_suffix_and_datetime_exposes_only_utc_hour() {
    let shield = Shield::new(vec![]).unwrap();
    let minimized = shield
        .minimize(
            "/home/synthetic-device/project/code.rs at 2026-11-23T12:34:56+04:00",
            &mut ConversationVault::default(),
        )
        .unwrap();
    assert_eq!(
        minimized.expose_secret(),
        "/home/⟨NW_USER_PATH_1⟩/project/code.rs at ⟨NW_DATETIME_2_20261123T0800Z⟩"
    );
}

#[test]
fn device_secrets_cover_encoded_transliterated_and_obfuscated_model_output() {
    for value in [
        "SYNTHETIC-PC-8635",
        "SyntheticSSID-4183",
        "synthetic-device-user",
        "00112233445566778899aabbccddeeff",
        "device-git@example.test",
        "Синтеград",
    ] {
        let shield = Shield::new(vec![
            Secret::new(SecretKind::Device, value.into(), false).unwrap(),
        ])
        .unwrap();
        let mut vault = ConversationVault::default();
        let minimized = shield.minimize(value, &mut vault).unwrap();
        assert_eq!(
            vault
                .rehydrate(minimized.expose_secret())
                .unwrap()
                .expose_secret(),
            value
        );
        for encoded in [
            value.to_owned(),
            STANDARD.encode(value),
            value.bytes().map(|b| format!("{b:02x}")).collect(),
            value.bytes().map(|b| format!("%{b:02x}")).collect(),
            value
                .encode_utf16()
                .map(|c| format!("\\u{c:04x}"))
                .collect(),
            value.chars().map(|c| format!("&#{};", c as u32)).collect(),
            value
                .chars()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        ] {
            assert!(shield.leakcheck(&encoded, &vault).is_err());
        }
    }
}
