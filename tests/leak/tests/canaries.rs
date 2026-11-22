use base64::{Engine, engine::general_purpose::STANDARD};
use nw_shield::{ConversationVault, Secret, SecretKind, Shield};
use secrecy::ExposeSecret;

#[test]
fn native_host_rejects_shadow_canary_without_echo() {
    for i in 0..100 {
        let canary = format!("NW_SYNTHETIC_SHADOW_CANARY_{i:04}_xQzV");
        let body = format!(
            r#"{{"version":1,"id":1,"command":{{"kind":"shadow_history","prompt":"{canary}"}}}}"#
        );
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend(body.as_bytes());
        assert!(nw_bridge::read_native(&mut frame.as_slice()).is_err());
        let mut output = vec![];
        nw_bridge::write_native(
            &mut output,
            &nw_bridge::Reply {
                version: 1,
                id: 1,
                result: nw_bridge::Result::Error {
                    code: nw_bridge::ErrorCode::InvalidRequest,
                },
            },
        )
        .unwrap();
        let output = String::from_utf8_lossy(&output);
        assert!(!output.contains(&canary));
        assert!(!output.contains(&STANDARD.encode(canary.as_bytes())));
    }
}
#[test]
fn safety_stop_protocol_cannot_carry_page_or_shadow_content() {
    const CANARY: &str = "SYNTHETIC_STOP_PAGE_CANARY_20971";
    for command in [
        serde_json::json!({"kind":"safety_stop","event_id":"a".repeat(32),"reason":"captcha","page":CANARY}),
        serde_json::json!({"kind":"safety_stop","event_id":CANARY,"reason":"login"}),
        serde_json::json!({"kind":"safety_stop","event_id":"a".repeat(32),"reason":CANARY}),
    ] {
        let bytes =
            serde_json::to_vec(&serde_json::json!({"version":1,"id":1,"command":command})).unwrap();
        let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
        frame.extend(bytes);
        assert!(nw_bridge::read_native(&mut frame.as_slice()).is_err());
    }
    let request = nw_bridge::Request {
        version: 1,
        id: 1,
        command: nw_bridge::Command::SafetyStop {
            event_id: "a".repeat(32),
            reason: nw_bridge::StopReason::Captcha,
        },
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend(bytes);
    assert!(
        nw_bridge::read_native(&mut frame.as_slice())
            .unwrap()
            .is_some()
    );
}

#[test]
fn one_hundred_canaries_never_cross_the_last_model_boundary() {
    for i in 0..100 {
        let canary = format!("NW_SYNTHETIC_CANARY_{i:04}_xQzV");
        let shield = Shield::new(vec![
            Secret::new(SecretKind::Secret, canary.clone(), false).unwrap(),
        ])
        .unwrap();
        let mut vault = ConversationVault::default();
        let prompt = format!("Summarize {canary}, preserve no personal details");
        let safe = shield
            .prepare(&prompt, &mut vault, |s| Ok(s.to_owned()))
            .unwrap();
        assert!(!safe.text().contains(&canary));
        assert_eq!(
            vault.rehydrate(safe.text()).unwrap().expose_secret(),
            prompt
        );
        let encodings = [
            canary.clone(),
            canary.to_lowercase(),
            STANDARD.encode(&canary),
            canary.bytes().map(|b| format!("%{b:02X}")).collect(),
            canary
                .chars()
                .map(|c| format!("\\u{:04x}", c as u32))
                .collect(),
            canary
                .chars()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        ];
        let mut captured_egress = Vec::new();
        for encoded in encodings {
            if let Ok(prepared) = shield.prepare("ordinary prompt", &mut vault, |_| Ok(encoded)) {
                captured_egress.push(prepared.text().to_owned());
            }
        }
        assert!(
            captured_egress.is_empty(),
            "secret crossed the final model boundary"
        );
    }
}

#[test]
fn domain_files_never_contain_plaintext() {
    use nw_vault::{Domain, KeyRing};
    let directory = tempfile::tempdir().unwrap();
    let ring = KeyRing::new().unwrap();
    let secret = b"NW_SYNTHETIC_AT_REST_732190";
    for domain in Domain::ALL {
        let path = directory.path().join(format!("{}.nwenc", domain.name()));
        ring.write(domain, &path, secret).unwrap();
        let disk = std::fs::read(path).unwrap();
        assert!(!disk.windows(secret.len()).any(|window| window == secret));
    }
}

#[test]
fn shaped_egress_contains_only_checked_text() {
    use nw_net::ShapedRequest;
    let canary = "SYNTHETIC_FINAL_EGRESS_CANARY_4018";
    let shield = Shield::new(vec![
        Secret::new(SecretKind::Secret, canary.into(), false).unwrap(),
    ])
    .unwrap();
    let mut vault = ConversationVault::default();
    let prepared = shield
        .prepare(&format!("Explain {canary}"), &mut vault, |text| {
            Ok(text.to_owned())
        })
        .unwrap();
    let shaped = ShapedRequest::new(&prepared).unwrap();
    let text = std::str::from_utf8(shaped.bytes()).unwrap();
    shield.leakcheck(text, &vault).unwrap();
    assert!(!text.contains(canary));
}
#[test]
fn one_hundred_canaries_stay_out_of_authenticated_egress_bodies() {
    use nw_net::{
        ShapedRequest,
        wire::{Command, Request, SessionKey},
    };
    let key = SessionKey::new([41; 32]).unwrap();
    for i in 1..=100 {
        let canary = format!("SYNTHETIC_WIRE_CANARY_{i:04}_DoNotTransmit");
        let shield = Shield::new(vec![
            Secret::new(SecretKind::Secret, canary.clone(), false).unwrap(),
        ])
        .unwrap();
        let mut vault = ConversationVault::default();
        let prepared = shield
            .prepare(&format!("Explain {canary}"), &mut vault, |text| {
                Ok(text.into())
            })
            .unwrap();
        let shaped = ShapedRequest::new(&prepared).unwrap();
        let request = Request {
            conversation: "a".repeat(32),
            body: shaped.bytes().to_vec(),
            authorization: "synthetic-provider-key".into(),
        };
        let command = if i % 2 == 0 {
            Command::SendOnce { request }
        } else {
            Command::Send { request }
        };
        let wire = key.seal(i, &command).unwrap();
        let captured = key.open::<Command>(&wire, i).unwrap();
        let captured = match &captured {
            Command::Send { request } | Command::SendOnce { request } => request,
            _ => panic!("send expected"),
        };
        let text = std::str::from_utf8(&captured.body).unwrap();
        shield.leakcheck(text, &vault).unwrap();
        for forbidden in [&canary, &STANDARD.encode(&canary)] {
            assert!(!text.contains(forbidden));
        }
        assert!(nw_net::BYTE_BUCKETS.contains(&captured.body.len()));
    }
}
