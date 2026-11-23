use super::*;
#[tokio::test]
async fn rejected_or_unavailable_ner_retains_a_local_answer_without_remote_retry() {
    struct UnverifiedNer(usize);
    impl LocalModel for UnverifiedNer {
        async fn identify_entities(&self, _: &str) -> Result<SecretString, nw_llm::ModelError> {
            match self.0 {
                0 => Err(nw_llm::ModelError::Unavailable),
                1 => Ok(r#"{"local_only":false,"entities":[{"kind":"PERSON","text":"invented absent person"}]}"#.into()),
                _ => Ok(r#"{"local_only":false,"entities":[{"kind":"IDENTIFIER","text":"NW_DEVICE"}]}"#.into()),
            }
        }
        async fn canonicalize(&self, text: &str) -> Result<SecretString, nw_llm::ModelError> {
            Ok(text.to_owned().into())
        }
        async fn complete(&self, _: &[Message]) -> Result<SecretString, nw_llm::ModelError> {
            Ok("42".into())
        }
        async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
            panic!("unverified NER must not continue to linkage or egress")
        }
    }
    struct NoSend;
    impl crate::RemoteCompletion for NoSend {
        fn trust(&self) -> nw_proto::TrustLevel {
            nw_proto::TrustLevel::L3
        }
        fn context(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
        async fn complete(
            &self,
            _: &str,
            _: &nw_shield::Prepared,
            _: u32,
        ) -> Result<SecretString, CoreError> {
            panic!("unverified NER must never send")
        }
    }
    // privacy-v3 development dev_0000 stopped at invalid_model_output from NER.
    // Exercise both rejected literal spans and an unavailable worker, including
    // an attempted match inside the Device placeholder already created by code.
    for mode in 0..3 {
        let canary = "SYNTHETIC_DEVICE_NER_REGRESSION_62491";
        let shield = Shield::new(vec![
            Secret::new(SecretKind::Device, canary.into(), false).unwrap(),
        ])
        .unwrap();
        let engine = crate::Engine::new(UnverifiedNer(mode), shield, Profile::Standard)
            .with_linkcheck(Some(crate::link_fixture::references()));
        let mut history = vec![Message {
            role: Role::User,
            content: format!(
                "Для вымышленного человека: делает фарфоровые миниатюры. {canary}. Сколько будет 40 плюс 2? Ответь целым числом."
            ),
        }];
        let reply = engine
            .chat_remote("new", &history, 32, &NoSend, None)
            .await
            .unwrap();
        assert_eq!(reply.trust, nw_proto::TrustLevel::L0);
        assert_eq!(reply.text.expose_secret(), "42");
        assert_eq!(
            serde_json::to_value(reply.local_reason).unwrap(),
            "entity_verification_unavailable"
        );
        history.push(Message {
            role: Role::Assistant,
            content: "42".into(),
        });
        history.push(Message {
            role: Role::User,
            content: "Снова ответь целым числом.".into(),
        });
        let next = engine
            .chat_remote(&reply.conversation, &history, 32, &NoSend, None)
            .await
            .unwrap();
        assert_eq!(next.trust, nw_proto::TrustLevel::L0);
        assert_eq!(
            serde_json::to_value(next.local_reason).unwrap(),
            "entity_verification_unavailable"
        );
    }
}
#[tokio::test]
async fn local_reason_and_json_answer_survive_encrypted_reopen_without_a_remote_retry() {
    struct JsonModel;
    impl LocalModel for JsonModel {
        async fn identify_entities(&self, _: &str) -> Result<SecretString, nw_llm::ModelError> {
            Ok(r#"{"local_only":false,"entities":[]}"#.into())
        }
        async fn canonicalize(&self, text: &str) -> Result<SecretString, nw_llm::ModelError> {
            Ok(text.to_owned().into())
        }
        async fn complete(&self, _: &[Message]) -> Result<SecretString, nw_llm::ModelError> {
            Ok(r#"{"answer":42}"#.into())
        }
        async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
            panic!("local fallback must not embed")
        }
    }
    struct NoSend;
    impl crate::RemoteCompletion for NoSend {
        fn trust(&self) -> nw_proto::TrustLevel {
            nw_proto::TrustLevel::L3
        }
        fn context(&self) -> &str {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
        async fn complete(
            &self,
            _: &str,
            _: &nw_shield::Prepared,
            _: u32,
        ) -> Result<SecretString, CoreError> {
            panic!("local fallback must not send")
        }
    }
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("local-reason");
    let keys = Arc::new(tests::MemoryKeys::default());
    let mut w = Workspace::create_with(
        &root,
        SecretString::from(""),
        Profile::Standard,
        keys.clone(),
    )
    .unwrap();
    let engine = crate::Engine::new(JsonModel, w.shield().unwrap(), Profile::Standard);
    let reply = engine
        .chat_remote(
            "new",
            &[Message {
                role: Role::User,
                content: "return the integer 42 as json.".into(),
            }],
            32,
            &NoSend,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        reply.local_reason,
        Some(crate::linkcheck::LocalReason::MissingDossier)
    ));
    assert_eq!(reply.text.expose_secret(), r#"{"answer":42}"#);
    let id = reply.conversation.clone();
    w.save_chat_reply(&reply).unwrap();
    drop(w);
    drop(engine);
    let mut w = Workspace::open_with(&root, SecretString::from(""), keys).unwrap();
    let recovered = crate::Engine::new(JsonModel, w.shield().unwrap(), Profile::Standard)
        .with_linkcheck(Some(crate::link_fixture::references()));
    recovered
        .restore_if_missing(&id, w.conversation_snapshot(&id).unwrap().unwrap())
        .await
        .unwrap();
    let mut history = w.history(&id).unwrap();
    history.push(Message {
        role: Role::User,
        content: "return the same json again.".into(),
    });
    let answer = recovered
        .chat_remote(&id, &history, 32, &NoSend, None)
        .await
        .unwrap();
    assert!(matches!(
        answer.local_reason,
        Some(crate::linkcheck::LocalReason::MissingDossier)
    ));
    assert_eq!(answer.text.expose_secret(), r#"{"answer":42}"#);
}
struct Model(std::sync::Mutex<zeroize::Zeroizing<Vec<String>>>);
impl LocalModel for Model {
    async fn complete(&self, _: &[Message]) -> Result<SecretString, nw_llm::ModelError> {
        panic!("dossiers never enter generation")
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, nw_llm::ModelError> {
        panic!("identified embeddings required")
    }
    async fn embed_identified(
        &self,
        texts: &[String],
    ) -> Result<nw_llm::EmbeddingBatch, nw_llm::ModelError> {
        self.0.lock().unwrap().extend_from_slice(texts);
        Ok(crate::link_fixture::identified(texts))
    }
}
#[tokio::test]
async fn dossier_covers_confirmed_persona_all_secrets_device_and_import_without_silent_truncation()
{
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("dossier");
    let keys = Arc::new(tests::MemoryKeys::default());
    let mut w = Workspace::create_with(
        &root,
        SecretString::from(""),
        Profile::Standard,
        keys.clone(),
    )
    .unwrap();
    assert!(w.linkcheck_references().unwrap().is_none());
    w.save_import(nw_audit::Summary::default()).unwrap();
    assert!(w.linkcheck_references().unwrap().is_none());
    w.save_persona(Persona {
        traits: vec![
            Trait {
                id: "a".repeat(64),
                claim: "SYNTHETIC_CONFIRMED_TRAIT_78314".into(),
                evidence: vec![
                    "SYNTHETIC_CONFIRMED_EVIDENCE_78314".into(),
                    MANUAL_CONFIRMATION_EVIDENCE.into(),
                ],
                confirmed: None,
            },
            Trait {
                id: "b".repeat(64),
                claim: "SYNTHETIC_UNCONFIRMED_TRAIT_78314".into(),
                evidence: vec!["synthetic evidence".into()],
                confirmed: None,
            },
            Trait {
                id: "c".repeat(64),
                claim: "SYNTHETIC_DENIED_TRAIT_78314".into(),
                evidence: vec!["synthetic evidence".into()],
                confirmed: None,
            },
        ],
    })
    .unwrap();
    w.confirm_traits(&[("a".repeat(64), true), ("c".repeat(64), false)])
        .unwrap();
    w.set_secrets(vec![
        SecretRecord {
            kind: SecretKind::Secret,
            value: "SYNTHETIC_PRIVATE_FACT_78314".into(),
            local_only: true,
        },
        SecretRecord {
            kind: SecretKind::Device,
            value: "SYNTHETIC_DEVICE_FACT_78314".into(),
            local_only: false,
        },
    ])
    .unwrap();
    w.save_import(nw_audit::Summary {
        records: 17,
        skipped_files: 2,
        domains: [("synthetic.example.test".into(), 9)].into(),
        titles: vec!["SYNTHETIC_IMPORT_TITLE_78314".into()],
        searches: vec!["SYNTHETIC_IMPORT_SEARCH_78314".into()],
        prompt_samples: vec!["SYNTHETIC_IMPORT_FACT_78314".into()],
        activity_hours: [(7, 3)].into(),
    })
    .unwrap();
    drop(w);
    let mut w = Workspace::open_with(&root, SecretString::from(""), keys).unwrap();
    let references = w.linkcheck_references().unwrap().unwrap();
    let model = Model(Default::default());
    references
        .inspect(
            &model,
            &[Message {
                role: Role::User,
                content: "Explain pottery".into(),
            }],
            &w.config.shield.linkcheck,
        )
        .await
        .unwrap();
    {
        let inputs = model.0.lock().unwrap();
        let dossier = &inputs[0];
        for fact in [
            "CONFIRMED_TRAIT",
            "CONFIRMED_EVIDENCE",
            "PRIVATE_FACT",
            "DEVICE_FACT",
            "IMPORT_FACT",
            "IMPORT_TITLE",
            "IMPORT_SEARCH",
            "synthetic.example.test",
            "Imported records: 17.",
            "Skipped import files: 2.",
            "Activity hour 7: 3 records.",
        ] {
            assert!(dossier.contains(fact));
        }
        assert!(!dossier.contains("UNCONFIRMED_TRAIT") && !dossier.contains("DENIED_TRAIT"));
        for metadata in [
            "confirmed_persona",
            "personal_and_device_secrets",
            "\"confirmed\":",
            "\"local_only\":",
            MANUAL_CONFIRMATION_EVIDENCE,
            &"a".repeat(64),
        ] {
            assert!(
                !dossier.contains(metadata),
                "storage metadata must not distinguish the real dossier from decoys: {metadata}"
            );
        }
        assert!(inputs[1..].iter().all(|d| !d.contains("78314")));
    }
    w.save_import(nw_audit::Summary {
        searches: vec!["x".repeat(8193)],
        ..Default::default()
    })
    .unwrap();
    let large = w.linkcheck_references().unwrap().unwrap();
    let model = Model(Default::default());
    large
        .inspect(
            &model,
            &[Message {
                role: Role::User,
                content: "Explain pottery".into(),
            }],
            &w.config.shield.linkcheck,
        )
        .await
        .unwrap();
    assert!(
        model
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|piece| piece.contains(&"x".repeat(1024)))
    );
}
