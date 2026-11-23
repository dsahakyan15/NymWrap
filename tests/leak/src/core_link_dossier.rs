use super::*;
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
    w.save_persona(Persona {
        traits: vec![
            Trait {
                id: "a".repeat(64),
                claim: "SYNTHETIC_CONFIRMED_TRAIT_78314".into(),
                evidence: vec!["synthetic evidence".into()],
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
        prompt_samples: vec!["SYNTHETIC_IMPORT_FACT_78314".into()],
        ..Default::default()
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
            "PRIVATE_FACT",
            "DEVICE_FACT",
            "IMPORT_FACT",
        ] {
            assert!(dossier.contains(fact));
        }
        assert!(!dossier.contains("UNCONFIRMED_TRAIT") && !dossier.contains("DENIED_TRAIT"));
        assert!(inputs[1..].iter().all(|d| !d.contains("78314")));
    }
    w.save_import(nw_audit::Summary {
        searches: vec!["x".repeat(8193)],
        ..Default::default()
    })
    .unwrap();
    assert!(w.linkcheck_references().unwrap().is_none());
}
