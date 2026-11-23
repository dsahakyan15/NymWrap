// Controlled geometry for tests of routing/approval, never production embeddings.
pub fn references() -> nw_core::linkcheck::References {
    nw_core::linkcheck::References::with_synthetic_decoys(secrecy::SecretString::from(
        "{\"fixture_user_dossier\":\"SYNTHETIC_FIXTURE_PERSON_84163\"}",
    ))
    .unwrap()
}
pub fn identified(texts: &[String]) -> nw_llm::EmbeddingBatch {
    nw_llm::EmbeddingBatch {
        model_sha256: nw_core::linkcheck::MODEL_SHA256.into(),
        recipe_id: nw_llm::embedding::for_model(nw_core::linkcheck::MODEL_SHA256)
            .unwrap()
            .id
            .into(),
        vectors: texts
            .iter()
            .map(|text| {
                let user = text.starts_with("{\"fixture_user_dossier\"")
                    || text.starts_with("{\"confirmed_persona\"");
                let mut vector = vec![0.0; nw_core::linkcheck::DIMENSION];
                vector[usize::from(!user)] = 1.0;
                vector
            })
            .collect(),
    }
}
pub fn engine<M: nw_llm::LocalModel>(
    model: M,
    shield: nw_shield::Shield,
    profile: nw_proto::Profile,
) -> nw_core::Engine<M> {
    nw_core::Engine::new(model, shield, profile).with_linkcheck(Some(references()))
}
pub fn configured<M: nw_llm::LocalModel>(
    model: M,
    shield: nw_shield::Shield,
    config: &nw_core::config::Config,
) -> Result<nw_core::Engine<M>, nw_core::CoreError> {
    nw_core::Engine::configured(model, shield, config)
        .map(|engine| engine.with_linkcheck(Some(references())))
}
