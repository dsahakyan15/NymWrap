use nw_llm::LocalModel;
pub async fn verify(model: &impl LocalModel) {
    let texts: Vec<String> =
        serde_json::from_str(include_str!("../fixtures/multilingual-embedding.json")).unwrap();
    let batch = model.embed_identified(&texts).await.unwrap();
    assert_eq!(batch.model_sha256, nw_llm::embedding::QWEN3_SHA256);
    assert_eq!(
        batch.recipe_id,
        nw_llm::embedding::for_model(nw_llm::embedding::QWEN3_SHA256)
            .unwrap()
            .id
    );
    assert_eq!(batch.vectors.len(), 9);
    let dot = |a: &[f64], b: &[f64]| a.iter().zip(b).map(|(a, b)| a * b).sum::<f64>();
    for (index, vector) in batch.vectors.iter().enumerate() {
        assert_eq!(vector.len(), 1024);
        assert!((dot(vector, vector) - 1.0).abs() < 1e-6);
        for language in 0..3 {
            if language == index / 3 {
                continue;
            }
            let best = (0..3)
                .max_by(|a, b| {
                    dot(vector, &batch.vectors[language * 3 + *a])
                        .total_cmp(&dot(vector, &batch.vectors[language * 3 + *b]))
                })
                .unwrap();
            assert_eq!(
                best,
                index % 3,
                "semantic fixture {index}, target language {language}"
            );
        }
    }
    model
        .embed(&["SYNTHETIC_MULTILINGUAL_CONTEXT_CANARY_73926".into()])
        .await
        .unwrap();
    let repeated = model.embed(&texts[..1]).await.unwrap();
    assert!(
        batch.vectors[0]
            .iter()
            .zip(&repeated[0])
            .all(|(a, b)| (a - b).abs() < 1e-6)
    );
    // A different longest input changes Qwen's allocated context. It must not
    // change the embedding space of the short document cached by linkcheck.
    let composition = model
        .embed(&[
            texts[0].clone(),
            "An unrelated synthetic context document. ".repeat(200),
        ])
        .await
        .unwrap();
    assert!(
        batch.vectors[0]
            .iter()
            .zip(&composition[0])
            .all(|(a, b)| (a - b).abs() < 1e-6)
    );
}
