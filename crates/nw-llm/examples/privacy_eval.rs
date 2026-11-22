//! Opt-in quality measurement, using only the compiled synthetic corpus.
use nw_llm::LocalModel;
use nw_shield::{ConversationVault, Secret, SecretKind, Sensitivity, Shield};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    language: String,
    input: String,
    #[serde(default)]
    secrets: Vec<String>,
    entities: Vec<String>,
    local_only: bool,
}
#[derive(Default, Serialize)]
struct Score {
    expected_entity_characters: usize,
    hidden_entity_characters: usize,
    unexpected_hidden_characters: usize,
}
fn score(source: &str, expected: &[String], masked: &[&str]) -> Score {
    let ranges = |values: &[&str]| {
        values
            .iter()
            .flat_map(|value| source.match_indices(value).map(|(i, v)| i..i + v.len()))
            .collect::<Vec<_>>()
    };
    let expected = ranges(&expected.iter().map(String::as_str).collect::<Vec<_>>());
    let masked = ranges(masked);
    let mut result = Score::default();
    for (i, _) in source.char_indices() {
        let needed = expected.iter().any(|r| r.contains(&i));
        let hidden = masked.iter().any(|r| r.contains(&i));
        result.expected_entity_characters += usize::from(needed);
        result.hidden_entity_characters += usize::from(needed && hidden);
        result.unexpected_hidden_characters += usize::from(!needed && hidden);
    }
    result
}
#[derive(Serialize)]
struct Observation {
    id: String,
    language: String,
    status: &'static str,
    actual_local_only: bool,
    expected_local_only: bool,
    unsafe_for_remote: bool,
    #[serde(flatten)]
    score: Score,
}
#[derive(Serialize)]
struct Report {
    corpus: &'static str,
    cases: usize,
    valid_responses: usize,
    rejected_responses: usize,
    model_errors: usize,
    policy_false_negatives: usize,
    policy_false_positives: usize,
    unsafe_remote_cases: usize,
    #[serde(flatten)]
    score: Score,
    observations: Vec<Observation>,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 1 {
        return Err("usage: privacy_eval PRIVATE_MODEL_ENDPOINT".into());
    }
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../../../tests/models/privacy-v1.json"))?;
    let model = nw_llm::UnixModel::new(
        args[0].clone().into(),
        "default".into(),
        "nomic-embed-text".into(),
    )?;
    let mut report = Report {
        corpus: "synthetic-privacy-v1",
        cases: cases.len(),
        valid_responses: 0,
        rejected_responses: 0,
        model_errors: 0,
        policy_false_negatives: 0,
        policy_false_positives: 0,
        unsafe_remote_cases: 0,
        score: Score::default(),
        observations: vec![],
    };
    let mut ids = std::collections::BTreeSet::new();
    for case in cases {
        if case.input.is_empty()
            || !ids.insert(case.id.clone())
            || case
                .entities
                .iter()
                .any(|e| e.is_empty() || !case.input.contains(e))
        {
            return Err("invalid_synthetic_corpus".into());
        }
        let shield = Shield::new(
            case.secrets
                .into_iter()
                .map(|s| Secret::new(SecretKind::Secret, s, false))
                .collect::<Result<_, _>>()?,
        )?;
        let mut vault = ConversationVault::default();
        let minimized = shield.minimize(&case.input, &mut vault)?;
        // Exercise the same fixed prompt, grammar and literal-span validator as the engine.
        let (status, actual_local_only) =
            match model.identify_entities(minimized.expose_secret()).await {
                Ok(analysis) => match shield.minimize_entities(
                    minimized.expose_secret(),
                    analysis.expose_secret(),
                    &mut vault,
                ) {
                    Ok(result) => (
                        "valid",
                        result.local_only || shield.classify(&case.input) == Sensitivity::LocalOnly,
                    ),
                    Err(_) => ("rejected", true),
                },
                Err(_) => ("model_error", true),
            };
        let snapshot = serde_json::to_value(vault.snapshot())?;
        let values = snapshot["entries"]
            .as_array()
            .ok_or("invalid_vault_snapshot")?
            .iter()
            .map(|v| v["value"].as_str().ok_or("invalid_vault_snapshot"))
            .collect::<Result<Vec<_>, _>>()?;
        let score = score(&case.input, &case.entities, &values);
        let unsafe_for_remote = status == "valid"
            && !actual_local_only
            && (case.local_only
                || score.hidden_entity_characters < score.expected_entity_characters);
        report.valid_responses += usize::from(status == "valid");
        report.rejected_responses += usize::from(status == "rejected");
        report.model_errors += usize::from(status == "model_error");
        report.policy_false_negatives +=
            usize::from(status == "valid" && case.local_only && !actual_local_only);
        report.policy_false_positives +=
            usize::from(status == "valid" && !case.local_only && actual_local_only);
        report.unsafe_remote_cases += usize::from(unsafe_for_remote);
        report.score.expected_entity_characters += score.expected_entity_characters;
        report.score.hidden_entity_characters += score.hidden_entity_characters;
        report.score.unexpected_hidden_characters += score.unexpected_hidden_characters;
        // Emit identifiers and counts only, never input, model output or vault contents.
        report.observations.push(Observation {
            id: case.id,
            language: case.language,
            status,
            actual_local_only,
            expected_local_only: case.local_only,
            unsafe_for_remote,
            score,
        });
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_union_coverage_and_partial_unicode_spans_without_double_counting() {
        let result = score("Лира Лира tea", &["Лира".into()], &["Ли", "Ли", "tea"]);
        assert_eq!(result.expected_entity_characters, 8);
        assert_eq!(result.hidden_entity_characters, 4);
        assert_eq!(result.unexpected_hidden_characters, 3);
    }
}
