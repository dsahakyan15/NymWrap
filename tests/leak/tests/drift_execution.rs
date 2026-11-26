//! The model-to-cover gate precedes every new search permit path.
use nw_llm::{LocalModel, Message, ModelError};
use secrecy::SecretString;
struct InjectedPlan {
    text: String,
    service: &'static str,
}
impl LocalModel for InjectedPlan {
    async fn complete(&self, _: &[Message]) -> Result<SecretString, ModelError> {
        let action = serde_json::json!({"service":self.service,"text":self.text});
        let stage = serde_json::json!({"theme":"synthetic gardening","bridge":"nature","actions":vec![action;5]});
        Ok(SecretString::from(serde_json::json!({"cover":"gardening","days_per_stage":5,"sensitive_consent":false,"stages":vec![stage;10]}).to_string()))
    }
    async fn canonicalize(&self, _: &str) -> Result<SecretString, ModelError> {
        Err(ModelError::Unavailable)
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, ModelError> {
        panic!("private action reached embeddings instead of being blocked")
    }
}
#[tokio::test]
async fn model_cannot_introduce_a_canary_into_a_cover_plan_for_browser_execution() {
    use base64::Engine;
    const CANARY: &str = "SYNTHETIC_DRIFT_EXECUTION_CANARY_37159";
    let shield = nw_shield::Shield::new(vec![
        nw_shield::Secret::new(nw_shield::SecretKind::Secret, CANARY.into(), false).unwrap(),
    ])
    .unwrap();
    for text in [
        CANARY.into(),
        base64::engine::general_purpose::STANDARD.encode(CANARY),
        CANARY.chars().map(|c| format!("{c} ")).collect(),
    ] {
        for service in ["google", "youtube", "chatgpt", "claude", "gemini"] {
            let model = InjectedPlan {
                text: text.clone(),
                service,
            };
            let result = nw_core::planning::generate(
                &model,
                &shield,
                &nw_core::planning::PlanInput {
                    activity: None,
                    confirmed_interests: vec!["synthetic pottery".into()],
                    cover: "gardening".into(),
                    sensitive_consent: false,
                },
            )
            .await;
            assert!(matches!(result, Err(nw_core::CoreError::Blocked)));
        }
    }
    for kind in ["begin_search", "validate_search", "finish_search"] {
        let command = serde_json::json!({"kind":kind,"task":{"plan_hash":"a".repeat(64),"stage":1,"day":1,"action_index":0,"service":"google","text":"gardening","shadow":CANARY},"token":"b".repeat(64)});
        let bytes =
            serde_json::to_vec(&serde_json::json!({"version":1,"id":1,"command":command})).unwrap();
        let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
        frame.extend(bytes);
        assert!(nw_bridge::read_native(&mut frame.as_slice()).is_err());
    }
}
