use super::*;
use nw_llm::{EmbeddingBatch, ModelError, Role};
fn basis(index: usize) -> Vec<f64> {
    let mut v = vec![0.0; DIMENSION];
    v[index] = 1.0;
    v
}
fn settings() -> Settings {
    Settings::default()
}
#[test]
fn ties_and_candidate_permutations_cannot_hide_a_top_k_user() {
    let mut candidates = vec![basis(0)];
    candidates.extend((0..64).map(|_| basis(1)));
    let risky = rank(&basis(0), &candidates, &settings()).unwrap();
    assert!(risky.risky);
    assert_eq!((risky.rank_min, risky.rank_max), (1, 1));
    let safe = rank(&basis(1), &candidates, &settings()).unwrap();
    assert!(!safe.risky);
    assert_eq!(safe.rank_min, 65);
    candidates[1..].reverse();
    assert_eq!(
        rank(&basis(0), &candidates, &settings()).unwrap().rank_min,
        risky.rank_min
    );
    let tied = rank(&basis(0), &vec![basis(0); 65], &settings()).unwrap();
    assert!(tied.risky);
    assert_eq!((tied.rank_min, tied.rank_max), (1, 65));
}
#[test]
fn malformed_embeddings_and_policies_never_authorize_a_request() {
    let mut candidates = vec![basis(0); 65];
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        candidates[4][32] = bad;
        assert_eq!(
            rank(&basis(0), &candidates, &settings()).unwrap_err(),
            Unavailable::Embedding
        );
    }
    candidates[4] = vec![0.0; DIMENSION];
    assert!(rank(&basis(0), &candidates, &settings()).is_err());
    candidates[4] = basis(0);
    assert!(rank(&basis(0), &candidates[..50], &settings()).is_err());
    assert!(rank(&basis(0)[..2], &candidates, &settings()).is_err());
    for margin in [-0.001, f64::NAN, f64::INFINITY, 1.001] {
        let mut policy = settings();
        policy.max_margin = margin;
        assert_eq!(
            rank(&basis(0), &candidates, &policy).unwrap_err(),
            Unavailable::Policy
        );
    }
    let mut policy = settings();
    policy.model_sha256 = "a".repeat(64);
    assert!(rank(&basis(0), &candidates, &policy).is_err());
    policy = settings();
    policy.top_k = 65;
    assert!(rank(&basis(0), &candidates, &policy).is_err());
}
#[test]
fn references_require_fifty_distinct_decoys_and_bounded_user_data() {
    let user = || SecretString::from("SYNTHETIC_DOSSIER_CANARY_62491");
    assert!(References::new(user(), synthetic_decoys()[..49].to_vec()).is_err());
    assert!(References::new(user(), vec!["same fictional dossier".into(); 64]).is_err());
    let mut duplicate = synthetic_decoys();
    duplicate[6] = "  SAME  DOSSIER ".into();
    duplicate[7] = "same dossier".into();
    assert!(References::new(user(), duplicate).is_err());
    assert!(
        References::with_synthetic_decoys(SecretString::from("x".repeat(MAX_DOSSIER_BYTES + 1)))
            .is_err()
    );
    assert!(References::with_synthetic_decoys(SecretString::from("")).is_err());
    let mut total_limit = synthetic_decoys();
    total_limit[0] = "y".repeat(MAX_DOSSIER_BYTES);
    assert!(
        References::new(
            SecretString::from("x".repeat(MAX_DOSSIER_BYTES)),
            total_limit
        )
        .is_err()
    );
    let references = References::with_synthetic_decoys(user()).unwrap();
    assert_eq!(references.documents.len(), 65);
    assert!(
        references.documents[1..]
            .iter()
            .all(|d| !d.contains("62491"))
    );
}
struct Model {
    calls: std::sync::Mutex<Zeroizing<Vec<Vec<String>>>>,
    identity: String,
}
impl Model {
    fn new() -> Self {
        Self {
            calls: Default::default(),
            identity: MODEL_SHA256.into(),
        }
    }
}
impl LocalModel for Model {
    async fn complete(&self, _: &[Message]) -> Result<SecretString, ModelError> {
        panic!("linkcheck cannot use generated judgements")
    }
    async fn embed(&self, _: &[String]) -> Result<Vec<Vec<f64>>, ModelError> {
        panic!("anonymous vectors cannot authorize egress")
    }
    async fn embed_identified(&self, texts: &[String]) -> Result<EmbeddingBatch, ModelError> {
        self.calls.lock().unwrap().push(texts.to_vec());
        Ok(EmbeddingBatch {
            model_sha256: self.identity.clone(),
            vectors: texts
                .iter()
                .map(|t| {
                    basis(usize::from(
                        !(t.contains("old rare craft") && t.contains("new rare schedule")),
                    ))
                })
                .collect(),
        })
    }
}
#[tokio::test]
async fn accumulated_history_is_checked_and_cached_references_do_not_bypass_model_identity() {
    let references = References::with_synthetic_decoys(SecretString::from(
        "old rare craft; new rare schedule; SYNTHETIC_DOSSIER_CANARY_62491",
    ))
    .unwrap();
    let model = Model::new();
    let first = Message {
        role: Role::User,
        content: "old rare craft".into(),
    };
    assert!(
        !references
            .inspect(&model, std::slice::from_ref(&first), &settings())
            .await
            .unwrap()
            .risky
    );
    let history = [
        first,
        Message {
            role: Role::Assistant,
            content: "earlier provider answer".into(),
        },
        Message {
            role: Role::User,
            content: "new rare schedule".into(),
        },
    ];
    assert!(
        references
            .inspect(&model, &history, &settings())
            .await
            .unwrap()
            .risky
    );
    {
        let calls = model.calls.lock().unwrap();
        let last = calls.last().unwrap();
        assert_eq!(last.len(), 1);
        assert!(
            last[0].contains("old rare craft")
                && last[0].contains("new rare schedule")
                && last[0].contains("earlier provider answer")
        );
        assert!(!last[0].contains("62491"));
        assert!(
            calls.iter().all(
                |b| b.len() <= 64 && b.iter().map(String::len).sum::<usize>() <= MAX_TEXT_BYTES
            )
        );
    }
    let mut replacement = Model::new();
    replacement.identity = "b".repeat(64);
    assert_eq!(
        references
            .inspect(&replacement, &history, &settings())
            .await
            .unwrap_err(),
        Unavailable::Identity
    );
}

#[tokio::test]
async fn a_rare_fact_at_the_end_of_a_large_dossier_remains_a_ranked_candidate() {
    let mut dossier = (0..700)
        .map(|i| format!("Սինթետիկ գրառում {i}. Синтетический факт {i}. Synthetic fact {i}.\n"))
        .collect::<String>();
    dossier.push_str("old rare craft; new rare schedule; SYNTHETIC_LARGE_DOSSIER_TAIL_62491");
    let boundary_fact = format!("SYNTHETIC_BOUNDARY_FACT_{}", "r".repeat(800));
    dossier = format!("{}{boundary_fact}\n{dossier}", " ".repeat(6000));
    let references = References::with_synthetic_decoys(SecretString::from(dossier.as_str()))
        .expect("a complete large dossier must be segmented, never truncated");
    let model = Model::new();
    let history = [Message {
        role: Role::User,
        content: "old rare craft and new rare schedule".into(),
    }];
    let result = references
        .inspect(&model, &history, &settings())
        .await
        .unwrap();
    assert!(result.risky);
    assert_eq!(
        result.candidates, 65,
        "segments are not independent decoy people"
    );
    let calls = model.calls.lock().unwrap();
    let pieces = calls[..calls.len() - 1]
        .iter()
        .flatten()
        .collect::<Vec<_>>();
    assert!(pieces.iter().any(|piece| piece.contains(&boundary_fact)));
    for index in 0..700 {
        for fact in [
            format!("գրառում {index}."),
            format!("факт {index}."),
            format!("fact {index}."),
        ] {
            assert!(
                pieces.iter().any(|piece| piece.contains(&fact)),
                "missing synthetic fact {index}"
            );
        }
    }
    assert!(
        pieces
            .iter()
            .any(|piece| piece.contains("SYNTHETIC_LARGE_DOSSIER_TAIL_62491"))
    );
    assert!(
        calls.iter().all(|batch| batch.len() <= 64
            && batch.iter().map(String::len).sum::<usize>() <= MAX_TEXT_BYTES)
    );
}
