//! Local deterministic linkage decisions. No score from a generative model is accepted.
use nw_llm::{LocalModel, Message};
use nw_proto::{MAX_TEXT_BYTES, Profile};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

pub const MODEL_SHA256: &str = nw_llm::embedding::NOMIC_SHA256;
pub const DIMENSION: usize = 768;
pub const MIN_DECOYS: usize = 50;
const MAX_DOSSIER_BYTES: usize = 1024 * 1024;
const MAX_REFERENCES_BYTES: usize = 2 * MAX_DOSSIER_BYTES;
const SEGMENT_BYTES: usize = 6144;
const SEGMENT_OVERLAP: usize = 1024;
const SCORE_SCALE: f64 = 1_000_000.0;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub top_k: usize,
    pub max_margin: f64,
    pub model_sha256: String,
}
impl Default for Settings {
    fn default() -> Self {
        Self::for_profile(Profile::Standard)
    }
}
impl Settings {
    pub fn for_profile(profile: Profile) -> Self {
        let (top_k, max_margin) = match profile {
            Profile::Standard => (3, 0.03),
            Profile::Strict => (5, 0.02),
            Profile::Paranoid => (8, 0.01),
        };
        Self {
            top_k,
            max_margin,
            model_sha256: MODEL_SHA256.into(),
        }
    }
    pub fn valid(&self, candidates: usize) -> bool {
        nw_llm::embedding::for_model(&self.model_sha256).is_some()
            && self.top_k > 0
            && self.top_k < candidates
            && self.max_margin.is_finite()
            && (0.0..=1.0).contains(&self.max_margin)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unavailable {
    #[error("linkcheck_invalid_dossier")]
    Dossier,
    #[error("linkcheck_input_limit")]
    Limit,
    #[error("linkcheck_model_unavailable")]
    Model,
    #[error("linkcheck_model_identity_mismatch")]
    Identity,
    #[error("linkcheck_invalid_embedding")]
    Embedding,
    #[error("linkcheck_invalid_policy")]
    Policy,
}

/// Only aggregate metadata; dossiers, vectors and their stable digests are never logged.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Rank {
    pub candidates: usize,
    pub rank_min: usize,
    pub rank_max: usize,
    pub user_score: i32,
    pub best_decoy_score: i32,
    pub background_score: i32,
    pub risky: bool,
}

/// User is index zero internally. Tie handling never uses this index as a tiebreaker.
pub struct References {
    documents: Zeroizing<Vec<String>>,
    /// Exclusive segment end for each person, not an expanded candidate pool.
    candidate_ends: Vec<usize>,
    vectors: Mutex<Option<Cached>>,
    observer: Option<std::sync::Arc<dyn Fn(Rank) + Send + Sync>>,
}
struct Cached {
    model_sha256: String,
    recipe_id: &'static str,
    vectors: Zeroizing<Vec<Vec<f64>>>,
}
impl References {
    pub fn new(user: SecretString, decoys: Vec<String>) -> Result<Self, Unavailable> {
        let mut documents = Zeroizing::new(vec![user.expose_secret().to_owned()]);
        let mut decoys = Zeroizing::new(decoys);
        if !(MIN_DECOYS..=256).contains(&decoys.len()) {
            return Err(Unavailable::Dossier);
        }
        documents.append(&mut decoys);
        if documents.iter().map(String::len).sum::<usize>() > MAX_REFERENCES_BYTES {
            return Err(Unavailable::Dossier);
        }
        let mut unique = Zeroizing::new(Vec::new());
        for document in documents.iter() {
            if document.trim().is_empty()
                || document.len() > MAX_DOSSIER_BYTES
                || document.contains('\0')
            {
                return Err(Unavailable::Dossier);
            }
            let words = Zeroizing::new(document.split_whitespace().collect::<Vec<_>>().join(" "));
            let mut normalized = Zeroizing::new(words.to_lowercase());
            if unique.iter().any(|value| value == &*normalized) {
                return Err(Unavailable::Dossier);
            }
            unique.push(std::mem::take(&mut *normalized));
        }
        let mut pieces = Zeroizing::new(Vec::new());
        let mut candidate_ends = Vec::with_capacity(documents.len());
        for document in documents.iter() {
            let mut start = 0;
            loop {
                let mut end = (start + SEGMENT_BYTES).min(document.len());
                while !document.is_char_boundary(end) {
                    end -= 1;
                }
                pieces.push(document[start..end].to_owned());
                if end == document.len() {
                    break;
                }
                start = end - SEGMENT_OVERLAP;
                while !document.is_char_boundary(start) {
                    start -= 1;
                }
            }
            candidate_ends.push(pieces.len());
        }
        Ok(Self {
            documents: pieces,
            candidate_ends,
            vectors: Mutex::new(None),
            observer: None,
        })
    }
    pub fn with_synthetic_decoys(user: SecretString) -> Result<Self, Unavailable> {
        Self::new(user, synthetic_decoys())
    }
    /// Optional aggregate-only observation for synthetic evaluation. It cannot
    /// alter the rank or receive dossier text, vectors or a stable dossier hash.
    pub fn observe(mut self, observer: std::sync::Arc<dyn Fn(Rank) + Send + Sync>) -> Self {
        self.observer = Some(observer);
        self
    }
    pub async fn inspect(
        &self,
        model: &impl LocalModel,
        history: &[Message],
        settings: &Settings,
    ) -> Result<Rank, Unavailable> {
        if !settings.valid(self.candidate_ends.len()) {
            return Err(Unavailable::Policy);
        }
        let recipe =
            nw_llm::embedding::for_model(&settings.model_sha256).ok_or(Unavailable::Policy)?;
        if history.is_empty()
            || history.len() > 64
            || history.iter().map(|m| m.content.len()).sum::<usize>() > MAX_TEXT_BYTES
        {
            return Err(Unavailable::Limit);
        }
        // Embed the entire immutable provider-visible history, including earlier
        // turns and provider replies. Never silently take just the last question.
        // Use the same plain-text representation as reference facts. Role
        // labels preserve attribution without making a JSON envelope a feature.
        let lines = Zeroizing::new(
            history
                .iter()
                .map(|message| {
                    format!(
                        "{}: {}",
                        match message.role {
                            nw_llm::Role::User => "user",
                            nw_llm::Role::Assistant => "assistant",
                            nw_llm::Role::System => "system",
                        },
                        message.content
                    )
                })
                .collect::<Vec<_>>(),
        );
        let query = Zeroizing::new(lines.join("\n"));
        drop(lines);
        if query.len() > MAX_TEXT_BYTES {
            return Err(Unavailable::Limit);
        }
        let mut cached = self.vectors.lock().await;
        if cached.as_ref().is_some_and(|cache| {
            cache.model_sha256 != settings.model_sha256 || cache.recipe_id != recipe.id
        }) {
            return Err(Unavailable::Identity);
        }
        if cached.is_none() {
            let mut vectors = Zeroizing::new(vec![]);
            let mut offset = 0;
            while offset < self.documents.len() {
                let mut end = offset;
                let mut size = 0;
                while end < self.documents.len()
                    && end - offset < 64
                    && size + self.documents[end].len() <= MAX_TEXT_BYTES
                {
                    size += self.documents[end].len();
                    end += 1;
                }
                if end == offset {
                    return Err(Unavailable::Limit);
                }
                let mut batch = identified(model, &self.documents[offset..end], settings).await?;
                vectors.append(&mut batch);
                offset = end;
            }
            *cached = Some(Cached {
                model_sha256: settings.model_sha256.clone(),
                recipe_id: recipe.id,
                vectors,
            });
        }
        let query_texts = Zeroizing::new(vec![query.to_string()]);
        let queries = identified(model, &query_texts, settings).await?;
        let vectors = &cached.as_ref().ok_or(Unavailable::Embedding)?.vectors;
        let mut scores = Zeroizing::new(Vec::with_capacity(self.candidate_ends.len()));
        let mut start = 0;
        for end in &self.candidate_ends {
            // A rare matching fact must not disappear in the average of unrelated
            // biography. More segments may increase risk, never the anonymity set.
            let score = vectors[start..*end]
                .iter()
                .try_fold(i32::MIN, |best, vector| {
                    similarity(&queries[0], vector, recipe.dimension).map(|value| best.max(value))
                })?;
            scores.push(score);
            start = *end;
        }
        let result = rank_scores(&scores, settings)?;
        drop(cached);
        if let Some(observer) = &self.observer {
            observer(result);
        }
        Ok(result)
    }
}

async fn identified(
    model: &impl LocalModel,
    texts: &[String],
    settings: &Settings,
) -> Result<Zeroizing<Vec<Vec<f64>>>, Unavailable> {
    let recipe = nw_llm::embedding::for_model(&settings.model_sha256).ok_or(Unavailable::Policy)?;
    let mut batch = model
        .embed_identified(texts)
        .await
        .map_err(|_| Unavailable::Model)?;
    if batch.model_sha256 != settings.model_sha256 || batch.recipe_id != recipe.id {
        return Err(Unavailable::Identity);
    }
    if batch.vectors.len() != texts.len()
        || batch
            .vectors
            .iter()
            .any(|v| v.len() != recipe.dimension || nw_drift::math::cos(v, v).is_err())
    {
        return Err(Unavailable::Embedding);
    }
    Ok(Zeroizing::new(std::mem::take(&mut batch.vectors)))
}

pub fn rank(
    query: &[f64],
    dossiers: &[Vec<f64>],
    settings: &Settings,
) -> Result<Rank, Unavailable> {
    if dossiers.len() < MIN_DECOYS + 1 || dossiers.len() > 257 || !settings.valid(dossiers.len()) {
        return Err(Unavailable::Policy);
    }
    let dimension = nw_llm::embedding::for_model(&settings.model_sha256)
        .ok_or(Unavailable::Policy)?
        .dimension;
    let scores = Zeroizing::new(
        dossiers
            .iter()
            .map(|d| similarity(query, d, dimension))
            .collect::<Result<Vec<_>, _>>()?,
    );
    rank_scores(&scores, settings)
}
fn similarity(query: &[f64], dossier: &[f64], dimension: usize) -> Result<i32, Unavailable> {
    if query.len() != dimension || dossier.len() != dimension {
        return Err(Unavailable::Embedding);
    }
    nw_drift::math::cos(query, dossier)
        .map(|v| (v * SCORE_SCALE).round() as i32)
        .map_err(|_| Unavailable::Embedding)
}
fn rank_scores(scores: &[i32], settings: &Settings) -> Result<Rank, Unavailable> {
    if scores.len() < MIN_DECOYS + 1 || scores.len() > 257 || !settings.valid(scores.len()) {
        return Err(Unavailable::Policy);
    }
    let user_score = scores[0];
    let best_decoy_score = *scores[1..].iter().max().ok_or(Unavailable::Dossier)?;
    let mut background = Zeroizing::new(scores[1..].to_vec());
    background.sort_unstable();
    // Lower median is deterministic and conservative for an even-sized cohort.
    // A best-decoy baseline made margin redundant with rank_min == 1.
    let background_score = background[(background.len() - 1) / 2];
    // A tie may put the user inside top-k regardless of the order of candidates.
    let rank_min = 1 + scores[1..].iter().filter(|v| **v > user_score).count();
    let rank_max = 1 + scores[1..].iter().filter(|v| **v >= user_score).count();
    let risky = rank_min <= settings.top_k
        || f64::from(user_score - background_score) / SCORE_SCALE >= settings.max_margin;
    Ok(Rank {
        candidates: scores.len(),
        rank_min,
        rank_max,
        user_score,
        best_decoy_score,
        background_score,
        risky,
    })
}

/// Fixed fictional references are public data. The user's facts never seed them.
pub fn synthetic_decoys() -> Vec<String> {
    let crafts = [
        "repairs reed organs",
        "restores mechanical looms",
        "makes ceramic cups",
        "weaves linen baskets",
    ];
    let interests = [
        "studies glass fungi",
        "collects toy boats",
        "grows alpine herbs",
        "draws lunar maps",
    ];
    let schedules = [
        "works rotating night shifts",
        "works seasonal dawn shifts",
        "studies during weekends",
        "teaches afternoon workshops",
    ];
    (0..64)
        .map(|i| {
            format!(
                "{}\n{}\n{}",
                crafts[i % 4],
                interests[(i / 4) % 4],
                schedules[i / 16]
            )
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalReason {
    EntityVerificationUnavailable,
    MissingDossier,
    VerificationUnavailable,
    GeneralizationFailed,
    IndependentSplitUnavailable,
}
impl LocalReason {
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::EntityVerificationUnavailable => {
                "Ответ подготовлен локально (L0): проверка персональных данных недоступна или вернула неподтверждённые фрагменты. Удалённая отправка запрещена."
            }
            Self::MissingDossier => {
                "Ответ подготовлен локально (L0): досье пока недоступно для полной проверки связывания."
            }
            Self::VerificationUnavailable => {
                "Ответ подготовлен локально (L0): проверка связывания не смогла подтвердить безопасность удалённой отправки."
            }
            Self::GeneralizationFailed => {
                "Ответ подготовлен локально (L0): безопасно обобщить редкие факты не удалось."
            }
            Self::IndependentSplitUnavailable => {
                "Ответ подготовлен локально (L0): даже после обобщения совокупность фактов может выдать вас. Независимое разделение разговоров пока недоступно."
            }
        }
    }
}
impl<M: LocalModel> crate::Engine<M> {
    pub(super) async fn protect_linkage(
        &self,
        conversation: &mut crate::Conversation,
        new_start: usize,
    ) -> Option<LocalReason> {
        let Some(references) = &self.linkcheck else {
            return Some(LocalReason::MissingDossier);
        };
        match references
            .inspect(
                &self.model,
                &conversation.canonical,
                &self.linkcheck_settings,
            )
            .await
        {
            Ok(rank) if !rank.risky => return None,
            Ok(_) => {}
            Err(_) => return Some(LocalReason::VerificationUnavailable),
        }
        let mut candidate = conversation.canonical.clone();
        for message in &mut candidate[new_start..] {
            if message.role != nw_llm::Role::User {
                continue;
            }
            let result = self.model.generalize(&message.content).await;
            let Ok(text) = result else {
                return Some(LocalReason::GeneralizationFailed);
            };
            if text.expose_secret().trim().is_empty() || text.expose_secret().len() > MAX_TEXT_BYTES
            {
                return Some(LocalReason::GeneralizationFailed);
            }
            let old = std::mem::replace(&mut message.content, text.expose_secret().to_owned());
            drop(Zeroizing::new(old));
        }
        // Earlier provider-visible messages are immutable. A rewritten transcript
        // cannot erase the provider's stored copy of a previously sent fact.
        match references
            .inspect(&self.model, &candidate, &self.linkcheck_settings)
            .await
        {
            Ok(rank) if !rank.risky => {}
            Ok(_) => return Some(LocalReason::IndependentSplitUnavailable),
            Err(_) => return Some(LocalReason::VerificationUnavailable),
        }
        if candidate.iter().any(|m| {
            self.shield.classify(&m.content) == nw_shield::Sensitivity::LocalOnly
                || self.shield.has_unresolved_name(&m.content)
                || self
                    .shield
                    .leakcheck(&m.content, &conversation.vault)
                    .is_err()
        }) {
            return Some(LocalReason::GeneralizationFailed);
        }
        conversation.canonical = candidate;
        None
    }
}

#[cfg(test)]
#[path = "../../../tests/leak/src/linkcheck_rank.rs"]
mod tests;
