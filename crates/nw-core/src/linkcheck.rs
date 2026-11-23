//! Local deterministic linkage decisions. No score from a generative model is accepted.
use nw_llm::{LocalModel, Message};
use nw_proto::{MAX_TEXT_BYTES, Profile};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

pub const MODEL_SHA256: &str = "d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac";
pub const DIMENSION: usize = 768;
pub const MIN_DECOYS: usize = 50;
const MAX_DOSSIER_BYTES: usize = 8192;
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
        self.model_sha256 == MODEL_SHA256
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
    pub risky: bool,
}

/// User is index zero internally. Tie handling never uses this index as a tiebreaker.
pub struct References {
    documents: Zeroizing<Vec<String>>,
    vectors: Mutex<Option<Zeroizing<Vec<Vec<f64>>>>>,
}
impl References {
    pub fn new(user: SecretString, decoys: Vec<String>) -> Result<Self, Unavailable> {
        let mut documents = Zeroizing::new(vec![user.expose_secret().to_owned()]);
        let mut decoys = Zeroizing::new(decoys);
        if !(MIN_DECOYS..=256).contains(&decoys.len()) {
            return Err(Unavailable::Dossier);
        }
        documents.append(&mut decoys);
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
        Ok(Self {
            documents,
            vectors: Mutex::new(None),
        })
    }
    pub fn with_synthetic_decoys(user: SecretString) -> Result<Self, Unavailable> {
        Self::new(user, synthetic_decoys())
    }
    pub async fn inspect(
        &self,
        model: &impl LocalModel,
        history: &[Message],
        settings: &Settings,
    ) -> Result<Rank, Unavailable> {
        if !settings.valid(self.documents.len()) {
            return Err(Unavailable::Policy);
        }
        if history.is_empty()
            || history.len() > 64
            || history.iter().map(|m| m.content.len()).sum::<usize>() > MAX_TEXT_BYTES
        {
            return Err(Unavailable::Limit);
        }
        // Embed the entire immutable provider-visible history, including earlier
        // turns and provider replies. Never silently take just the last question.
        let query = Zeroizing::new(serde_json::to_string(history).map_err(|_| Unavailable::Limit)?);
        if query.len() > MAX_TEXT_BYTES {
            return Err(Unavailable::Limit);
        }
        let mut cached = self.vectors.lock().await;
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
                let mut batch = identified(model, &self.documents[offset..end]).await?;
                vectors.append(&mut batch);
                offset = end;
            }
            *cached = Some(vectors);
        }
        let query_texts = Zeroizing::new(vec![query.to_string()]);
        let queries = identified(model, &query_texts).await?;
        rank(
            &queries[0],
            cached.as_ref().ok_or(Unavailable::Embedding)?,
            settings,
        )
    }
}

async fn identified(
    model: &impl LocalModel,
    texts: &[String],
) -> Result<Zeroizing<Vec<Vec<f64>>>, Unavailable> {
    let mut batch = model
        .embed_identified(texts)
        .await
        .map_err(|_| Unavailable::Model)?;
    if batch.model_sha256 != MODEL_SHA256 {
        return Err(Unavailable::Identity);
    }
    if batch.vectors.len() != texts.len()
        || batch
            .vectors
            .iter()
            .any(|v| v.len() != DIMENSION || nw_drift::math::cos(v, v).is_err())
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
    if query.len() != DIMENSION || dossiers.iter().any(|v| v.len() != DIMENSION) {
        return Err(Unavailable::Embedding);
    }
    let scores = Zeroizing::new(
        dossiers
            .iter()
            .map(|d| {
                nw_drift::math::cos(query, d)
                    .map(|v| (v * SCORE_SCALE).round() as i32)
                    .map_err(|_| Unavailable::Embedding)
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let user_score = scores[0];
    let best_decoy_score = *scores[1..].iter().max().ok_or(Unavailable::Dossier)?;
    // A tie may put the user inside top-k regardless of the order of candidates.
    let rank_min = 1 + scores[1..].iter().filter(|v| **v > user_score).count();
    let rank_max = 1 + scores[1..].iter().filter(|v| **v >= user_score).count();
    let risky = rank_min <= settings.top_k
        || f64::from(user_score - best_decoy_score) / SCORE_SCALE >= settings.max_margin;
    Ok(Rank {
        candidates: dossiers.len(),
        rank_min,
        rank_max,
        user_score,
        best_decoy_score,
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
                "A fictional person who {}, {}, and {}.",
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
    MissingDossier,
    VerificationUnavailable,
    GeneralizationFailed,
    IndependentSplitUnavailable,
}
impl LocalReason {
    pub fn explanation(&self) -> &'static str {
        match self {
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
