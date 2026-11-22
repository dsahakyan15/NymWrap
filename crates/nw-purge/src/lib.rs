//! Local suggestions only. This crate cannot execute deletion or send mail.
pub mod guides;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PurgeError {
    #[error("invalid_signal")]
    Invalid,
    #[error("batch_approval_required")]
    Approval,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    pub id: String,
    pub axis_position: f64,
    pub frequency: u32,
}
#[derive(Serialize)]
pub struct Ranked {
    pub id: String,
    pub score: f64,
}
pub fn rank(signals: &[Signal]) -> Result<Vec<Ranked>, PurgeError> {
    if signals.len() > 50_000 {
        return Err(PurgeError::Invalid);
    }
    let mut out = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for signal in signals {
        if !signal.axis_position.is_finite()
            || signal.frequency == 0
            || signal.id.is_empty()
            || signal.id.len() > 128
            || !ids.insert(&signal.id)
        {
            return Err(PurgeError::Invalid);
        }
        let strength = (1.0 - signal.axis_position.abs()).max(0.0);
        if strength < 0.5 {
            continue;
        }
        out.push(Ranked {
            id: signal.id.clone(),
            score: strength * (1.0 + f64::from(signal.frequency).ln()),
        });
    }
    out.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub service: nw_proto::Service,
    pub record_ids: Vec<String>,
}
pub struct ApprovedBatch {
    batch: Batch,
    hash: String,
}
impl Batch {
    pub fn hash(&self) -> Result<String, PurgeError> {
        if self.record_ids.is_empty()
            || self.record_ids.len() > 100
            || self
                .record_ids
                .iter()
                .any(|s| s.is_empty() || s.len() > 128)
        {
            return Err(PurgeError::Invalid);
        }
        let ids: std::collections::BTreeSet<_> = self.record_ids.iter().collect();
        if ids.len() != self.record_ids.len() {
            return Err(PurgeError::Invalid);
        }
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).map_err(|_| PurgeError::Invalid)?)
        ))
    }
    pub fn approve(&self, displayed_hash: &str) -> Result<ApprovedBatch, PurgeError> {
        let hash = self.hash()?;
        if hash != displayed_hash {
            return Err(PurgeError::Approval);
        }
        Ok(ApprovedBatch {
            batch: self.clone(),
            hash,
        })
    }
}
impl ApprovedBatch {
    pub fn batch(&self) -> &Batch {
        &self.batch
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
}
pub fn deletion_template() -> &'static str {
    "Тема: Запрос на доступ и удаление персональных данных\n\nЗдравствуйте.\nПрошу сообщить, какие мои персональные данные вы обрабатываете, и удалить данные, которые не требуется сохранять по закону.\nАккаунт: [заполните локально]\nОбъём запроса: [укажите данные]\nПрошу подтвердить получение и сообщить результат.\n[Имя и дата — заполните самостоятельно]"
}
pub fn checklist(service: nw_proto::Service) -> &'static [&'static str] {
    use nw_proto::Service;
    match service {
        Service::Google | Service::Youtube => &[
            "Откройте настройки своего аккаунта и раздел истории активности.",
            "Просмотрите предложенную партию и удалите только подтверждённые элементы.",
            "Включите подходящий срок автоудаления истории.",
            "Проверьте настройки персонализации рекламы.",
        ],
        _ => &[
            "Откройте настройки данных своего ИИ-сервиса.",
            "Просмотрите сохранённую память и удалите выбранные воспоминания.",
            "Удалите подтверждённые старые чаты отдельно от памяти.",
            "Проверьте настройки использования новых разговоров для обучения.",
        ],
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_guides_are_offline_distinct_and_use_only_official_sources() {
        use nw_proto::Service;
        let mut texts = std::collections::BTreeSet::new();
        for service in [
            Service::Google,
            Service::Youtube,
            Service::Chatgpt,
            Service::Claude,
            Service::Gemini,
        ] {
            let guide = guides::guide(service);
            assert_eq!(guide.service, service);
            assert!(texts.insert(guide.steps[0].text.clone()));
            let ids: std::collections::BTreeSet<_> =
                guide.steps.iter().map(|s| s.id.as_str()).collect();
            assert_eq!(ids.len(), guide.steps.len());
            assert!(ids.contains("history"));
            assert!(ids.contains("verify"));
            for source in guide.sources {
                assert!(
                    [
                        "https://support.google.com/",
                        "https://support.claude.com/",
                        "https://learn.chatgpt.com/"
                    ]
                    .iter()
                    .any(|p| source.url.starts_with(p))
                );
            }
            let review = guides::Review {
                outcome: guides::ObservedOutcome::NoLongerVisible,
                completed_steps: vec!["history".into(), "verify".into()],
                checked_at: 60,
            };
            review.validate(service).unwrap();
        }
    }
    #[test]
    fn strongest_first_neutral_retained_and_approval_bound() {
        let ranked = rank(&[
            Signal {
                id: "strong".into(),
                axis_position: 0.0,
                frequency: 10,
            },
            Signal {
                id: "neutral".into(),
                axis_position: 0.6,
                frequency: 100,
            },
            Signal {
                id: "weak".into(),
                axis_position: 0.3,
                frequency: 1,
            },
        ])
        .unwrap();
        assert_eq!(
            ranked.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["strong", "weak"]
        );
        let mut batch = Batch {
            service: nw_proto::Service::Google,
            record_ids: vec!["strong".into()],
        };
        let hash = batch.hash().unwrap();
        batch.record_ids.push("weak".into());
        assert!(batch.approve(&hash).is_err());
        assert!(deletion_template().contains("[заполните локально]"));
    }
}
