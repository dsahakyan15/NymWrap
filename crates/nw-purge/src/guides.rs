//! Reviewed, offline instructions. URLs are reference text, never network requests.
use nw_proto::Service;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct StepRef {
    pub id: &'static str,
    pub title: &'static str,
    pub text: &'static str,
}
#[derive(Serialize)]
struct SourceRef {
    pub title: &'static str,
    pub url: &'static str,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guide {
    pub service: Service,
    pub checked_on: String,
    pub steps: Vec<Step>,
    pub sources: Vec<Source>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    pub title: String,
    pub text: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub title: String,
    pub url: String,
}
const VERIFY: StepRef = StepRef {
    id: "verify",
    title: "Проверить результат",
    text: "Повторно откройте историю и найдите выбранные записи. Сохраните ниже то, что вы наблюдаете. Отсутствие записи в интерфейсе не доказывает удаление всех копий у сервиса.",
};
pub fn guide(service: Service) -> Guide {
    let (steps, sources): (&'static [StepRef], &'static [SourceRef]) = match service {
        Service::Google => (
            &[
                StepRef {
                    id: "history",
                    title: "Выбранная активность",
                    text: "В My Activity нужного аккаунта найдите записи партии поиском и фильтрами даты/продукта. Сверьте каждую запись и удалите только одобренные элементы.",
                },
                StepRef {
                    id: "retention",
                    title: "Автоудаление",
                    text: "В Google Account → Data & privacy → History settings выберите нужную историю, затем Auto-delete. Просмотрите срок и подтвердите свой выбор.",
                },
                StepRef {
                    id: "ads",
                    title: "Рекламная персонализация",
                    text: "Отдельно просмотрите настройки рекламы в своём Google Account / My Ad Center. Изменение рекламы и удаление истории — разные действия.",
                },
                VERIFY,
            ],
            &[
                SourceRef {
                    title: "Google: удаление активности",
                    url: "https://support.google.com/accounts/answer/465?hl=en",
                },
                SourceRef {
                    title: "Google: настройки приватности",
                    url: "https://support.google.com/accounts/answer/10400210?hl=en",
                },
            ],
        ),
        Service::Youtube => (
            &[
                StepRef {
                    id: "history",
                    title: "Просмотры и поиски YouTube",
                    text: "В My Activity → YouTube History → Manage history найдите выбранные видео. Удаление диапазона может затронуть и поиски этого периода: сначала сверьте объём с одобренной партией.",
                },
                StepRef {
                    id: "retention",
                    title: "Будущая история",
                    text: "В Controls просмотрите сохранение просмотров и поисков; отдельно проверьте Auto-delete. Пауза истории влияет на будущие рекомендации.",
                },
                VERIFY,
            ],
            &[
                SourceRef {
                    title: "YouTube: история просмотров",
                    url: "https://support.google.com/youtube/answer/95725?hl=en",
                },
                SourceRef {
                    title: "Google: автоудаление",
                    url: "https://support.google.com/accounts/answer/465?hl=en",
                },
            ],
        ),
        Service::Chatgpt => (
            &[
                StepRef {
                    id: "history",
                    title: "Выбранные чаты",
                    text: "В своём ChatGPT найдите чаты одобренной партии. Просмотрите содержимое и используйте удаление выбранных чатов; проверьте подтверждение перед удалением.",
                },
                StepRef {
                    id: "memory",
                    title: "Память и инструкции",
                    text: "На ChatGPT web откройте Settings → Personalization. Просмотрите доступные настройки памяти и личные инструкции отдельно от истории чатов. Набор элементов зависит от аккаунта.",
                },
                StepRef {
                    id: "training",
                    title: "Использование данных",
                    text: "В Settings → Data controls просмотрите доступные параметры использования разговоров. Изменение этих настроек не заменяет просмотр старых чатов и памяти.",
                },
                VERIFY,
            ],
            &[
                SourceRef {
                    title: "ChatGPT: память",
                    url: "https://learn.chatgpt.com/docs/customization/memories",
                },
                SourceRef {
                    title: "ChatGPT: персонализация",
                    url: "https://learn.chatgpt.com/docs/personalize",
                },
                SourceRef {
                    title: "ChatGPT: настройки данных",
                    url: "https://learn.chatgpt.com/docs/browser#privacy-and-browser-data",
                },
            ],
        ),
        Service::Claude => (
            &[
                StepRef {
                    id: "history",
                    title: "Выбранные разговоры",
                    text: "В Claude web найдите разговор в боковой панели или Chats and tasks. Через меню ⋮ выберите Delete и сверяйте подтверждение с партией. Не выбирайте все разговоры, если они не одобрены.",
                },
                StepRef {
                    id: "memory",
                    title: "Память",
                    text: "Отдельно просмотрите память в настройках Claude и удалите ненужные записи. Удаление разговора само по себе не удаляет созданные из него воспоминания.",
                },
                StepRef {
                    id: "training",
                    title: "Приватность",
                    text: "Просмотрите доступные настройки Privacy и использования новых разговоров для улучшения моделей. Для рабочего аккаунта учитывайте политику организации.",
                },
                VERIFY,
            ],
            &[
                SourceRef {
                    title: "Claude: удаление разговоров",
                    url: "https://support.claude.com/en/articles/8230524-delete-or-rename-a-conversation",
                },
                SourceRef {
                    title: "Claude: память",
                    url: "https://support.claude.com/en/articles/11817273-use-claude-s-chat-search-and-memory-to-build-on-previous-context",
                },
            ],
        ),
        Service::Gemini => (
            &[
                StepRef {
                    id: "history",
                    title: "История Gemini",
                    text: "В Gemini web откройте Settings → History или My Activity для Gemini. Найдите записи партии; перед удалением периода проверьте все затрагиваемые разговоры.",
                },
                StepRef {
                    id: "retention",
                    title: "Хранение и использование данных",
                    text: "Отдельно просмотрите текущие настройки History и обработки данных в справке Gemini. Для рабочего или учебного аккаунта сроками может управлять администратор.",
                },
                StepRef {
                    id: "memory",
                    title: "Сохранённая персонализация",
                    text: "Если в аккаунте есть сохранённые сведения и настройки персонализации, просмотрите их отдельно. Не считайте удаление истории подтверждением очистки других сервисов Google.",
                },
                VERIFY,
            ],
            &[
                SourceRef {
                    title: "Gemini: управление историей",
                    url: "https://support.google.com/gemini/answer/13278892?hl=en",
                },
                SourceRef {
                    title: "Gemini: приватность",
                    url: "https://support.google.com/gemini/answer/13594961?hl=en",
                },
            ],
        ),
    };
    Guide {
        service,
        checked_on: "2026-11-22".into(),
        steps: steps
            .iter()
            .map(|s| Step {
                id: s.id.into(),
                title: s.title.into(),
                text: s.text.into(),
            })
            .collect(),
        sources: sources
            .iter()
            .map(|s| Source {
                title: s.title.into(),
                url: s.url.into(),
            })
            .collect(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedOutcome {
    NotChecked,
    NoLongerVisible,
    StillVisible,
    Unavailable,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub outcome: ObservedOutcome,
    pub completed_steps: Vec<String>,
    pub checked_at: u64,
}
impl Review {
    pub fn validate(&self, service: Service) -> Result<(), crate::PurgeError> {
        let guide = guide(service);
        let unique: std::collections::BTreeSet<_> = self.completed_steps.iter().collect();
        if unique.len() != self.completed_steps.len()
            || unique.len() > guide.steps.len()
            || self
                .completed_steps
                .iter()
                .any(|id| !guide.steps.iter().any(|s| s.id == *id))
            || (self.outcome == ObservedOutcome::NoLongerVisible
                && !["history", "verify"]
                    .iter()
                    .all(|id| self.completed_steps.iter().any(|s| s == id)))
        {
            return Err(crate::PurgeError::Invalid);
        }
        Ok(())
    }
}
