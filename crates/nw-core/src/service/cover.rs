//! Narrow cover endpoint: never serializes workspace, configuration or model evidence.
use super::backend::{State, require};
use crate::workspace;
use nw_bridge::{CaptureKind, Command, ErrorCode, Mode, Result as Reply};
use nw_llm::LocalModel;
pub(super) struct DesktopCover(pub(super) State);
fn error(e: workspace::WorkspaceError) -> Reply {
    use workspace::WorkspaceError::*;
    Reply::Error {
        code: match e {
            AlreadyAttempted => ErrorCode::AlreadyAttempted,
            ExecutionBusy => ErrorCode::RequestInProgress,
            Paused => ErrorCode::Paused,
            Model => ErrorCode::ModelUnavailable,
            Store(_) => ErrorCode::StorageUnavailable,
            Invalid | Policy => ErrorCode::InvalidRequest,
            _ => ErrorCode::NotReady,
        },
    }
}
impl nw_bridge::Handler for DesktopCover {
    async fn handle(&self, request: Command) -> Reply {
        if let Command::Snapshot { snapshot } = request {
            let context = {
                let Ok(mut s) = self.0.session.lock() else {
                    return Reply::Error {
                        code: ErrorCode::StorageUnavailable,
                    };
                };
                let epoch = s.epoch;
                let Ok(w) = require(&mut s) else {
                    return Reply::Error {
                        code: ErrorCode::WorkspaceLocked,
                    };
                };
                let model = match w.model() {
                    Ok(m) => m,
                    Err(e) => return error(e),
                };
                (epoch, model)
            };
            let kind = match snapshot.kind {
                CaptureKind::YoutubeFeed => nw_mirror::SnapshotKind::YoutubeFeed,
                CaptureKind::AdTopics => nw_mirror::SnapshotKind::AdTopics,
                CaptureKind::SearchSuggestions => nw_mirror::SnapshotKind::SearchSuggestions,
                CaptureKind::AiMemory => nw_mirror::SnapshotKind::AiMemory,
            };
            let snapshot = nw_mirror::Snapshot {
                kind,
                captured_at: workspace::now(),
                items: snapshot.items,
            };
            if snapshot.validate().is_err() {
                return Reply::Error {
                    code: ErrorCode::InvalidRequest,
                };
            }
            let vectors = match context.1.embed(&snapshot.items).await {
                Ok(v) => v,
                Err(_) => {
                    return Reply::Error {
                        code: ErrorCode::ModelUnavailable,
                    };
                }
            };
            let Ok(mut s) = self.0.session.lock() else {
                return Reply::Error {
                    code: ErrorCode::StorageUnavailable,
                };
            };
            if s.epoch != context.0 {
                return Reply::Error {
                    code: ErrorCode::WorkspaceLocked,
                };
            }
            let Ok(w) = require(&mut s) else {
                return Reply::Error {
                    code: ErrorCode::WorkspaceLocked,
                };
            };
            return match w.snapshot(snapshot, &vectors) {
                Ok(_) => Reply::Ack {},
                Err(e) => error(e),
            };
        }
        let Ok(mut s) = self.0.session.lock() else {
            return Reply::Error {
                code: ErrorCode::StorageUnavailable,
            };
        };
        let Ok(w) = require(&mut s) else {
            return Reply::Error {
                code: ErrorCode::WorkspaceLocked,
            };
        };
        match request {
            Command::Status {} => Reply::Status {
                paused: w.paused(),
                mode: match w.config.drift.mode {
                    crate::config::DriftMode::Assisted => Mode::Assisted,
                    crate::config::DriftMode::Extension => Mode::Extension,
                },
                ai_web_automation: w.config.drift.allow_ai_web_automation,
            },
            Command::Tasks {} => match w.daily_tasks(workspace::now()) {
                Ok(tasks) => Reply::Tasks { tasks },
                Err(e) => error(e),
            },
            Command::Pause { paused } => match w.pause(paused) {
                Ok(()) => Reply::Ack {},
                Err(e) => error(e),
            },
            Command::SafetyStop { event_id, .. } => match w.safety_stop(&event_id) {
                Ok(()) => Reply::Ack {},
                Err(e) => error(e),
            },
            Command::Complete { task } => match w.complete_bound_task(&task, workspace::now()) {
                Ok(()) => Reply::Ack {},
                Err(e) => error(e),
            },
            Command::BeginSearch { task } => {
                match w.begin_search_execution(&task, workspace::now()) {
                    Ok(token) => Reply::Execution {
                        token: nw_bridge::ExecutionToken::new(token),
                    },
                    Err(e) => error(e),
                }
            }
            Command::FinishSearch { task, token } => {
                match w.finish_search_execution(&task, token.as_str(), workspace::now()) {
                    Ok(()) => Reply::Ack {},
                    Err(e) => error(e),
                }
            }
            Command::ValidateSearch { task, token } => {
                match w.validate_search_execution(&task, token.as_str(), workspace::now()) {
                    Ok(()) => Reply::Ack {},
                    Err(e) => error(e),
                }
            }
            Command::Snapshot { .. } => Reply::Error {
                code: ErrorCode::InvalidRequest,
            },
        }
    }
}
