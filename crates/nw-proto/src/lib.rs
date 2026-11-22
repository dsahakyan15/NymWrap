//! Versioned IPC. A lane is assigned by the receiving endpoint, never by payload.
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Shadow,
    Cover,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Standard,
    Strict,
    Paranoid,
}

/// Lower numbers demand stronger privacy; L4 cannot be represented.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TrustLevel {
    L0,
    L1,
    L2,
    L3,
}

impl Profile {
    pub fn min_trust(self) -> TrustLevel {
        match self {
            Self::Standard => TrustLevel::L3,
            Self::Strict => TrustLevel::L2,
            Self::Paranoid => TrustLevel::L1,
        }
    }
    pub fn max_turns(self) -> usize {
        match self {
            Self::Standard => 30,
            Self::Strict => 12,
            Self::Paranoid => 6,
        }
    }
    pub fn requires_approval(self) -> bool {
        self != Self::Standard
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Google,
    Youtube,
    Chatgpt,
    Claude,
    Gemini,
}

impl Service {
    pub fn is_ai(self) -> bool {
        matches!(self, Self::Chatgpt | Self::Claude | Self::Gemini)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftTask {
    pub plan_hash: String,
    pub stage: u16,
    pub day: u16,
    pub action_index: u16,
    pub service: Service,
    pub text: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Msg {
    ShieldRequest {
        conversation: String,
        text: String,
        min_trust: TrustLevel,
    },
    ShieldResponse {
        conversation: String,
        text: String,
        trust: TrustLevel,
    },
    DriftTask(DriftTask),
    DriftResult {
        plan_hash: String,
        stage: u16,
        day: u16,
        completed: bool,
    },
    AuditImport {
        format: String,
    },
    Error {
        code: ErrorCode,
    },
}

impl Msg {
    pub fn lane(&self) -> Option<Lane> {
        match self {
            Self::ShieldRequest { .. } | Self::ShieldResponse { .. } | Self::AuditImport { .. } => {
                Some(Lane::Shadow)
            }
            Self::DriftTask(_) | Self::DriftResult { .. } => Some(Lane::Cover),
            Self::Error { .. } => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u16,
    pub lane: Lane,
    pub message: Msg,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    #[error("invalid_schema")]
    InvalidSchema,
    #[error("frame_too_large")]
    FrameTooLarge,
    #[error("wrong_lane")]
    WrongLane,
    #[error("blocked")]
    Blocked,
    #[error("approval_required")]
    ApprovalRequired,
    #[error("transport_unavailable")]
    TransportUnavailable,
    #[error("local_model_unavailable")]
    LocalModelUnavailable,
    #[error("unsupported")]
    Unsupported,
}

impl Envelope {
    pub fn new(lane: Lane, message: Msg) -> Result<Self, ErrorCode> {
        let envelope = Self {
            version: SCHEMA_VERSION,
            lane,
            message,
        };
        envelope.validate(lane)?;
        Ok(envelope)
    }
    pub fn validate(&self, endpoint_lane: Lane) -> Result<(), ErrorCode> {
        if self.version != SCHEMA_VERSION {
            return Err(ErrorCode::InvalidSchema);
        }
        if self.lane != endpoint_lane || self.message.lane().is_some_and(|l| l != endpoint_lane) {
            return Err(ErrorCode::WrongLane);
        }
        match &self.message {
            Msg::ShieldRequest {
                text, conversation, ..
            }
            | Msg::ShieldResponse {
                text, conversation, ..
            } => {
                if text.len() > MAX_TEXT_BYTES || conversation.len() > 128 {
                    return Err(ErrorCode::FrameTooLarge);
                }
            }
            Msg::DriftTask(task)
                if task.text.len() > 4096
                    || task.plan_hash.len() != 64
                    || task.stage == 0
                    || task.day == 0 =>
            {
                return Err(ErrorCode::InvalidSchema);
            }
            _ => {}
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8], endpoint_lane: Lane) -> Result<Self, ErrorCode> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ErrorCode::FrameTooLarge);
        }
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidSchema)?;
        envelope.validate(endpoint_lane)?;
        Ok(envelope)
    }
    pub fn encode(&self, endpoint_lane: Lane) -> Result<Vec<u8>, ErrorCode> {
        self.validate(endpoint_lane)?;
        let bytes = serde_json::to_vec(self).map_err(|_| ErrorCode::InvalidSchema)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ErrorCode::FrameTooLarge);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_forged_lane_version_unknown_fields_and_oversize() {
        let e = Envelope::new(
            Lane::Shadow,
            Msg::ShieldRequest {
                conversation: "new".into(),
                text: "synthetic".into(),
                min_trust: TrustLevel::L0,
            },
        )
        .unwrap();
        let encoded = e.encode(Lane::Shadow).unwrap();
        assert_eq!(
            Envelope::decode(&encoded, Lane::Cover).err(),
            Some(ErrorCode::WrongLane)
        );
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["extra"] = true.into();
        assert!(Envelope::decode(&serde_json::to_vec(&value).unwrap(), Lane::Shadow).is_err());
        value.as_object_mut().unwrap().remove("extra");
        value["message"]["data"]["secret"] = "hidden".into();
        assert!(Envelope::decode(&serde_json::to_vec(&value).unwrap(), Lane::Shadow).is_err());
        value["version"] = 2.into();
        assert!(Envelope::decode(&serde_json::to_vec(&value).unwrap(), Lane::Shadow).is_err());
        assert_eq!(
            Envelope::decode(&vec![0; MAX_FRAME_BYTES + 1], Lane::Shadow).err(),
            Some(ErrorCode::FrameTooLarge)
        );
    }
}
