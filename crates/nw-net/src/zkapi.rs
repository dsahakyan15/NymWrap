//! Protocol candidate, never evidence that an anonymous upstream is deployed.
//! Socket/HTTP code belongs exclusively to nw-netd. See ADR 0107.
use crate::NetError;
use nw_proto::TrustLevel;

pub const PATH: &str = "/v1/chat/completions";
pub const CREDENTIAL_REF: &str = "keyring:experimental-zkapi";
pub const UPSTREAM_REVISION: &str = "0fb263b0da04986cfe5c63b12340c1581018ae9b";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Tor,
    #[cfg(feature = "experimental-nym")]
    Nym,
}
impl Route {
    /// Policy floor for admission tests, NOT an available/verified trust level.
    pub fn candidate_trust(self) -> TrustLevel {
        match self {
            Self::Tor => TrustLevel::L2,
            #[cfg(feature = "experimental-nym")]
            Self::Nym => TrustLevel::L1,
        }
    }
    /// No manifest, ceremony assets, reviewed final-rewrite boundary or Nym
    /// connector exists. A healthy HTTP endpoint cannot open this gate.
    pub fn ensure_available(self) -> Result<(), NetError> {
        Err(NetError::Unavailable)
    }
}
