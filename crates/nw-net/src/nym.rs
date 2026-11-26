//! Reserved nw-netd boundary only. No SDK, state, telemetry or socket fallback.
//! ADR 0108 records why even experimental builds cannot use this transport.
use crate::NetError;

pub struct Nym {
    _private: (),
}
impl Nym {
    pub fn initialize() -> Result<Self, NetError> {
        Err(NetError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn experimental_nym_remains_unavailable() {
        assert!(matches!(
            super::Nym::initialize(),
            Err(crate::NetError::Unavailable)
        ));
    }
}
