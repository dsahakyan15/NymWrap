//! A fresh key is delivered to a child daemon over inherited stdin, never argv/disk.
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use nw_platform::LockedKey;
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
const AAD: &[u8] = b"nymwrap-egress-shadow-v1";
pub const MAX_WIRE: usize = 512 * 1024;
pub struct SessionKey(LockedKey);
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub sequence: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub conversation: String,
    pub body: Vec<u8>,
    pub authorization: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Initialize {
        state: String,
        host: String,
        path: String,
        #[serde(default)]
        bridges: Option<crate::bridges::BridgeConfig>,
    },
    Send {
        request: Request,
    },
    SendOnce {
        request: Request,
    },
    Reset {},
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ready {},
    Answer { text: String },
    Error { code: String },
}
impl SessionKey {
    pub fn new(mut bytes: [u8; 32]) -> std::io::Result<Self> {
        let key = LockedKey::new(SecretBox::new(Box::new(bytes)));
        bytes.zeroize();
        Ok(Self(key?))
    }
    pub fn seal<T: Serialize>(&self, sequence: u64, value: &T) -> Result<Envelope, &'static str> {
        if sequence == 0 {
            return Err("invalid_sequence");
        }
        let bytes =
            Zeroizing::new(serde_json::to_vec(value).map_err(|_| "invalid_egress_message")?);
        if bytes.len() > MAX_WIRE {
            return Err("egress_too_large");
        }
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(&sequence.to_le_bytes());
        let cipher = XChaCha20Poly1305::new(self.0.expose_secret().into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| "egress_authentication_failed")?;
        Ok(Envelope {
            sequence,
            nonce,
            ciphertext,
        })
    }
    pub fn open<T: serde::de::DeserializeOwned>(
        &self,
        envelope: &Envelope,
        expected: u64,
    ) -> Result<T, &'static str> {
        if expected == 0
            || envelope.sequence != expected
            || envelope.ciphertext.len() > MAX_WIRE + 16
        {
            return Err("invalid_egress_sequence");
        }
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(&expected.to_le_bytes());
        let cipher = XChaCha20Poly1305::new(self.0.expose_secret().into());
        let bytes = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&envelope.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| "egress_authentication_failed")?,
        );
        serde_json::from_slice(&bytes).map_err(|_| "invalid_egress_message")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_frames_bind_sequence_and_key() {
        let key = SessionKey::new([7; 32]).unwrap();
        let other = SessionKey::new([8; 32]).unwrap();
        let mut frame = key
            .seal(
                1,
                &Response::Answer {
                    text: "synthetic".into(),
                },
            )
            .unwrap();
        assert!(key.open::<Response>(&frame, 1).is_ok());
        assert!(key.open::<Response>(&frame, 2).is_err());
        assert!(other.open::<Response>(&frame, 1).is_err());
        frame.ciphertext[0] ^= 1;
        assert!(key.open::<Response>(&frame, 1).is_err());
    }
}
