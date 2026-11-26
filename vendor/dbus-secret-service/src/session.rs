// Copyright 2016-2024 dbus-secret-service Contributors
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// key exchange and crypto for session:
// 1. Before session negotiation (openSession), set private key and public key using DH method.
// 2. In session negotiation, send public key.
// 3. In session negotiation, exchange my public key for server's public key.
// 4. Use server public key and my private key to derive a shared AES key using HKDF.
// 5. Format Secret: aes iv is random seed, in secret struct it's the parameter (Array(Byte))
// 6. Format Secret: encode the secret value for the value field in secret struct.
//      This encoding uses the aes_key from the associated Session.

use dbus::{
    arg::{RefArg, Variant},
    blocking::{Connection, Proxy},
    Path,
};
use zeroize::ZeroizeOnDrop;

use crate::Error;

#[cfg(any(feature = "crypto-rust", not(feature = "crypto-openssl")))]
compile_error!("NymWrap requires crypto-openssl; crypto-rust is disabled");

/// The algorithms that can be used for encryption-in-transit.
///
/// If you are writing an ultra-secure program that accesses the secret service,
/// and you want to be sure that your secrets are encrypted while being sent to
/// or retrieved from the service, you can specify either the "crypto-rust" or
/// the "crypto-openssl" feature to this crate and tell it to use Diffie-Hellman
/// shared key encryption when passing secrets.  If you don't specify one of those
/// features, then your only choice is to use no encryption.
#[derive(Debug, Eq, PartialEq)]
pub enum EncryptionType {
    /// Use no encryption when sending/receiving secrets
    Plain,
    #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
    /// Use Diffie-Hellman shared key encryption when sending/receiving secrets
    Dh,
}

#[derive(ZeroizeOnDrop)]
pub(crate) struct EncryptedSecret {
    #[zeroize(skip)]
    path: Path<'static>, // the session path
    salt: Vec<u8>,           // the salt for the encrypted data
    data: Vec<u8>,           // the encrypted data
    pub(crate) mime: String, // the mime type of the decrypted data
}

impl EncryptedSecret {
    pub(crate) fn from_dbus(value: (Path<'static>, Vec<u8>, Vec<u8>, String)) -> Self {
        Self {
            path: value.0,
            salt: value.1,
            data: value.2,
            mime: value.3.to_string(),
        }
    }

    pub(crate) fn to_dbus(&self) -> (Path<'static>, Vec<u8>, Vec<u8>, &str) {
        (
            self.path.clone(),
            self.salt.clone(),
            self.data.clone(),
            &self.mime,
        )
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Session {
    #[zeroize(skip)]
    pub(crate) path: Path<'static>,
    #[zeroize(skip)]
    encryption: EncryptionType,
    #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
    shared_key: Option<crypto::AesKey>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("path", &self.path)
            .field(
                "secrets",
                if self.is_encrypted() {
                    &"(Hidden)"
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

impl Session {
    pub fn new(p: Proxy<'_, &'_ Connection>, encryption: EncryptionType) -> Result<Session, Error> {
        use crate::proxy::service::Service;
        match encryption {
            EncryptionType::Plain => {
                use crate::ss::ALGORITHM_PLAIN;
                // in rust 1.70, this lint applies here even though it shouldn't
                // because we need an explicit string to interpret as a RefArg
                #[allow(clippy::box_default)]
                let bytes_arg = Box::new(String::new()) as Box<dyn RefArg>;
                let (_, path) = p.open_session(ALGORITHM_PLAIN, Variant(bytes_arg))?;
                Ok(Session {
                    path,
                    encryption,
                    #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
                    shared_key: None,
                })
            }
            #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
            EncryptionType::Dh => {
                use crate::ss::ALGORITHM_DH;
                use dbus::arg::cast;

                // crypto: create private and public key
                let keypair = crypto::Keypair::generate().map_err(Error::Crypto)?;

                // send our public key with algorithm to service
                let public_bytes = keypair.public.clone();
                let bytes_arg = Variant(Box::new(public_bytes) as Box<dyn RefArg>);
                let (out, path) = p.open_session(ALGORITHM_DH, bytes_arg)?;

                // get service public key back and create shared key from it
                if let Some(server_public_key_bytes) = cast::<Vec<u8>>(&out.0) {
                    let shared_key = keypair
                        .derive_shared(server_public_key_bytes)
                        .map_err(Error::Crypto)?;
                    Ok(Session {
                        path,
                        encryption,
                        #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
                        shared_key: Some(shared_key),
                    })
                } else {
                    Err(Error::Parse)
                }
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        match self.encryption {
            EncryptionType::Plain => false,
            #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
            EncryptionType::Dh => true,
        }
    }

    pub(crate) fn encrypt_secret(&self, data: &[u8], mime: &str) -> Result<EncryptedSecret, Error> {
        Ok(match self.encryption {
            EncryptionType::Plain => EncryptedSecret {
                path: self.path.clone(),
                salt: vec![],
                data: data.to_vec(),
                mime: mime.to_string(),
            },
            #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
            EncryptionType::Dh => {
                // encrypt the secret with the data
                let (encrypted, salt) =
                    crypto::encrypt(data, self.shared_key.as_ref().ok_or(Error::Parse)?)
                        .map_err(Error::Crypto)?;
                EncryptedSecret {
                    path: self.path.clone(),
                    salt,
                    data: encrypted,
                    mime: mime.to_string(),
                }
            }
        })
    }

    pub(crate) fn decrypt_secret(&self, secret: EncryptedSecret) -> Result<Vec<u8>, Error> {
        match self.encryption {
            EncryptionType::Plain => Ok(secret.data.clone()),
            #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
            EncryptionType::Dh => {
                let clear = crypto::decrypt(
                    &secret.data,
                    self.shared_key.as_ref().ok_or(Error::Parse)?,
                    &secret.salt,
                )
                .map_err(Error::Crypto)?;
                Ok(clear)
            }
        }
    }
}

#[cfg(feature = "crypto-openssl")]
#[path = "crypto_openssl.rs"]
mod crypto;

#[cfg(test)]
mod test {
    use dbus::blocking::Connection;

    use crate::proxy::new_proxy;
    use crate::ss::SS_DBUS_PATH;

    use super::*;

    #[test]
    fn should_create_plain_session() {
        let connection = Connection::new_session().unwrap();
        let proxy = new_proxy(&connection, SS_DBUS_PATH);
        let session = Session::new(proxy, EncryptionType::Plain).unwrap();
        assert!(!session.is_encrypted());
    }

    #[cfg(any(feature = "crypto-rust", feature = "crypto-openssl"))]
    #[test]
    fn should_create_encrypted_session() {
        let connection = Connection::new_session().unwrap();
        let proxy = new_proxy(&connection, SS_DBUS_PATH);
        let session = Session::new(proxy, EncryptionType::Dh).unwrap();
        assert!(session.is_encrypted());
    }
}
