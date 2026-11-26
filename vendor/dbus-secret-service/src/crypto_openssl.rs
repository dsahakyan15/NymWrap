// NymWrap patch: Secret Service's fixed RFC 2409 group and wire format are unchanged.
// Temporary Rust secret buffers are zeroized; OpenSSL owns/clears private BIGNUMs.
use openssl::{
    bn::BigNum,
    derive::Deriver,
    dh::Dh,
    md::Md,
    pkey::{Id, PKey, Private},
    pkey_ctx::PkeyCtx,
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use std::{cmp::Ordering, error::Error, io};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
pub(super) type AesKey = [u8; 16];

fn invalid() -> Box<dyn Error + Send + Sync> {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid_secret_service_crypto_input",
    )
    .into()
}

fn params() -> Result<Dh<openssl::pkey::Params>> {
    Ok(Dh::from_pqg(
        BigNum::get_rfc2409_prime_1024()?,
        None,
        BigNum::from_u32(2)?,
    )?)
}

pub(super) struct Keypair {
    private: PKey<Private>,
    pub(super) public: Vec<u8>,
}

impl Keypair {
    pub(super) fn generate() -> Result<Self> {
        let dh = params()?.generate_key()?;
        let public = dh.public_key().to_vec();
        Ok(Self {
            private: PKey::from_dh(dh)?,
            public,
        })
    }

    pub(super) fn derive_shared(&self, peer: &[u8]) -> Result<AesKey> {
        if peer.is_empty() || peer.len() > 128 {
            return Err(invalid());
        }
        let public = BigNum::from_slice(peer)?;
        let dh = params()?;
        let mut upper = dh.prime_p().to_owned()?;
        upper.sub_word(1)?;
        let one = BigNum::from_u32(1)?;
        if public.ucmp(&one) != Ordering::Greater || public.ucmp(&upper) != Ordering::Less {
            return Err(invalid());
        }
        let peer = PKey::from_dh(dh.set_public_key(public)?)?;
        let mut deriver = Deriver::new(&self.private)?;
        deriver.set_peer(&peer)?;
        let mut shared = Zeroizing::new([0u8; 128]);
        let length = deriver.derive(&mut shared[..])?;
        if length == 0 || length > shared.len() {
            return Err(invalid());
        }
        // DH_compute_key omits leading zeroes; Secret Service HKDF uses 128 bytes.
        let offset = shared.len() - length;
        shared.copy_within(..length, offset);
        shared[..offset].fill(0);
        let mut key = Zeroizing::new([0u8; 16]);
        let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
        ctx.derive_init()?;
        ctx.set_hkdf_md(Md::sha256())?;
        ctx.set_hkdf_key(&shared[..])?;
        ctx.add_hkdf_info(&[])?;
        ctx.derive(Some(&mut key[..]))?;
        Ok(*key)
    }
}

pub(super) fn encrypt(data: &[u8], key: &AesKey) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut iv = [0u8; 16];
    rand_bytes(&mut iv)?;
    let mut ctx = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, key, Some(&iv))?;
    let mut output = vec![0u8; data.len() + 16];
    let count = ctx.update(data, &mut output)?;
    let count = count + ctx.finalize(&mut output[count..])?;
    output.truncate(count);
    Ok((output, iv.to_vec()))
}

pub(super) fn decrypt(data: &[u8], key: &AesKey, iv: &[u8]) -> Result<Vec<u8>> {
    // Reject both short and long IVs before entering an FFI wrapper that may panic.
    if iv.len() != 16 || data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(invalid());
    }
    let mut ctx = Crypter::new(Cipher::aes_128_cbc(), Mode::Decrypt, key, Some(iv))?;
    // Keep failed/padding-error output zeroized as well as successful buffers.
    let mut output = Zeroizing::new(vec![0u8; data.len() + 16]);
    let count = ctx.update(data, &mut output)?;
    let count = count + ctx.finalize(&mut output[count..])?;
    Ok(output[..count].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_dh_vector_preserves_secret_service_left_padding_and_hkdf() {
        // g=2, private=2, peer=2^3 => shared=64. The wire KDF input is
        // 127 zero bytes followed by 0x40, not the one-byte integer 0x40.
        let dh = params()
            .unwrap()
            .set_private_key(BigNum::from_u32(2).unwrap())
            .unwrap();
        let public = dh.public_key().to_vec();
        let alice = Keypair {
            private: PKey::from_dh(dh).unwrap(),
            public,
        };
        let key = Zeroizing::new(alice.derive_shared(&[8]).unwrap());
        // Independently computed with Node's HKDF-SHA256, empty salt/info.
        assert_eq!(
            *key,
            [
                0xdd, 0x73, 0x52, 0xd6, 0x48, 0xb8, 0x1b, 0x68, 0xe7, 0xcf, 0xbf, 0x88, 0xf5, 0xc3,
                0xe2, 0xee
            ]
        );
        let mut p_minus_one = BigNum::get_rfc2409_prime_1024().unwrap();
        p_minus_one.sub_word(1).unwrap();
        assert!(alice.derive_shared(&p_minus_one.to_vec()).is_err());
        assert!(
            alice
                .derive_shared(&BigNum::get_rfc2409_prime_1024().unwrap().to_vec())
                .is_err()
        );
    }
}
