//! Low level cryptography: random bytes, Argon2id key derivation and
//! XChaCha20-Poly1305 authenticated encryption.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug)]
pub enum CryptoError {
    Random,
    Kdf(String),
    /// Wrong key, wrong password, or the data was tampered with.
    Decrypt,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Random => write!(f, "the system random number generator failed"),
            CryptoError::Kdf(e) => write!(f, "key derivation failed: {e}"),
            CryptoError::Decrypt => write!(f, "decryption failed"),
        }
    }
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| CryptoError::Random)?;
    Ok(out)
}

pub fn random_key() -> Result<SecretKey, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut()).map_err(|_| CryptoError::Random)?;
    Ok(key)
}

/// Uniform random number in `0..bound` (rejection sampling, no modulo bias).
pub fn random_below(bound: u32) -> Result<u32, CryptoError> {
    assert!(bound > 0);
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let v = getrandom::u32().map_err(|_| CryptoError::Random)?;
        if v < zone {
            return Ok(v % bound);
        }
    }
}

/// Argon2id cost settings, stored in the vault file so they can be raised later
/// without breaking older vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// 256 MiB, 3 passes, 4 lanes. Each password guess costs an attacker the same.
    pub const STRONG: KdfParams = KdfParams { m_cost: 256 * 1024, t_cost: 3, p_cost: 4 };
    /// Cheap settings used only by the unit tests.
    #[cfg(test)]
    pub const TEST: KdfParams = KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
}

pub fn derive_key(password: &[u8], salt: &[u8], p: KdfParams) -> Result<SecretKey, CryptoError> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(KEY_LEN))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

/// Turns arbitrary secret material (for example a Windows Hello signature)
/// into a 256-bit key, bound to a purpose label.
pub fn key_from_material(label: &[u8], material: &[u8]) -> SecretKey {
    let mut h = Sha256::new();
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update(material);
    let digest = h.finalize();
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&digest);
    out
}

/// A nonce plus ciphertext (which carries the 16 byte Poly1305 tag).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Sealed { nonce: nonce_bytes.to_vec(), ciphertext })
}

pub fn open(key: &[u8; KEY_LEN], sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce_bytes: [u8; NONCE_LEN] = sealed.nonce.as_slice().try_into().map_err(|_| CryptoError::Decrypt)?;
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let nonce = XNonce::from(nonce_bytes);
    cipher
        .decrypt(&nonce, Payload { msg: &sealed.ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// Seals a 32 byte key under another key.
pub fn wrap_key(kek: &[u8; KEY_LEN], key: &[u8; KEY_LEN], aad: &[u8]) -> Result<Sealed, CryptoError> {
    seal(kek, key, aad)
}

pub fn unwrap_key(kek: &[u8; KEY_LEN], sealed: &Sealed, aad: &[u8]) -> Result<SecretKey, CryptoError> {
    let plain = open(kek, sealed, aad)?;
    if plain.len() != KEY_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&plain);
    Ok(out)
}

/// Base64 (standard alphabet) for byte fields in the JSON vault file.
pub mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key().unwrap();
        let sealed = seal(&key, b"hello", b"aad").unwrap();
        assert_ne!(sealed.ciphertext, b"hello");
        assert_eq!(&open(&key, &sealed, b"aad").unwrap()[..], b"hello");
    }

    #[test]
    fn wrong_key_or_aad_fails() {
        let key = random_key().unwrap();
        let other = random_key().unwrap();
        let sealed = seal(&key, b"secret", b"aad").unwrap();
        assert!(open(&other, &sealed, b"aad").is_err());
        assert!(open(&key, &sealed, b"different").is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let key = random_key().unwrap();
        let mut sealed = seal(&key, b"secret", b"").unwrap();
        sealed.ciphertext[0] ^= 1;
        assert!(open(&key, &sealed, b"").is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = random_key().unwrap();
        let a = seal(&key, b"x", b"").unwrap();
        let b = seal(&key, b"x", b"").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn kdf_is_deterministic_and_salted() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"pw", &salt, KdfParams::TEST).unwrap();
        let b = derive_key(b"pw", &salt, KdfParams::TEST).unwrap();
        let c = derive_key(b"pw", &[8u8; SALT_LEN], KdfParams::TEST).unwrap();
        let d = derive_key(b"pw2", &salt, KdfParams::TEST).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    #[test]
    fn strong_params_are_accepted_by_argon2() {
        let p = KdfParams::STRONG;
        assert!(Params::new(p.m_cost, p.t_cost, p.p_cost, Some(KEY_LEN)).is_ok());
    }

    #[test]
    fn random_below_stays_in_range() {
        for _ in 0..1000 {
            assert!(random_below(7).unwrap() < 7);
        }
    }
}
