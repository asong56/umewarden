//! Local encryption primitives (Argon2id + AES-256-GCM). Separate from
//! keys.rs, which implements Bitwarden's own key hierarchy - different
//! crypto choices, not meant to be mixed.
use crate::error::{VaultError, VaultResult};
use ring::{aead, rand::{self, SecureRandom}};
use zeroize::Zeroizing;

pub mod keys;
pub mod totp;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 32;

#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    /// salt should be a unique random 32 bytes per vault, stored in the vault header.
    pub fn derive(password: &str, salt: &[u8]) -> VaultResult<Self> {
        // TODO: expose Argon2id params as config; currently OWASP minimums (m=64MB, t=3, p=4)
        let params = argon2::Params::new(65536, 3, 4, Some(KEY_LEN))
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        Ok(MasterKey(key))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
    let rng = rand::SystemRandom::new();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| VaultError::Crypto("nonce generation failed".into()))?;

    let ring_key = aead::UnboundKey::new(&aead::AES_256_GCM, key.as_bytes())
        .map_err(|_| VaultError::Crypto("key construction failed".into()))?;
    let mut sealing_key = aead::SealingKey::new(
        ring_key,
        aead::Nonce::assume_unique_for_key(nonce_bytes),
    );

    let mut buf = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(aead::Aad::empty(), &mut buf)
        .map_err(|_| VaultError::Crypto("encryption failed".into()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

pub fn decrypt(key: &MasterKey, data: &[u8]) -> VaultResult<Vec<u8>> {
    if data.len() < NONCE_LEN + 16 {
        return Err(VaultError::Crypto("ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| VaultError::Crypto("invalid nonce".into()))?;

    let ring_key = aead::UnboundKey::new(&aead::AES_256_GCM, key.as_bytes())
        .map_err(|_| VaultError::Crypto("key construction failed".into()))?;
    let mut opening_key = aead::OpeningKey::new(ring_key, nonce);

    let mut buf = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(aead::Aad::empty(), &mut buf)
        .map_err(|_| VaultError::Crypto("decryption failed (wrong key or tampered data)".into()))?;

    Ok(plaintext.to_vec())
}

pub fn random_salt() -> VaultResult<[u8; SALT_LEN]> {
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| VaultError::Crypto("salt generation failed".into()))?;
    Ok(salt)
}
