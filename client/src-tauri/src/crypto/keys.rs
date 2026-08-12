//! Key chain: password+email -(KDF)-> master_key -(HKDF)-> stretched enc/mac
//! -> decrypts server's protected key -> user_enc_key/user_mac_key -> decrypts ciphers.
//! Ref: https://bitwarden.com/help/bitwarden-security-white-paper/

use crate::error::{VaultError, VaultResult};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use ring::{hmac, rand::SecureRandom};
use sha2::Sha256;
use zeroize::Zeroizing;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

// ─── EncString ────────────────────────────────────────────────────────────────

/// `{type}.{iv_b64}|{ciphertext_b64}[|{mac_b64}]`.
/// type 0 = AesCbc256_B64 (no MAC, deprecated), 2 = AesCbc256_HmacSha256_B64 (standard).
/// 4/6 (asymmetric, org keys) not implemented.
#[derive(Debug, Clone)]
pub struct EncString {
    pub enc_type:   u8,
    pub iv:         Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac:        Option<Vec<u8>>,
}

impl EncString {
    pub fn parse(s: &str) -> VaultResult<Self> {
        let (type_part, rest) = s
            .split_once('.')
            .ok_or_else(|| VaultError::Crypto("EncString: missing type separator".into()))?;

        let enc_type: u8 = type_part
            .parse()
            .map_err(|_| VaultError::Crypto("EncString: invalid type prefix".into()))?;

        let parts: Vec<&str> = rest.split('|').collect();

        match enc_type {
            2 => {
                if parts.len() != 3 {
                    return Err(VaultError::Crypto(
                        "EncString: type 2 requires iv|ct|mac".into(),
                    ));
                }
                Ok(EncString {
                    enc_type,
                    iv:         b64_decode(parts[0])?,
                    ciphertext: b64_decode(parts[1])?,
                    mac:        Some(b64_decode(parts[2])?),
                })
            }
            0 => {
                if parts.len() != 2 {
                    return Err(VaultError::Crypto(
                        "EncString: type 0 requires iv|ct".into(),
                    ));
                }
                Ok(EncString {
                    enc_type,
                    iv:         b64_decode(parts[0])?,
                    ciphertext: b64_decode(parts[1])?,
                    mac:        None,
                })
            }
            other => Err(VaultError::Crypto(format!(
                "EncString: unsupported type {other} (asymmetric/org-key EncStrings not implemented)"
            ))),
        }
    }

    pub fn decrypt(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> VaultResult<Zeroizing<Vec<u8>>> {
        if let Some(mac) = &self.mac {
            let mut mac_input = Vec::with_capacity(self.iv.len() + self.ciphertext.len());
            mac_input.extend_from_slice(&self.iv);
            mac_input.extend_from_slice(&self.ciphertext);

            let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
            hmac::verify(&key, &mac_input, mac)
                .map_err(|_| VaultError::Crypto("EncString: MAC verification failed (wrong key or tampered data)".into()))?;
        }

        let iv: [u8; 16] = self.iv.as_slice().try_into()
            .map_err(|_| VaultError::Crypto("EncString: IV must be 16 bytes".into()))?;

        let mut buf = self.ciphertext.clone();
        let key_ga = aes::cipher::generic_array::GenericArray::from_slice(enc_key);
        let iv_ga  = aes::cipher::generic_array::GenericArray::from_slice(&iv);
        let decryptor = Aes256CbcDec::new(key_ga, iv_ga);
        let plaintext = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| VaultError::Crypto("EncString: AES-CBC decryption failed (bad padding)".into()))?;

        Ok(Zeroizing::new(plaintext.to_vec()))
    }

    pub fn decrypt_to_string(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> VaultResult<String> {
        let bytes = self.decrypt(enc_key, mac_key)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| VaultError::Crypto("EncString: decrypted data is not valid UTF-8".into()))
    }

    pub fn encrypt(plaintext: &[u8], enc_key: &[u8; 32], mac_key: &[u8; 32]) -> VaultResult<Self> {
        let mut iv = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut iv)
            .map_err(|_| VaultError::Crypto("IV generation failed".into()))?;

        let mut buf = plaintext.to_vec();
        let pad_len = 16 - (buf.len() % 16);
        buf.resize(buf.len() + pad_len, 0);
        let ct_len = plaintext.len();

        let encryptor = Aes256CbcEnc::new(
            aes::cipher::generic_array::GenericArray::from_slice(enc_key),
            aes::cipher::generic_array::GenericArray::from_slice(&iv),
        );
        let ciphertext = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buf, ct_len)
            .map_err(|_| VaultError::Crypto("AES-CBC encryption failed".into()))?
            .to_vec();

        let mut mac_input = Vec::with_capacity(iv.len() + ciphertext.len());
        mac_input.extend_from_slice(&iv);
        mac_input.extend_from_slice(&ciphertext);
        let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
        let tag = hmac::sign(&key, &mac_input);

        Ok(EncString {
            enc_type: 2,
            iv: iv.to_vec(),
            ciphertext,
            mac: Some(tag.as_ref().to_vec()),
        })
    }
}

impl std::fmt::Display for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}|{}", self.enc_type, B64.encode(&self.iv), B64.encode(&self.ciphertext))?;
        if let Some(mac) = &self.mac {
            write!(f, "|{}", B64.encode(mac))?;
        }
        Ok(())
    }
}

fn b64_decode(s: &str) -> VaultResult<Vec<u8>> {
    B64.decode(s).map_err(|e| VaultError::Crypto(format!("base64 decode failed: {e}")))
}

/// HKDF-Expand only (no extract step) - master_key is already high-entropy KDF output.
pub fn stretch_master_key(master_key: &[u8; 32]) -> VaultResult<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let hk = Hkdf::<Sha256>::from_prk(master_key)
        .map_err(|_| VaultError::Crypto("HKDF: master_key too short as PRK".into()))?;

    let mut enc_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"enc", enc_key.as_mut())
        .map_err(|_| VaultError::Crypto("HKDF expand(enc) failed".into()))?;

    let mut mac_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"mac", mac_key.as_mut())
        .map_err(|_| VaultError::Crypto("HKDF expand(mac) failed".into()))?;

    Ok((enc_key, mac_key))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2Sha256,
    Argon2id,
}

impl KdfType {
    pub fn from_server_value(v: u32) -> VaultResult<Self> {
        match v {
            0 => Ok(KdfType::Pbkdf2Sha256),
            1 => Ok(KdfType::Argon2id),
            other => Err(VaultError::Crypto(format!("unknown KDF type from server: {other}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub kdf_type:    KdfType,
    pub iterations:  u32, // PBKDF2 iterations, or Argon2id t_cost
    pub memory_mib:  Option<u32>, // Argon2id only
    pub parallelism: Option<u32>, // Argon2id only
}

/// salt = lowercased email, not random - same account must derive the same
/// master_key on every device.
pub fn derive_master_key(password: &str, email: &str, params: &KdfParams) -> VaultResult<Zeroizing<[u8; 32]>> {
    let salt = email.trim().to_lowercase();
    let mut out = Zeroizing::new([0u8; 32]);

    match params.kdf_type {
        KdfType::Pbkdf2Sha256 => {
            let iterations = std::num::NonZeroU32::new(params.iterations.max(1))
                .ok_or_else(|| VaultError::Crypto("PBKDF2 iterations must be > 0".into()))?;
            ring::pbkdf2::derive(
                ring::pbkdf2::PBKDF2_HMAC_SHA256,
                iterations,
                salt.as_bytes(),
                password.as_bytes(),
                out.as_mut(),
            );
        }
        KdfType::Argon2id => {
            let memory_kib = params
                .memory_mib
                .ok_or_else(|| VaultError::Crypto("Argon2id requires memory_mib".into()))?
                * 1024; // API gives MiB, argon2 crate wants KiB
            let parallelism = params
                .parallelism
                .ok_or_else(|| VaultError::Crypto("Argon2id requires parallelism".into()))?;

            // same raw salt as the PBKDF2 branch - no extra SHA-256(email) pre-hash
            let argon2_params = argon2::Params::new(memory_kib, params.iterations.max(1), parallelism, Some(32))
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params);
            argon2
                .hash_password_into(password.as_bytes(), salt.as_bytes(), out.as_mut())
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
        }
    }

    Ok(out)
}

/// PBKDF2-SHA256(secret=master_key, salt=password, 1 iteration), base64-encoded.
/// Not the same as the 2-iteration local-verification hash used elsewhere -
/// this one is what the server expects in /connect/token.
pub fn master_password_hash(master_key: &[u8; 32], password: &str) -> String {
    let mut out = [0u8; 32];
    let one_iter = std::num::NonZeroU32::new(1).expect("1 is nonzero");
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        one_iter,
        password.as_bytes(),
        master_key,
        &mut out,
    );
    B64.encode(out)
}

#[derive(Clone)]
pub struct DecryptContext {
    pub enc_key: Zeroizing<[u8; 32]>,
    pub mac_key: Zeroizing<[u8; 32]>,
}

impl DecryptContext {
    /// Decrypted protected_key is 64 bytes: [0..32]=enc_key, [32..64]=mac_key.
    pub fn from_protected_key(
        protected_key: &EncString,
        stretched_enc_key: &[u8; 32],
        stretched_mac_key: &[u8; 32],
    ) -> VaultResult<Self> {
        let raw = protected_key.decrypt(stretched_enc_key, stretched_mac_key)?;
        if raw.len() != 64 {
            return Err(VaultError::Crypto(format!(
                "decrypted user key has unexpected length {} (expected 64)",
                raw.len()
            )));
        }

        let mut enc_key = Zeroizing::new([0u8; 32]);
        let mut mac_key = Zeroizing::new([0u8; 32]);
        enc_key.copy_from_slice(&raw[0..32]);
        mac_key.copy_from_slice(&raw[32..64]);

        Ok(DecryptContext { enc_key, mac_key })
    }

    pub fn decrypt_str(&self, enc_string: &str) -> VaultResult<String> {
        EncString::parse(enc_string)?.decrypt_to_string(&self.enc_key, &self.mac_key)
    }

    pub fn encrypt_str(&self, plaintext: &str) -> VaultResult<String> {
        Ok(EncString::encrypt(plaintext.as_bytes(), &self.enc_key, &self.mac_key)?.to_string())
    }
}
