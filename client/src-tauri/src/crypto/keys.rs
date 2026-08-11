/// Bitwarden / Vaultwarden 密钥层级
///
/// Bitwarden 的密钥体系（完整链路）：
///
///   master password + email(lowercase, 作为 salt)
///     └─ KDF(PBKDF2-SHA256 或 Argon2id，类型由服务器 prelogin 返回) → master_key (256-bit)
///         │
///         ├─ PBKDF2-SHA256(master_key, password, 1 iter) → master_password_hash
///         │     （发送给服务器用于登录认证，服务器保存的是这个 hash 的 hash）
///         │
///         └─ HKDF-Expand(master_key as PRK, info="enc"/"mac") → stretched enc_key/mac_key (各 256-bit)
///               │
///               └─ 用 stretched enc_key+mac_key 解密服务器返回的 protected symmetric key (EncString)
///                     → 64 字节：前 32 字节 = user_enc_key，后 32 字节 = user_mac_key
///                           │
///                           └─ 用 user_enc_key + user_mac_key 解密所有 cipher 字段（AES-256-CBC + HMAC-SHA256）
///
/// 参考：https://bitwarden.com/help/bitwarden-security-white-paper/
///       Goldwarden: cli/agent/bitwarden/crypto.go（HKDF stretch + EncString 解密的等价实现）

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

/// Bitwarden EncString 格式：`{type}.{iv_b64}|{ciphertext_b64}[|{mac_b64}]`
///
/// 已知 type 值：
///   0 = AesCbc256_B64                （无 MAC，已弃用，部分旧组织密钥仍可能用）
///   2 = AesCbc256_HmacSha256_B64      （当前标准格式，绝大多数字段用这个）
///   4/6 = 非对称（RSA），组织密钥场景，本实现暂不支持
#[derive(Debug, Clone)]
pub struct EncString {
    pub enc_type:   u8,
    pub iv:         Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac:        Option<Vec<u8>>,
}

impl EncString {
    /// 解析 "type.iv|ct|mac" 格式的字符串
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
                // AesCbc256_HmacSha256_B64: iv|ct|mac
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
                // AesCbc256_B64（无 MAC）：iv|ct
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

    /// 使用 enc_key + mac_key 解密。
    /// 先验证 HMAC-SHA256（常数时间比较，由 ring::hmac::verify 保证），再 AES-256-CBC 解密并去 PKCS7 padding。
    pub fn decrypt(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> VaultResult<Zeroizing<Vec<u8>>> {
        if let Some(mac) = &self.mac {
            // MAC 覆盖范围：iv || ciphertext
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

    /// 解密为 UTF-8 字符串（绝大多数 cipher 字段用这个）
    pub fn decrypt_to_string(&self, enc_key: &[u8; 32], mac_key: &[u8; 32]) -> VaultResult<String> {
        let bytes = self.decrypt(enc_key, mac_key)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| VaultError::Crypto("EncString: decrypted data is not valid UTF-8".into()))
    }

    /// 加密任意字节为 EncString（type 2, AesCbc256_HmacSha256_B64），用于 create/update item
    pub fn encrypt(plaintext: &[u8], enc_key: &[u8; 32], mac_key: &[u8; 32]) -> VaultResult<Self> {
        let mut iv = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut iv)
            .map_err(|_| VaultError::Crypto("IV generation failed".into()))?;

        // PKCS7 padding 需要预留到下一个 16 字节边界的空间
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
    /// 序列化回 "type.iv|ct|mac" 格式，供上传给服务器
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

// ─── 密钥拉伸（stretch）───────────────────────────────────────────────────────

/// 从 master_key 派生 stretched enc_key / mac_key（HKDF-Expand-only，无 extract 步骤，
/// 因为 master_key 本身已经是高熵的 KDF 输出，符合 Bitwarden 官方实现的做法）。
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

// ─── Master key 派生（PBKDF2 或 Argon2id，取决于服务器 KDF 配置）────────────────

/// KDF 类型，对应 Bitwarden prelogin 响应里的 `kdf` 字段
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
    pub iterations:  u32,          // PBKDF2: 迭代次数；Argon2id: t_cost
    pub memory_mib:  Option<u32>,  // 仅 Argon2id，单位 MiB（服务器返回的就是 MiB）
    pub parallelism: Option<u32>,  // 仅 Argon2id
}

/// 派生 master_key = KDF(password, salt=email_lowercase)
///
/// 注意：Bitwarden 用 email（小写，UTF-8 字节）作为 salt，而不是随机盐 ——
/// 这是协议本身的设计（同一账号在不同设备登录必须得到相同的 master_key）。
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
                * 1024; // Bitwarden API 用 MiB，argon2 crate 的 Params 用 KiB
            let parallelism = params
                .parallelism
                .ok_or_else(|| VaultError::Crypto("Argon2id requires parallelism".into()))?;

            // salt 和 PBKDF2 分支一样，直接用 trim+lowercase 后的 email 原始字节 ——
            // 官方客户端的 deriveKeyFromPassword(password, salt=email, kdfConfig) 对两个
            // KDF 分支传的是同一个 salt 参数，没有对 Argon2id 分支做额外的预哈希。
            // （早期草稿这里错误地加了一次 SHA-256(email) 预处理，已经改掉 —— 那是没有
            // 核实来源就写的细节，如果真的编译测试连接 Argon2id 配置的服务器发现登录失败，
            // 这是第一个该怀疑的地方。）
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

/// 计算 master password hash（发给服务器 /connect/token 做登录认证用）
/// = PBKDF2-SHA256(secret=master_key, salt=password, 1 iteration)，然后 base64 编码
///
/// 注意：Bitwarden 生态里还存在另一个"本地校验用的 master key hash"，那个是拿
/// **2 次迭代**算出来、只在本地比对（比如重新输入主密码解锁时的本地验证、不需要
/// 联网），跟这里发给服务器登录用的这个是两个不同的值，别搞混。如果照着这个函数
/// 实现之后登录一直被服务器拒绝，第一件事就是用浏览器开发者工具抓一下真实登录请求
/// 的 `password` 字段做对比，确认没有搞反两个哈希。
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

// ─── 解密上下文 ───────────────────────────────────────────────────────────────

/// 持有 user_enc_key + user_mac_key，用于解密所有 cipher 字段。
/// 由 daemon::handle_unlock 在解锁流程末尾构造，存入 VaultState。
#[derive(Clone)]
pub struct DecryptContext {
    pub enc_key: Zeroizing<[u8; 32]>,
    pub mac_key: Zeroizing<[u8; 32]>,
}

impl DecryptContext {
    /// 从服务器返回的 protected symmetric key（EncString，用 stretched key 加密）解密得到。
    /// protected_key 解密后应为 64 字节：[0..32]=user_enc_key, [32..64]=user_mac_key
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

    /// 便捷方法：解密一个 EncString 字符串（parse + decrypt 一步到位）
    pub fn decrypt_str(&self, enc_string: &str) -> VaultResult<String> {
        EncString::parse(enc_string)?.decrypt_to_string(&self.enc_key, &self.mac_key)
    }

    /// 便捷方法：加密明文为 EncString 字符串表示
    pub fn encrypt_str(&self, plaintext: &str) -> VaultResult<String> {
        Ok(EncString::encrypt(plaintext.as_bytes(), &self.enc_key, &self.mac_key)?.to_string())
    }
}
