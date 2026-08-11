/// Umewarden 加密层
///
/// 技术选型：
///   - KDF:        Argon2id（memory-hard，抗 GPU 暴力破解）
///   - 对称加密:   AES-256-GCM（ring 提供 AEAD，含完整性校验）
///   - 密钥派生:   HKDF-SHA256（从 master key 派生子密钥）
///   - 随机数:     ring::rand::SystemRandom
///
/// 所有密钥材料使用 `zeroize` 包装，Drop 时自动清零。
use crate::error::{VaultError, VaultResult};
use ring::{aead, rand::{self, SecureRandom}};
use zeroize::Zeroizing;

// 这个模块提供的 AES-256-GCM + Argon2id 是通用本地加密原语（例如未来可能需要的
// 本地缓存加密），不是 Bitwarden 协议本身用的方案 —— Bitwarden 的密钥层级
// （PBKDF2/Argon2id 由服务器 KDF 参数决定 + HKDF-Expand 拉伸 + AES-256-CBC）
// 单独实现在 `keys.rs` 里，因为两者的密码学原语选择完全不同，不应该混用。

pub mod keys;
pub mod totp;

// ─── 常量 ─────────────────────────────────────────────────────────────────────

/// AES-256-GCM nonce 长度（96 bit）
const NONCE_LEN: usize = 12;
/// AES-256-GCM key 长度（256 bit）
const KEY_LEN: usize = 32;
/// Argon2id 盐长度
const SALT_LEN: usize = 32;

// ─── MasterKey ────────────────────────────────────────────────────────────────

/// 从 master password + salt 派生出的 256-bit 主密钥。
/// 内部用 `Zeroizing<[u8; KEY_LEN]>` 保证 Drop 时清零。
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    /// 使用 Argon2id 从 master password 派生主密钥。
    /// salt 应为每个 vault 唯一的随机值（32 字节），存储在 vault header 中。
    pub fn derive(password: &str, salt: &[u8]) -> VaultResult<Self> {
        // TODO: 将 Argon2id 参数（m_cost, t_cost, p_cost）暴露为配置项
        //       当前使用 OWASP 推荐的最低安全参数：
        //       m=65536 (64 MB), t=3, p=4
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

// ─── 对称加密 / 解密（AES-256-GCM） ──────────────────────────────────────────

/// 加密任意字节，返回 `nonce(12) || ciphertext+tag` 格式。
pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
    let rng = rand::SystemRandom::new();

    // 生成随机 nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| VaultError::Crypto("nonce generation failed".into()))?;

    // 构造 ring AEAD key
    let ring_key = aead::UnboundKey::new(&aead::AES_256_GCM, key.as_bytes())
        .map_err(|_| VaultError::Crypto("key construction failed".into()))?;
    let mut sealing_key = aead::SealingKey::new(
        ring_key,
        aead::Nonce::assume_unique_for_key(nonce_bytes),
    );

    let mut buf = plaintext.to_vec();
    // ring 会在 buf 尾部追加 16 字节 GCM tag
    sealing_key
        .seal_in_place_append_tag(aead::Aad::empty(), &mut buf)
        .map_err(|_| VaultError::Crypto("encryption failed".into()))?;

    // 输出格式：nonce(12) || ciphertext || tag(16)
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// 解密 `encrypt` 产生的数据。
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

/// 生成随机盐（Argon2id 使用）。
pub fn random_salt() -> VaultResult<[u8; SALT_LEN]> {
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| VaultError::Crypto("salt generation failed".into()))?;
    Ok(salt)
}
