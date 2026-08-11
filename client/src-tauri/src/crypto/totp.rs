/// TOTP 生成（RFC 6238），基于 ring 的 HMAC-SHA1。
///
/// Bitwarden 的 CipherLogin.totp 字段可能是两种格式：
///   1. 裸的 Base32 密钥，如 "JBSWY3DPEHPK3PXP"
///   2. 完整的 otpauth:// URI，如 "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30"
///
/// 本实现两种都支持，统一解析出 (secret_bytes, digits, period)。

use crate::error::{VaultError, VaultResult};
use ring::hmac;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct TotpParams {
    secret: Vec<u8>,
    digits: u32,
    period: u64,
}

/// 计算当前 TOTP 码。
/// 返回 (code, remaining_secs)：remaining_secs 是当前码剩余有效秒数，供前端做倒计时。
pub fn generate(input: &str) -> VaultResult<(String, u8)> {
    let params = parse_totp_input(input)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Internal("system clock before Unix epoch".into()))?
        .as_secs();

    let counter = now / params.period;
    let remaining = params.period - (now % params.period);

    let code = hotp(&params.secret, counter, params.digits)?;
    Ok((code, remaining as u8))
}

/// 解析裸 Base32 密钥或 otpauth:// URI
fn parse_totp_input(input: &str) -> VaultResult<TotpParams> {
    let input = input.trim();

    if let Some(rest) = input.strip_prefix("otpauth://totp/") {
        // 找到 '?' 之后的 query string
        let query = rest
            .split_once('?')
            .map(|(_, q)| q)
            .ok_or_else(|| VaultError::Internal("otpauth URI missing query string".into()))?;

        let mut secret_b32: Option<&str> = None;
        let mut digits: u32 = 6;
        let mut period: u64 = 30;

        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else { continue };
            match key {
                "secret" => secret_b32 = Some(value),
                "digits" => digits = value.parse().unwrap_or(6),
                "period" => period = value.parse().unwrap_or(30),
                _ => {}
            }
        }

        let secret_b32 = secret_b32
            .ok_or_else(|| VaultError::Internal("otpauth URI missing secret parameter".into()))?;
        let secret = base32_decode(secret_b32)?;

        Ok(TotpParams { secret, digits, period })
    } else {
        // 裸 Base32 密钥，默认 6 位数字 / 30 秒周期
        let secret = base32_decode(input)?;
        Ok(TotpParams { secret, digits: 6, period: 30 })
    }
}

/// RFC 4226 HOTP：HMAC-SHA1(secret, counter) → 动态截断 → N 位数字
fn hotp(secret: &[u8], counter: u64, digits: u32) -> VaultResult<String> {
    if secret.is_empty() {
        return Err(VaultError::Internal("TOTP secret is empty".into()));
    }

    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let msg = counter.to_be_bytes();
    let tag = hmac::sign(&key, &msg);
    let hash = tag.as_ref();

    // 动态截断（RFC 4226 §5.4）
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin_code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32 & 0xff) << 16)
        | ((hash[offset + 2] as u32 & 0xff) << 8)
        | (hash[offset + 3] as u32 & 0xff);

    let modulus = 10u32.pow(digits);
    let code = bin_code % modulus;

    Ok(format!("{code:0width$}", width = digits as usize))
}

/// RFC 4648 Base32 解码（大写字母 A-Z + 数字 2-7，'=' padding 可选）
/// 手写实现，避免为一个小功能引入额外 crate。
fn base32_decode(input: &str) -> VaultResult<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let cleaned: Vec<u8> = input
        .trim()
        .to_uppercase()
        .bytes()
        .filter(|b| *b != b'=' && !b.is_ascii_whitespace())
        .collect();

    if cleaned.is_empty() {
        return Err(VaultError::Internal("TOTP secret is empty after cleaning".into()));
    }

    let mut bits_buf: u64 = 0;
    let mut bits_len: u32 = 0;
    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);

    for &c in &cleaned {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| VaultError::Internal(format!("invalid Base32 character: {}", c as char)))?
            as u64;

        bits_buf = (bits_buf << 5) | val;
        bits_len += 5;

        if bits_len >= 8 {
            bits_len -= 8;
            out.push(((bits_buf >> bits_len) & 0xff) as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip_known_vector() {
        // RFC 4648 test vector: "foobar" -> Base32 "MZXW6YTBOI======"
        let decoded = base32_decode("MZXW6YTBOI").unwrap();
        assert_eq!(decoded, b"foobar");
    }

    #[test]
    fn hotp_rfc4226_test_vector() {
        // RFC 4226 Appendix D, secret = "12345678901234567890" (ASCII), counter=0 -> "755224"
        let secret = b"12345678901234567890";
        let code = hotp(secret, 0, 6).unwrap();
        assert_eq!(code, "755224");
    }
}
