/*!
 * umewarden vault-crypto.js
 *
 * Minimal, from-scratch implementation of the client-side crypto Bitwarden
 * (and therefore vaultwarden) accounts rely on:
 *
 *   - Master Key    = KDF(password, email)                    [PBKDF2-SHA256 or Argon2id]
 *   - Stretched Key = HKDF-Expand-SHA256(Master Key, "enc"|"mac", 32 bytes each)
 *   - Master Password Hash (sent to server) = PBKDF2-SHA256(key=MasterKey, salt=password, 1 iter)
 *   - User Key      = decrypt(account.Key, StretchedKey)       [AES-256-CBC + HMAC-SHA256]
 *   - Every cipher field ("2.iv|ct|mac" strings) is decrypted the same way with
 *     the User Key (or an individual per-cipher key, itself wrapped with the User Key).
 *
 * This only supports the "EncryptionType 2" (AesCbc256_HmacSha256_B64) format,
 * which is what every vaultwarden/Bitwarden account created in the last several
 * years uses. Organization/shared ciphers (which use an org key wrapped with the
 * user's RSA keypair) are intentionally out of scope for this minimal UI.
 */
(function (global) {
  'use strict';

  const te = new TextEncoder();
  const td = new TextDecoder();

  // ---- base64 / bytes helpers -----------------------------------------

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function concatBytes(...parts) {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }

  function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // ---- low level primitives (Web Crypto) --------------------------------

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  }

  async function hmacSha256(keyBytes, dataBytes) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
  }

  async function pbkdf2(passwordBytes, saltBytes, iterations, lengthBytes) {
    const key = await crypto.subtle.importKey('raw', passwordBytes, { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations },
      key,
      lengthBytes * 8
    );
    return new Uint8Array(bits);
  }

  // RFC 5869 HKDF-Expand only (the master key is used directly as the PRK,
  // there is no HKDF-Extract step - this matches Bitwarden's "stretchKey").
  async function hkdfExpand(prkBytes, infoBytes, lengthBytes) {
    const hashLen = 32; // SHA-256
    const n = Math.ceil(lengthBytes / hashLen);
    if (n > 255) throw new Error('HKDF-Expand: requested length too large');
    let t = new Uint8Array(0);
    let okm = new Uint8Array(0);
    for (let i = 1; i <= n; i++) {
      const input = concatBytes(t, infoBytes, new Uint8Array([i]));
      t = await hmacSha256(prkBytes, input);
      okm = concatBytes(okm, t);
    }
    return okm.slice(0, lengthBytes);
  }

  async function aesCbcEncrypt(keyBytes, ivBytes, plaintextBytes) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
    const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, key, plaintextBytes);
    return new Uint8Array(ct);
  }

  async function aesCbcDecrypt(keyBytes, ivBytes, ciphertextBytes) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBytes }, key, ciphertextBytes);
    return new Uint8Array(pt);
  }

  // ---- KDF: turn (email, password) into a 32-byte Master Key -----------

  const KDF_PBKDF2 = 0;
  const KDF_ARGON2ID = 1;

  /**
   * kdfInfo: { kdfType, kdfIterations, kdfMemory (MB, argon2 only), kdfParallelism (argon2 only) }
   */
  async function makeMasterKey(email, password, kdfInfo) {
    const emailBytes = te.encode(email.trim().toLowerCase());
    const passwordBytes = te.encode(password);

    if (kdfInfo.kdfType === KDF_ARGON2ID) {
      if (typeof global.umewardenArgon2id !== 'function') {
        throw new Error('This account uses Argon2id, but the Argon2 module failed to load.');
      }
      const salt = await sha256(emailBytes);
      const memoryKiB = Math.max(16, Math.round((kdfInfo.kdfMemory || 64) * 1024));
      const out = await global.umewardenArgon2id({
        password: passwordBytes,
        salt,
        iterations: kdfInfo.kdfIterations || 3,
        parallelism: kdfInfo.kdfParallelism || 4,
        memorySize: memoryKiB,
        hashLength: 32,
        outputType: 'binary',
      });
      return out instanceof Uint8Array ? out : new Uint8Array(out);
    }

    // Default / KDF_PBKDF2
    const iterations = kdfInfo.kdfIterations || 600000;
    return await pbkdf2(passwordBytes, emailBytes, iterations, 32);
  }

  async function stretchKey(masterKey) {
    const encKey = await hkdfExpand(masterKey, te.encode('enc'), 32);
    const macKey = await hkdfExpand(masterKey, te.encode('mac'), 32);
    return { encKey, macKey };
  }

  // The value sent to the server as the "password" field of the login request.
  async function hashMasterKeyForServer(masterKey, password) {
    const hash = await pbkdf2(masterKey, te.encode(password), 1, 32);
    return bytesToB64(hash);
  }

  // ---- EncString ("2.iv|ct|mac") encode / decode ------------------------

  async function encryptString(plaintext, encKey, macKey) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const ct = await aesCbcEncrypt(encKey, iv, te.encode(plaintext == null ? '' : plaintext));
    const mac = await hmacSha256(macKey, concatBytes(iv, ct));
    return `2.${bytesToB64(iv)}|${bytesToB64(ct)}|${bytesToB64(mac)}`;
  }

  // Symmetric key blobs (e.g. the account's "Key" field, or a per-cipher key)
  // are encoded the same way but decode to raw key bytes instead of UTF-8 text.
  async function decryptToBytes(encStr, encKey, macKey) {
    if (!encStr) return null;
    const dot = encStr.indexOf('.');
    if (dot === -1) throw new Error('Malformed encrypted value (no type prefix)');
    const type = encStr.slice(0, dot);
    if (type !== '2') throw new Error(`Unsupported encryption type "${type}" (only type 2 is supported)`);
    const parts = encStr.slice(dot + 1).split('|');
    if (parts.length !== 3) throw new Error('Malformed encrypted value (expected iv|ct|mac)');
    const iv = b64ToBytes(parts[0]);
    const ct = b64ToBytes(parts[1]);
    const mac = b64ToBytes(parts[2]);

    if (macKey) {
      const expectedMac = await hmacSha256(macKey, concatBytes(iv, ct));
      if (!constantTimeEqual(mac, expectedMac)) {
        throw new Error('MAC verification failed - wrong key or corrupted data');
      }
    }
    return await aesCbcDecrypt(encKey, iv, ct);
  }

  async function decryptString(encStr, encKey, macKey) {
    if (encStr == null || encStr === '') return '';
    const bytes = await decryptToBytes(encStr, encKey, macKey);
    return td.decode(bytes);
  }

  // The account's symmetric key ("Key"/"akey", 64 bytes = 32 enc + 32 mac)
  // is itself an EncString, decrypted with the *stretched master key*.
  async function decryptUserKey(encryptedUserKey, stretchedEncKey, stretchedMacKey) {
    const raw = await decryptToBytes(encryptedUserKey, stretchedEncKey, stretchedMacKey);
    if (raw.length !== 64) {
      throw new Error(`Unexpected user key length: ${raw.length} (expected 64)`);
    }
    return { encKey: raw.slice(0, 32), macKey: raw.slice(32, 64) };
  }

  // Individual ciphers can carry their own wrapped key ("cipher.key"),
  // itself an EncString wrapped with the account User Key.
  async function decryptCipherKey(encryptedCipherKey, userKey) {
    if (!encryptedCipherKey) return null;
    const raw = await decryptToBytes(encryptedCipherKey, userKey.encKey, userKey.macKey);
    if (raw.length !== 64) {
      throw new Error(`Unexpected cipher key length: ${raw.length} (expected 64)`);
    }
    return { encKey: raw.slice(0, 32), macKey: raw.slice(32, 64) };
  }

  global.umewardenCrypto = {
    KDF_PBKDF2,
    KDF_ARGON2ID,
    makeMasterKey,
    stretchKey,
    hashMasterKeyForServer,
    encryptString,
    decryptString,
    decryptUserKey,
    decryptCipherKey,
    // exposed for the self-test harness / advanced use
    _internal: { pbkdf2, hkdfExpand, hmacSha256, sha256, aesCbcEncrypt, aesCbcDecrypt, b64ToBytes, bytesToB64 },
  };
})(typeof window !== 'undefined' ? window : globalThis);
