/*!
 * umewarden vault-api.js
 *
 * Thin fetch() wrapper around the handful of vaultwarden REST/OAuth2
 * endpoints this minimal UI needs: prelogin, connect/token (password grant,
 * with 2FA retry), sync, and cipher create/update/delete. Nothing here
 * touches organizations, sends, attachments, or SSO - nowhere for this
 * lightweight UI to hook in, so the server-side features remain fully
 * available to the official apps.
 */
(function (global) {
  'use strict';

  class ApiError extends Error {
    constructor(message, body, status) {
      super(message);
      this.name = 'ApiError';
      this.body = body;
      this.status = status;
    }
  }

  function extractErrorMessage(body, fallback) {
    if (!body || typeof body !== 'object') return fallback;
    return body.error_description || body.ErrorModel?.Message || body.message || body.Message || fallback;
  }

  function getDeviceIdentifier() {
    const key = 'umewarden.deviceIdentifier';
    let id = localStorage.getItem(key);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(key, id);
    }
    return id;
  }

  async function jsonFetch(path, options) {
    const res = await fetch(path, options);
    let body = null;
    try {
      body = await res.json();
    } catch (e) {
      // No/invalid JSON body - fine for e.g. empty 204 responses.
    }
    if (!res.ok) {
      throw new ApiError(extractErrorMessage(body, `Request to ${path} failed (${res.status})`), body, res.status);
    }
    return body;
  }

  async function prelogin(email) {
    const body = await jsonFetch('/api/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    return {
      kdfType: body.kdf ?? 0,
      kdfIterations: body.kdfIterations ?? 600000,
      kdfMemory: body.kdfMemory ?? null,
      kdfParallelism: body.kdfParallelism ?? null,
    };
  }

  /**
   * Performs the OAuth2 "password" grant. Returns:
   *   - { ok: true, tokens: {...} } on success
   *   - { ok: false, twoFactorProviders: [...] } if a 2FA step is required
   * Throws ApiError for any other failure (wrong password, disabled user, etc.)
   */
  async function login({ email, masterPasswordHashB64, twoFactorProvider, twoFactorToken }) {
    const form = new URLSearchParams();
    // Field names use the camelCase convention (deviceType, twoFactorProvider, ...)
    // rather than snake_case - this matches what the official Bitwarden clients send,
    // and what client/src-tauri/src/bitwarden/auth.rs uses. The server accepts both
    // (Rocket's `uncased` form-field matching, see server/src/api/identity.rs), but
    // one convention across both apps is easier to read and diff against.
    form.set('grant_type', 'password');
    form.set('username', email);
    form.set('password', masterPasswordHashB64);
    form.set('scope', 'api offline_access');
    form.set('client_id', 'web');
    form.set('deviceIdentifier', getDeviceIdentifier());
    form.set('deviceName', 'umewarden-web');
    form.set('deviceType', '9'); // 9 = "Unknown Browser" in Bitwarden's DeviceType enum
    if (twoFactorProvider != null) {
      form.set('twoFactorProvider', String(twoFactorProvider));
      form.set('twoFactorToken', twoFactorToken || '');
      form.set('twoFactorRemember', '0'); // server expects an int (0/1), not a JS-style bool
    }

    let body;
    try {
      body = await jsonFetch('/identity/connect/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      });
    } catch (e) {
      if (e instanceof ApiError && e.body && e.body.error === 'invalid_grant' && Array.isArray(e.body.TwoFactorProviders)) {
        return { ok: false, twoFactorProviders: e.body.TwoFactorProviders.map(Number) };
      }
      throw e;
    }

    return {
      ok: true,
      tokens: {
        accessToken: body.access_token,
        refreshToken: body.refresh_token,
        expiresIn: body.expires_in,
      },
      account: {
        encryptedUserKey: body.Key,
        kdfType: body.Kdf,
        kdfIterations: body.KdfIterations,
        kdfMemory: body.KdfMemory,
        kdfParallelism: body.KdfParallelism,
      },
    };
  }

  function authHeaders(accessToken) {
    return { Authorization: `Bearer ${accessToken}` };
  }

  async function sync(accessToken) {
    return await jsonFetch('/api/sync?excludeDomains=true', {
      headers: authHeaders(accessToken),
    });
  }

  async function createCipher(accessToken, cipherData) {
    return await jsonFetch('/api/ciphers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders(accessToken) },
      body: JSON.stringify(cipherData),
    });
  }

  async function updateCipher(accessToken, cipherId, cipherData) {
    return await jsonFetch(`/api/ciphers/${encodeURIComponent(cipherId)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...authHeaders(accessToken) },
      body: JSON.stringify(cipherData),
    });
  }

  async function softDeleteCipher(accessToken, cipherId) {
    return await jsonFetch(`/api/ciphers/${encodeURIComponent(cipherId)}/delete`, {
      method: 'PUT',
      headers: authHeaders(accessToken),
    });
  }

  global.umewardenApi = {
    ApiError,
    prelogin,
    login,
    sync,
    createCipher,
    updateCipher,
    softDeleteCipher,
  };
})(typeof window !== 'undefined' ? window : globalThis);
