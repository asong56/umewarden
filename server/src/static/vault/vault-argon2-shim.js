// Thin glue between the vendored hash-wasm Argon2 build (vault-argon2.vendor.js,
// MIT licensed, see file header) and vault-crypto.js's expected entry point.
// The WASM binary is embedded inline in the vendored file - no network fetch,
// no separate .wasm asset, works fully offline/self-hosted.
(function (global) {
  'use strict';
  if (global.hashwasm && typeof global.hashwasm.argon2id === 'function') {
    global.umewardenArgon2id = global.hashwasm.argon2id;
  }
})(typeof window !== 'undefined' ? window : globalThis);
