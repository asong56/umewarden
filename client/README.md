# Umewarden Client

A minimal, single-binary desktop password manager built with **Rust + Tauri v2 + Vanilla JS**.

Connects to an **Umewarden** (or any Vaultwarden-compatible) server, and can also open local
**KDBX** (KeePass) files. This is the desktop companion to [`../server`](../server) — see
[`/docs/DESIGN_SYSTEM.md`](../docs/DESIGN_SYSTEM.md) for how its UI shares one visual language
with the server's built-in web vault, and [`/docs/API_ALIGNMENT.md`](../docs/API_ALIGNMENT.md)
for how the two talk to each other over the wire.

---

## Architecture

```
umewarden-client (single binary)
├── Tauri frontend        HTML/CSS/JS, compiled-in via Tauri asset bundling
│   ├── js/api.js         Typed wrappers around tauri.invoke()
│   ├── js/vault.js       Frontend state (pub/sub, no framework)
│   ├── js/ui.js          DOM rendering
│   └── js/app.js         Event wiring + init
└── Rust backend (src-tauri/src/)
    ├── main.rs            Entry: Tauri setup, tray icon
    ├── model.rs           Canonical VaultItem (backend-agnostic)
    ├── error.rs           Unified VaultError (Serialize for IPC)
    ├── daemon/            Tokio async background task
    │   ├── mod.rs         Event loop, DaemonMsg dispatch
    │   ├── state.rs       In-memory vault state (zeroize on lock)
    │   └── timer.rs       Auto-lock countdown
    ├── crypto/            Ring-based crypto (no OpenSSL)
    │   ├── mod.rs         AES-256-GCM encrypt/decrypt, Argon2id KDF
    │   ├── keys.rs        Bitwarden key hierarchy (EncString, HKDF)
    │   └── totp.rs        RFC 6238 TOTP generation
    ├── bitwarden/         Vaultwarden/Umewarden API adapter
    │   ├── auth.rs        Prelogin → login → token refresh
    │   ├── models.rs      API response structs + VaultItem conversion
    │   └── sync.rs        Full sync + WebSocket push listener
    ├── kdbx/              KeePass file adapter
    │   └── mod.rs         Open/create/save KDBX, Entry → VaultItem
    ├── autofill/          Cross-platform input injection
    │   └── mod.rs         rdev hotkey listener + enigo keyboard inject
    ├── storage/           Persistence layer
    │   └── mod.rs         OS keychain (salt/token) via keyring crate
    └── commands/          Tauri IPC command handlers
        ├── vault.rs       unlock/lock/list/get/create/update/delete
        ├── config.rs      get_config/set_vaultwarden_server/open_kdbx_file
        ├── generator.rs   generate_password/generate_passphrase
        ├── sync.rs        sync_now/get_sync_status
        └── autofill.rs    trigger_autofill
```

## Binary size targets

| Platform            | Target                        | Expected size |
|---------------------|-------------------------------|---------------|
| Windows x64         | x86_64-pc-windows-msvc        | ~8–12 MB      |
| Linux amd64         | x86_64-unknown-linux-gnu      | ~6–10 MB      |
| macOS arm64         | aarch64-apple-darwin          | ~6–10 MB      |

> Tauri v2 embeds the frontend assets into the binary. WebKitGTK on Linux is a system
> library (pre-installed on most distros); it is not bundled.

Size optimizations in effect:
- `opt-level = "z"` (size over speed)
- `lto = "fat"` (cross-crate dead code elimination)
- `codegen-units = 1`
- `panic = "abort"` (removes unwinding machinery)
- `strip = "symbols"`
- No OpenSSL — uses `ring` + `rustls`
- Tauri with minimal feature flags only

---

## Building

Run all commands from this directory (`client/`).

### Prerequisites

**All platforms:**
```sh
cargo install tauri-cli --version "^2" --locked
```

**Linux:**
```sh
sudo apt install libwebkit2gtk-4.1-dev libssl-dev libayatana-appindicator3-dev \
  librsvg2-dev libsecret-1-dev libxtst-dev libxi-dev libx11-dev
```

### Dev mode
```sh
cargo tauri dev
```

### Release builds
```sh
# Windows (run on Windows or cross-compile)
cargo tauri build --target x86_64-pc-windows-msvc

# Linux
cargo tauri build --target x86_64-unknown-linux-gnu

# macOS arm64
cargo tauri build --target aarch64-apple-darwin
```

CI (`.github/workflows/client-release.yml` at the repo root) builds all three targets and
publishes to GitHub Releases on `client-v*` tags.

---

## Implementation status

The Rust backend (crypto, KDF, Bitwarden-protocol auth/sync, KDBX, autofill, daemon, IPC
commands) is substantively implemented, not a skeleton — every module listed above has a real
implementation, verified against this repo's actual server routes (see
[`/docs/API_ALIGNMENT.md`](../docs/API_ALIGNMENT.md)). What's genuinely still missing is
frontend polish:

### Done
- [x] Project structure & Cargo workspace
- [x] Size-optimized build profile
- [x] Canonical `VaultItem` model (backend-agnostic)
- [x] Unified `VaultError` (serializable for IPC)
- [x] Daemon architecture (Tokio task + mpsc channel)
- [x] In-memory vault state with `zeroize` on lock
- [x] Auto-lock timer (reset on activity)
- [x] AES-256-GCM encrypt/decrypt (`ring`), Argon2id KDF
- [x] OS keychain integration (`keyring`)
- [x] `crypto/keys.rs`: EncString parse + decrypt, HKDF stretch
- [x] `crypto/totp.rs`: RFC 6238 TOTP implementation
- [x] `bitwarden/auth.rs`: prelogin, login, token refresh, 2FA
- [x] `bitwarden/sync.rs`: GET /api/sync, WebSocket push (SignalR)
- [x] `bitwarden/models.rs`: CipherResponse ↔ VaultItem conversion
- [x] `kdbx/mod.rs`: open/create/save via `keepass-ng`
- [x] `autofill/mod.rs`: rdev global hotkey, enigo inject
- [x] `daemon/mod.rs`: unlock flow wired to crypto + backends
- [x] All Tauri IPC command signatures + implementations
- [x] Frontend: unlock screen, main layout (sidebar/list/detail), settings
- [x] Frontend: vanilla pub/sub state management
- [x] Frontend: item list + detail pane rendering, TOTP countdown
- [x] Frontend/server: shared design tokens and component conventions (see docs/DESIGN_SYSTEM.md)
- [x] GitHub Actions CI (3 platforms)

### TODO (marked in source)
- [ ] Frontend: new/edit item form (currently a toast placeholder)
- [ ] Frontend: password generator modal (backend commands already work)
- [ ] Frontend: folder-filtered item list (folders render, but selecting one doesn't filter yet)
- [ ] Frontend: keyboard navigation (↑↓, Enter, Ctrl+K)
- [ ] Frontend: key-file support for KDBX (path-only today)
- [ ] `commands/config.rs`: full server-connectivity check before saving
- [ ] SignalR push: confirm JSON vs MessagePack framing against a real deployment (see comment in `bitwarden/sync.rs`)
- [ ] `plugin:dialog` invoke parameter shape: confirm against the pinned `tauri-plugin-dialog` version (see comment in `js/api.js`)

---

## Security notes

- Master key is **never stored**; derived fresh from password on each unlock via Argon2id.
- All sensitive strings use `zeroize::Zeroize` — memory is cleared on `Drop`.
- Vault state is cleared (zeroized) on lock, timeout, or process exit.
- On Linux Wayland, global hotkey listening is limited by the compositor.
  Autofill falls back to manual copy-paste in that environment.
- CSP is set to `default-src 'self'` — no external resource loading from the webview.
