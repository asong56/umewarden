# umewarden

A trimmed-down [vaultwarden](https://github.com/dani-garcia/vaultwarden) fork
meant to build and run as a single, self-contained binary: no MySQL/PostgreSQL,
no S3, no Docker/CI/test tooling in the source tree, and no separately-downloaded
`web-vault/` folder to keep in sync — a minimal web vault UI (styled with the
[nepenthe/acdn](https://github.com/) design system) is compiled directly into
the executable.

This fork is derived from vaultwarden and remains **AGPL-3.0-only** licensed
(see `../LICENSE`) — the original copyright notice is preserved.

## ⚠️ Please read before relying on this

This fork was produced in a sandboxed environment that had **no working Rust
toolchain** (only `rustc` 1.75 via `apt`, while this project needs 1.97.1 for
edition 2024 — see `rust-toolchain.toml` — and `rustup`/`static.rust-lang.org`
were network-blocked). That means **the Rust changes below could not be
compiled or run** as part of producing this fork. They were made carefully,
by:

- Reading the actual vaultwarden source for every endpoint/contract the web UI
  depends on (login, prelogin, sync, cipher CRUD) rather than guessing,
- Confirming each removal (MySQL/PostgreSQL/S3) was cleanly `#[cfg(...)]`-gated
  in only a handful of files before touching anything,
- Grepping the whole tree afterwards for dangling references.

The JavaScript web UI and admin panel, by contrast, **were** thoroughly
tested: vault crypto (PBKDF2, Argon2id, HKDF-Expand, AES-256-CBC+HMAC-SHA256)
was verified against independent Node.js reference implementations; the full
vault login → decrypt → edit → create → delete flow was run end-to-end
against a hand-built mock server replicating vaultwarden's actual REST/OAuth2
contract byte-for-byte; the admin panel's users/settings pages (sorting,
searching, dialogs, the group-enable/disable toggle, risk-setting
highlighting, password show/hide) were driven interactively via a jsdom
harness against realistic rendered HTML. The database migration consolidation
was verified by actually executing the resulting SQL against a real SQLite
engine and diff-checking every table/column against `schema.rs`.

**Before relying on this fork:** run `cargo build --release` yourself, back up
your existing `data/` folder first if migrating an existing install, and test
with a throwaway account before your real vault. Please report any compile
errors — given the scope of the trim, there may be a small one somewhere.

## What was removed, and why

| Removed | Why |
|---|---|
| `.github/`, `docker/`, `playwright/`, `tools/`, CI/lint configs (`.hadolint.yaml`, `.typos.toml`, `.pre-commit-config.yaml`), `Dockerfile`, `SECURITY.md`, `rustfmt.toml`, `.editorconfig` | Build/CI/container/test/editor tooling, irrelevant to compiling a single binary |
| MySQL & PostgreSQL support | A "single binary" deployment shouldn't need a separate database server; only 3 files (`src/db/mod.rs`, `src/api/admin.rs`, `build.rs`) referenced them, all `#[cfg(...)]`-gated |
| 55 of 56 historical DB migrations | Consolidated into one, fresh-installs-only (see "Migrations" below) |
| Bootstrap, jQuery, DataTables (admin panel) | Third-party UI frameworks with no place in an acdn-only project; admin assets went from 1.2MB to ~80KB |
| S3 remote storage (`src/storage.rs`, `src/http_client.rs`'s AWS connector) | Same reasoning — local filesystem storage only |
| The `web-vault/` folder dependency, and the startup check that used to **refuse to start** (`exit(1)`) if that folder was missing | This is very likely the source of the errors you were seeing. The web vault now ships inside the binary — there is nothing left to go missing |

**Kept, deliberately:** 2FA (TOTP/WebAuthn/Duo/email/Yubikey), email, and the
full organizations/send/attachments/emergency-access **server-side** code —
these are deeply integrated into the cipher/auth system and risky to rip out
by hand without a compiler. The new minimal UI just doesn't expose them (see
below) — your existing data and any official Bitwarden client remain fully
compatible.

**Removed:** OIDC/SSO login. It touched core login across 8 files
(`src/sso*.rs`, `src/auth.rs`, `src/api/identity.rs`, ...) and was fully
stripped — the `SSO_*` config options, `sso_auth`/`sso_users` tables, and the
`AuthMethod::Sso` code path are all gone.

## The built-in web UI

Deliberately minimal — "just enough to talk to the server," per the brief —
and built from scratch in vanilla JS against the acdn/nepenthe design tokens
(`src/static/vault/`):

- **Supports:** email + master-password login (PBKDF2 or Argon2id KDF,
  detected automatically), TOTP-based two-step verification, viewing/creating/
  editing/deleting **Login** and **Secure note** items, search, copy-to-clipboard.
- **Read-only:** Card/Identity/SSH key/Bank account items show in the list but
  open in a "not editable here — use an official app" notice, so nothing is
  ever corrupted by a UI that doesn't understand their shape.
- **Not implemented:** organizations/shared vaults (these use org keys wrapped
  via your RSA keypair — genuinely out of scope for a minimal client, and
  org-owned items are simply hidden from the list, never decrypted with the
  wrong key), sends, attachments, folders, trash management, WebAuthn/Duo/
  email 2FA, and self-service registration (create your first account via the
  admin panel invite flow or an official client once, then use umewarden
  day-to-day).
- **Session is in-memory only** — closing or reloading the tab requires
  unlocking again. This is a deliberate, conservative default for a password
  manager UI; nothing sensitive touches `localStorage`.
- Every edit **preserves fields the UI doesn't understand** (TOTP secrets,
  custom fields, password history, folder/favorite assignment) by round-
  tripping them unchanged rather than dropping them.

The Argon2id KDF is computed via a vendored, MIT-licensed build of
[hash-wasm](https://github.com/Daninet/hash-wasm) (`vault-argon2.vendor.js`) —
the WASM binary is embedded inline in that file, so there's no separate
`.wasm` fetch and it works fully offline/self-hosted.

## The admin panel

The server-management panel at `/admin` (`src/static/templates/admin/`,
`src/static/admin/`) has also been rebuilt on acdn/nepenthe — **Bootstrap,
jQuery, and DataTables are gone entirely** (this cut the admin assets from
1.2MB down to about 80KB). Table sorting/searching is a small vanilla-JS
replacement for DataTables; modals use the native `<dialog>` element instead
of Bootstrap's; collapsible settings groups use native `<details>`/`<summary>`
(acdn's `.accordion` component) instead of Bootstrap's JS-driven collapse.
`jdenticon` (the avatar-icon generator) was kept — it's a small, standalone
library unrelated to the UI framework, not part of the Bootstrap/jQuery stack.

One capability was consciously dropped rather than reimplemented: Bootstrap's
manual light/dark/auto theme switcher. acdn only supports automatic dark mode
via `prefers-color-scheme`, so the admin panel (and the vault UI) now follow
your OS/browser setting only, with no in-app override — matching what the
design system actually provides rather than inventing something outside it.

All admin functionality (invite/disable/delete users, change org roles,
diagnostics checks, config editing, SMTP test, DB backup) was preserved;
verified interactively (sorting, searching, dialogs, form data collection,
the settings page's group-enable/disable and risk-highlighting logic) via a
jsdom harness driving the actual shipped JS against realistic rendered HTML.

## Migrations

The 56 historical schema migrations (2018–2026) were consolidated into a
single migration, since umewarden targets fresh installs only — **upgrading
an existing vaultwarden database is no longer supported**. This isn't a
guess: the consolidated SQL was executed against a real SQLite engine and
checked table-by-table and column-by-column against what `src/db/schema.rs`
(what the Rust code actually queries) expects — same set of columns in every
table, no missing/extra/renamed columns anywhere (a few tables have columns
in a different physical order than `schema.rs` lists them, a pre-existing
artifact of historical `ALTER TABLE ADD COLUMN`s; harmless since Diesel's
`Selectable` derive matches columns by name, not position).


## Building

```sh
cargo build --release
# binary: target/release/vaultwarden (the package name itself wasn't
# renamed — see below — rename it yourself if you'd like)
```

SQLite is statically linked in by default (`default = ["sqlite"]`) — no other
setup is needed. Configuration is unchanged from upstream vaultwarden; see
`.env.template` for every available option.

> The Cargo package itself is still named `vaultwarden` internally (and the
> built binary will be named that) — renaming it safely requires regenerating
> `Cargo.lock` with a working `cargo`, which wasn't available while building
> this fork. Feel free to rename `[package] name` in `Cargo.toml` and run
> `cargo build` once to update the lock file yourself.

## License

AGPL-3.0-only, inherited from vaultwarden. See `../LICENSE` at the repo root.
