# Umewarden

A self-hosted, Bitwarden-compatible password vault, plus a lightweight native desktop client.

This is a monorepo with two independently-buildable projects that are meant to be used
together:

| Path        | What it is                                                                 |
|-------------|------------------------------------------------------------------------------|
| [`server/`](server) | The Umewarden server: a trimmed-down [Vaultwarden](https://github.com/dani-garcia/vaultwarden) fork that builds as a single self-contained binary, with a minimal built-in web vault. |
| [`client/`](client) | Umewarden Client: a small Rust + Tauri v2 desktop app that talks to an Umewarden (or any Vaultwarden-compatible) server, and can also open local KDBX files. |

Each has its own README with build instructions: [`server/README.md`](server/README.md),
[`client/README.md`](client/README.md).

## Layout

```
umewarden/
├── server/     Rust web server + built-in web vault (server/src/static/vault/)
├── client/     Rust + Tauri desktop client
├── docs/       Cross-cutting docs: design system, API alignment
└── .github/
    └── workflows/
        └── client-release.yml   Builds & releases the desktop client on `client-v*` tags
```

`server/` has no CI workflow in this repo yet — see the caveats in `server/README.md` about
this fork not yet having been compiled in a working Rust toolchain; add one once that's
verified. `client/`'s release workflow lives at the repo root because GitHub Actions only
reads workflows from `.github/workflows/` at the repository root, regardless of which
subdirectory a project lives in.

## License

AGPL-3.0-only for the whole repository (inherited from Vaultwarden, which `server/` is
derived from) — see [`LICENSE`](LICENSE).
