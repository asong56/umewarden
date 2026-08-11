-- This project consolidates vaultwarden's full migration history (2018-2026)
-- into a single migration for fresh installs only (upgrade-path support for
-- existing databases was intentionally dropped). Reverting is not supported
-- at runtime (umewarden only ever calls `run_pending_migrations`, never
-- `revert`), so this file is a placeholder for `diesel_cli` compatibility.
SELECT 1;
