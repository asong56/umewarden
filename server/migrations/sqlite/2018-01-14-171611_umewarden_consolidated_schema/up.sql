-- ===== from original migration: 2018-01-14-171611_create_tables =====
CREATE TABLE users (
  uuid                TEXT     NOT NULL PRIMARY KEY,
  created_at          DATETIME NOT NULL,
  updated_at          DATETIME NOT NULL,
  email               TEXT     NOT NULL UNIQUE,
  name                TEXT     NOT NULL,
  password_hash       BLOB     NOT NULL,
  salt                BLOB     NOT NULL,
  password_iterations INTEGER  NOT NULL,
  password_hint       TEXT,
  key                 TEXT     NOT NULL,
  private_key         TEXT,
  public_key          TEXT,
  totp_secret         TEXT,
  totp_recover        TEXT,
  security_stamp      TEXT     NOT NULL,
  equivalent_domains  TEXT     NOT NULL,
  excluded_globals    TEXT     NOT NULL
);

CREATE TABLE devices (
  uuid          TEXT     NOT NULL PRIMARY KEY,
  created_at    DATETIME NOT NULL,
  updated_at    DATETIME NOT NULL,
  user_uuid     TEXT     NOT NULL REFERENCES users (uuid),
  name          TEXT     NOT NULL,
  type          INTEGER  NOT NULL,
  push_token    TEXT,
  refresh_token TEXT     NOT NULL
);

CREATE TABLE ciphers (
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     NOT NULL REFERENCES users (uuid),
  folder_uuid       TEXT REFERENCES folders (uuid),
  type              INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  favorite          BOOLEAN  NOT NULL
);

CREATE TABLE attachments (
  id          TEXT    NOT NULL PRIMARY KEY,
  cipher_uuid TEXT    NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT    NOT NULL,
  file_size   INTEGER NOT NULL

);

CREATE TABLE folders (
  uuid       TEXT     NOT NULL PRIMARY KEY,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  user_uuid  TEXT     NOT NULL REFERENCES users (uuid),
  name       TEXT     NOT NULL
);
  
-- ===== from original migration: 2018-04-27-155151_create_users_ciphers =====
ALTER TABLE ciphers RENAME TO oldCiphers;

CREATE TABLE ciphers (
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     REFERENCES users (uuid), -- Make this optional
  -- Remove folder_uuid
  type              INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  favorite          BOOLEAN  NOT NULL
);

CREATE TABLE folders_ciphers (
  cipher_uuid TEXT NOT NULL REFERENCES ciphers (uuid),
  folder_uuid TEXT NOT NULL REFERENCES folders (uuid),

  PRIMARY KEY (cipher_uuid, folder_uuid)
);

INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, type, name, notes, fields, data, favorite)
SELECT uuid, created_at, updated_at, user_uuid, type, name, notes, fields, data, favorite FROM oldCiphers;

INSERT INTO folders_ciphers (cipher_uuid, folder_uuid)
SELECT uuid, folder_uuid FROM oldCiphers WHERE folder_uuid IS NOT NULL;


DROP TABLE oldCiphers;

-- ===== from original migration: 2018-05-25-232323_update_attachments_reference =====
ALTER TABLE attachments RENAME TO oldAttachments;

CREATE TABLE attachments (
  id          TEXT    NOT NULL PRIMARY KEY,
  cipher_uuid TEXT    NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT    NOT NULL,
  file_size   INTEGER NOT NULL

);

INSERT INTO attachments (id, cipher_uuid, file_name, file_size) 
SELECT id, cipher_uuid, file_name, file_size FROM oldAttachments;

DROP TABLE oldAttachments;
-- ===== from original migration: 2018-06-01-112529_update_devices_twofactor_remember =====
ALTER TABLE devices
    ADD COLUMN
    twofactor_remember TEXT;
-- ===== from original migration: 2018-07-11-181453_create_u2f_twofactor =====
CREATE TABLE twofactor (
  uuid      TEXT     NOT NULL PRIMARY KEY,
  user_uuid TEXT     NOT NULL REFERENCES users (uuid),
  type      INTEGER  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL,

  UNIQUE (user_uuid, type)
);


INSERT INTO twofactor (uuid, user_uuid, type, enabled, data) 
SELECT lower(hex(randomblob(16))) , uuid, 0, 1, u.totp_secret FROM users u where u.totp_secret IS NOT NULL;

UPDATE users SET totp_secret = NULL; -- Instead of recreating the table, just leave the columns empty
-- ===== from original migration: 2018-08-27-172114_update_ciphers =====
ALTER TABLE ciphers
    ADD COLUMN
    password_history TEXT;
-- ===== from original migration: 2018-09-10-111213_add_invites =====
CREATE TABLE invitations (
    email   TEXT NOT NULL PRIMARY KEY
);
-- ===== from original migration: 2018-09-19-144557_add_kdf_columns =====
ALTER TABLE users
    ADD COLUMN
    client_kdf_type INTEGER NOT NULL DEFAULT 0; -- PBKDF2

ALTER TABLE users
    ADD COLUMN
    client_kdf_iter INTEGER NOT NULL DEFAULT 100000;

-- ===== from original migration: 2018-11-27-152651_add_att_key_columns =====
ALTER TABLE attachments
    ADD COLUMN
    key TEXT;
-- ===== from original migration: 2019-05-26-216651_rename_key_and_type_columns =====
ALTER TABLE attachments RENAME COLUMN key TO akey;
ALTER TABLE ciphers RENAME COLUMN type TO atype;
ALTER TABLE devices RENAME COLUMN type TO atype;
ALTER TABLE twofactor RENAME COLUMN type TO atype;
ALTER TABLE users RENAME COLUMN key TO akey;
-- ===== from original migration: 2019-10-10-083032_add_column_to_twofactor =====
ALTER TABLE twofactor ADD COLUMN last_used INTEGER NOT NULL DEFAULT 0;

-- ===== from original migration: 2019-11-17-011009_add_email_verification =====
ALTER TABLE users ADD COLUMN verified_at DATETIME DEFAULT NULL;
ALTER TABLE users ADD COLUMN last_verifying_at DATETIME DEFAULT NULL;
ALTER TABLE users ADD COLUMN login_verify_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN email_new TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN email_new_token TEXT DEFAULT NULL;

-- ===== from original migration: 2020-04-09-235005_add_cipher_delete_date =====
ALTER TABLE ciphers
    ADD COLUMN
    deleted_at DATETIME;

-- ===== from original migration: 2020-08-02-025025_add_favorites_table =====
CREATE TABLE favorites (
  user_uuid   TEXT NOT NULL REFERENCES users(uuid),
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),

  PRIMARY KEY (user_uuid, cipher_uuid)
);

-- Transfer favorite status for user-owned ciphers.
INSERT INTO favorites(user_uuid, cipher_uuid)
SELECT user_uuid, uuid
FROM ciphers
WHERE favorite = 1
  AND user_uuid IS NOT NULL;

-- Drop the `favorite` column from the `ciphers` table, using the 12-step
-- procedure from <https://www.sqlite.org/lang_altertable.html#altertabrename>.
-- Note that some steps aren't applicable and are omitted.

-- 1. If foreign key constraints are enabled, disable them using PRAGMA foreign_keys=OFF.
--
-- Diesel runs each migration in its own transaction. `PRAGMA foreign_keys`
-- is a no-op within a transaction, so this step must be done outside of this
-- file, before starting the Diesel migrations.

-- 2. Start a transaction.
--
-- Diesel already runs each migration in its own transaction.

-- 4. Use CREATE TABLE to construct a new table "new_X" that is in the
--    desired revised format of table X. Make sure that the name "new_X" does
--    not collide with any existing table name, of course.

CREATE TABLE new_ciphers(
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     REFERENCES users(uuid),
  atype             INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  password_history  TEXT,
  deleted_at        DATETIME
);

-- 5. Transfer content from X into new_X using a statement like:
--    INSERT INTO new_X SELECT ... FROM X.

INSERT INTO new_ciphers(uuid, created_at, updated_at, user_uuid, atype,
                        name, notes, fields, data, password_history, deleted_at)
SELECT uuid, created_at, updated_at, user_uuid, atype,
       name, notes, fields, data, password_history, deleted_at
FROM ciphers;

-- 6. Drop the old table X: DROP TABLE X.

DROP TABLE ciphers;

-- 7. Change the name of new_X to X using: ALTER TABLE new_X RENAME TO X.

ALTER TABLE new_ciphers RENAME TO ciphers;

-- 11. Commit the transaction started in step 2.

-- 12. If foreign keys constraints were originally enabled, reenable them now.
--
-- `PRAGMA foreign_keys` is scoped to a database connection, and Diesel
-- migrations are run in a separate database connection that is closed once
-- the migrations finish.

-- ===== from original migration: 2020-11-30-224000_add_user_enabled =====
ALTER TABLE users ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 1;

-- ===== from original migration: 2020-12-09-173101_add_stamp_exception =====
ALTER TABLE users ADD COLUMN stamp_exception TEXT DEFAULT NULL;
-- ===== from original migration: 2021-04-30-233251_add_reprompt =====
ALTER TABLE ciphers
ADD COLUMN reprompt INTEGER;

-- ===== from original migration: 2021-10-24-164321_add_2fa_incomplete =====
CREATE TABLE twofactor_incomplete (
  user_uuid   TEXT     NOT NULL REFERENCES users(uuid),
  device_uuid TEXT     NOT NULL,
  device_name TEXT     NOT NULL,
  login_time  DATETIME NOT NULL,
  ip_address  TEXT     NOT NULL,

  PRIMARY KEY (user_uuid, device_uuid)
);

-- ===== from original migration: 2022-01-17-234911_add_api_key =====
ALTER TABLE users
ADD COLUMN api_key TEXT;

-- ===== from original migration: 2022-03-02-210038_update_devices_primary_key =====
-- Create new devices table with primary keys on both uuid and user_uuid
CREATE TABLE devices_new (
	uuid	TEXT NOT NULL,
	created_at	DATETIME NOT NULL,
	updated_at	DATETIME NOT NULL,
	user_uuid	TEXT NOT NULL,
	name	TEXT NOT NULL,
	atype	INTEGER NOT NULL,
	push_token	TEXT,
	refresh_token	TEXT NOT NULL,
	twofactor_remember	TEXT,
	PRIMARY KEY(uuid, user_uuid),
	FOREIGN KEY(user_uuid) REFERENCES users(uuid)
);

-- Transfer current data to new table
INSERT INTO devices_new SELECT * FROM devices;

-- Drop the old table
DROP TABLE devices;

-- Rename the new table to the original name
ALTER TABLE devices_new RENAME TO devices;

-- ===== from original migration: 2023-01-11-205851_add_avatar_color =====
ALTER TABLE users
ADD COLUMN avatar_color TEXT;

-- ===== from original migration: 2023-01-31-222222_add_argon2 =====
ALTER TABLE users
    ADD COLUMN
    client_kdf_memory INTEGER DEFAULT NULL;

ALTER TABLE users
    ADD COLUMN
    client_kdf_parallelism INTEGER DEFAULT NULL;

-- ===== from original migration: 2023-02-18-125735_push_uuid_table =====
ALTER TABLE devices ADD COLUMN push_uuid TEXT;
-- ===== from original migration: 2023-06-02-200424_create_organization_api_key =====
-- (only the users.external_id column is kept here - the organization_api_key
-- table itself was organization-only and has been removed)
ALTER TABLE users ADD COLUMN external_id TEXT;
-- ===== from original migration: 2023-06-17-200424_create_auth_requests_table =====
CREATE TABLE auth_requests (
	uuid            TEXT NOT NULL PRIMARY KEY,
	user_uuid	    TEXT NOT NULL,
	request_device_identifier         TEXT NOT NULL,
	device_type         INTEGER NOT NULL,
	request_ip         TEXT NOT NULL,
	response_device_id         TEXT,
	access_code         TEXT NOT NULL,
	public_key         TEXT NOT NULL,
	enc_key         TEXT NOT NULL,
	master_password_hash         TEXT NOT NULL,
	approved         BOOLEAN,
	creation_date         DATETIME NOT NULL,
	response_date         DATETIME,
	authentication_date         DATETIME,
	FOREIGN KEY(user_uuid) REFERENCES users(uuid)
);
-- ===== from original migration: 2023-09-01-170620_update_auth_request_table =====
-- Create new auth_requests table with master_password_hash as nullable column
CREATE TABLE auth_requests_new (
    uuid                        TEXT NOT NULL PRIMARY KEY,
    user_uuid                   TEXT NOT NULL,
    request_device_identifier   TEXT NOT NULL,
    device_type                 INTEGER NOT NULL,
    request_ip                  TEXT NOT NULL,
    response_device_id          TEXT,
    access_code                 TEXT NOT NULL,
    public_key                  TEXT NOT NULL,
    enc_key                     TEXT,
    master_password_hash        TEXT,
    approved                    BOOLEAN,
    creation_date               DATETIME NOT NULL,
    response_date               DATETIME,
    authentication_date         DATETIME,
    FOREIGN KEY (user_uuid) REFERENCES users (uuid)
);

-- Transfer current data to new table
INSERT INTO	auth_requests_new (uuid, user_uuid, request_device_identifier, device_type, request_ip,
	response_device_id, access_code, public_key, enc_key, master_password_hash, approved, creation_date,
	response_date, authentication_date)
SELECT uuid, user_uuid, request_device_identifier, device_type, request_ip,
	response_device_id, access_code, public_key, enc_key, master_password_hash, approved, creation_date,
	response_date, authentication_date
FROM auth_requests;

-- Drop the old table
DROP TABLE auth_requests;

-- Rename the new table to the original name
ALTER TABLE auth_requests_new RENAME TO auth_requests;

-- ===== from original migration: 2023-10-21-221242_add_cipher_key =====
ALTER TABLE ciphers
ADD COLUMN "key" TEXT;

-- ===== from original migration: 2024-01-12-210182_change_attachment_size =====
-- Integer size in SQLite is already i64, so we don't need to do anything

-- ===== from original migration: 2024-02-14-140000_change_time_stamp_data_type =====
-- Integer size in SQLite is already i64, so we don't need to do anything

-- ===== from original migration: 2024-06-05-131359_add_2fa_duo_store =====
CREATE TABLE twofactor_duo_ctx (
    state      TEXT    NOT NULL,
    user_email TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    exp        INTEGER NOT NULL,

    PRIMARY KEY (state)
);

-- ===== from original migration: 2024-09-04-091351_use_device_type_for_mails =====
ALTER TABLE twofactor_incomplete ADD COLUMN device_type INTEGER NOT NULL DEFAULT 14; -- 14 = Unknown Browser

-- ===== from original migration: 2026-03-09-005927_add_archives =====
DROP TABLE IF EXISTS archives;

CREATE TABLE archives (
    user_uuid   CHAR(36) NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers (uuid) ON DELETE CASCADE,
    archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_uuid, cipher_uuid)
);

