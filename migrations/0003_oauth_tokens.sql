-- OAuth provider tokens (Wave B Plan 1). Tokens are AES-GCM ciphertexts
-- (12-byte IV prefix); the key lives in the OAUTH_ENCRYPTION_KEY secret.
CREATE TABLE oauth_tokens (
  provider        TEXT PRIMARY KEY,
  access_token    BLOB NOT NULL,
  refresh_token   BLOB,
  expires_at      INTEGER,
  account_label   TEXT,
  meta            TEXT,
  auth_kind       TEXT NOT NULL DEFAULT 'oauth',
  connected_at    INTEGER NOT NULL,
  last_refresh_at INTEGER,
  last_error      TEXT
);

-- One in-flight login flow at a time per provider (PKCE verifier/state or
-- device code), expires on its own clock.
CREATE TABLE oauth_pending (
  provider      TEXT PRIMARY KEY,
  mode          TEXT NOT NULL,
  state         TEXT,
  code_verifier TEXT,
  device_code   TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL
);
