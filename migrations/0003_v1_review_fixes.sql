-- Preserve the AAD version of the payload when only the DEK is rewrapped.
ALTER TABLE credentials ADD COLUMN credential_key_version TEXT;
UPDATE credentials SET credential_key_version = key_version;

ALTER TABLE ssh_sessions ADD COLUMN exit_code INTEGER;
ALTER TABLE ssh_sessions ADD COLUMN exit_signal TEXT;

-- Keep the trusted key while a changed key awaits explicit approval.
ALTER TABLE ssh_host_keys ADD COLUMN candidate_fingerprint TEXT;
ALTER TABLE ssh_host_keys ADD COLUMN candidate_public_key TEXT;

-- Restricted login sessions can only enroll MFA until confirmation succeeds.
ALTER TABLE auth_sessions ADD COLUMN mfa_pending INTEGER NOT NULL DEFAULT 0;

CREATE TABLE auth_mfa_challenges (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX idx_mfa_challenge_expiry ON auth_mfa_challenges(expires_at);

INSERT INTO system_settings (key, value, updated_at)
VALUES ('auth_session_absolute_ttl', '28800', 0),
       ('auth_session_idle_ttl', '1800', 0),
       ('disconnect_on_browser_close', 'true', 0)
ON CONFLICT(key) DO NOTHING;
