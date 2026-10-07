-- Migration 0001: Initial Schema for EdgeJump Bastion

-- 1. Users & Authentication
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  password_algorithm TEXT NOT NULL DEFAULT 'pbkdf2-sha256',
  password_params TEXT NOT NULL, -- {"iterations":600000}
  password_salt TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active', 'disabled', 'locked')) DEFAULT 'active',
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  totp_secret_ciphertext TEXT,
  totp_secret_nonce TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER,
  created_by TEXT
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at INTEGER,
  created_at INTEGER NOT NULL
);

-- 2. System RBAC
CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  is_builtin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
  id TEXT PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);

-- 3. Assets, Groups & Accounts
CREATE TABLE IF NOT EXISTS asset_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  parent_id TEXT REFERENCES asset_groups(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  hostname TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  description TEXT,
  platform TEXT NOT NULL DEFAULT 'linux',
  environment TEXT NOT NULL DEFAULT 'production',
  enabled INTEGER NOT NULL DEFAULT 1,
  host_key_policy TEXT NOT NULL DEFAULT 'strict',
  last_seen_host_key TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  created_by TEXT
);

CREATE TABLE IF NOT EXISTS asset_group_members (
  group_id TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, asset_id)
);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('password', 'private_key')),
  credential_ciphertext TEXT NOT NULL,
  credential_nonce TEXT NOT NULL,
  encrypted_dek TEXT NOT NULL,
  dek_nonce TEXT NOT NULL,
  key_version TEXT NOT NULL DEFAULT 'v1',
  algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_accounts (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(asset_id, username)
);

CREATE TABLE IF NOT EXISTS ssh_host_keys (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  public_key TEXT NOT NULL,
  verified_at INTEGER,
  verified_by TEXT,
  status TEXT NOT NULL CHECK(status IN ('unverified', 'verified', 'changed')),
  created_at INTEGER NOT NULL,
  UNIQUE(asset_id, algorithm)
);

-- 4. Asset Authorization Rules (JumpServer Model)
CREATE TABLE IF NOT EXISTS authorization_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  all_accounts INTEGER NOT NULL DEFAULT 0, -- 1 = matches all accounts on asset (@ALL)
  enabled INTEGER NOT NULL DEFAULT 1,
  valid_from INTEGER,
  valid_until INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  created_by TEXT
);

CREATE TABLE IF NOT EXISTS authorization_rule_users (
  rule_id TEXT NOT NULL REFERENCES authorization_rules(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, user_id)
);

CREATE TABLE IF NOT EXISTS authorization_rule_groups (
  rule_id TEXT NOT NULL REFERENCES authorization_rules(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, group_id)
);

CREATE TABLE IF NOT EXISTS authorization_rule_assets (
  rule_id TEXT NOT NULL REFERENCES authorization_rules(id) ON DELETE CASCADE,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, asset_id)
);

CREATE TABLE IF NOT EXISTS authorization_rule_asset_groups (
  rule_id TEXT NOT NULL REFERENCES authorization_rules(id) ON DELETE CASCADE,
  asset_group_id TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, asset_group_id)
);

CREATE TABLE IF NOT EXISTS authorization_rule_accounts (
  rule_id TEXT NOT NULL REFERENCES authorization_rules(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES asset_accounts(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, account_id)
);

CREATE TABLE IF NOT EXISTS authorization_rule_actions (
  rule_id TEXT NOT NULL REFERENCES authorization_rules(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  PRIMARY KEY (rule_id, action)
);

-- 5. Sessions & Audit Records
CREATE TABLE IF NOT EXISTS ssh_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  username_snapshot TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  asset_name_snapshot TEXT NOT NULL,
  account_id TEXT NOT NULL,
  account_name_snapshot TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  user_agent TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  status TEXT NOT NULL CHECK(status IN ('creating', 'connecting', 'active', 'closing', 'closed', 'failed', 'terminated', 'timeout')),
  disconnect_reason TEXT,
  client_closed INTEGER DEFAULT 0,
  terminated_by TEXT,
  recording_status TEXT DEFAULT 'none',
  recording_path TEXT,
  recording_hash TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS session_commands (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES ssh_sessions(id) ON DELETE CASCADE,
  timestamp INTEGER NOT NULL,
  command TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'heuristic',
  redacted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  timestamp INTEGER NOT NULL,
  actor_user_id TEXT,
  actor_username_snapshot TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  resource_name_snapshot TEXT,
  source_ip TEXT NOT NULL,
  user_agent TEXT,
  result TEXT NOT NULL CHECK(result IN ('success', 'failure', 'denied')),
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS system_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  updated_by TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON auth_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_asset_accounts_asset_id ON asset_accounts(asset_id);
CREATE INDEX IF NOT EXISTS idx_ssh_host_keys_asset_id ON ssh_host_keys(asset_id);
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_user_id ON ssh_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_asset_id ON ssh_sessions(asset_id);
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_status ON ssh_sessions(status);
CREATE INDEX IF NOT EXISTS idx_session_commands_session_id ON session_commands(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
