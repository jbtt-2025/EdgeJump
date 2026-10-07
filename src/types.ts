export interface Env {
  SSH_SESSIONS: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;
  DB: D1Database;
  RECORDINGS: R2Bucket;
  KV_CACHE: KVNamespace;
  ASSETS?: Fetcher;

  // Secrets
  CREDENTIAL_KEK_V1?: string;
  CREDENTIAL_KEK_V2?: string;
  AUTH_PEPPER?: string;
  BOOTSTRAP_TOKEN?: string;

  // Vars
  CONNECT_TIMEOUT_MS?: string;
  ENVIRONMENT?: string;
}

export type UserStatus = 'active' | 'disabled' | 'locked';
export type HostKeyStatus = 'unverified' | 'verified' | 'changed';
export type SessionStatus = 'creating' | 'connecting' | 'active' | 'closing' | 'closed' | 'failed' | 'terminated' | 'timeout';
export type CredentialType = 'password' | 'private_key';

export interface UserRow {
  id: string;
  username: string;
  display_name: string;
  email: string | null;
  password_hash: string;
  password_algorithm: string;
  password_params: string;
  password_salt: string;
  status: UserStatus;
  mfa_enabled: number;
  totp_secret_ciphertext: string | null;
  totp_secret_nonce: string | null;
  created_at: number;
  updated_at: number;
  last_login_at: number | null;
  created_by: string | null;
}

export interface AuthSessionRow {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: number;
  last_seen_at: number;
  expires_at: number;
  ip: string;
  user_agent: string | null;
  revoked_at: number | null;
}

export interface AssetRow {
  id: string;
  name: string;
  hostname: string;
  port: number;
  description: string | null;
  platform: string;
  environment: string;
  enabled: number;
  host_key_policy: string;
  last_seen_host_key: string | null;
  created_at: number;
  updated_at: number;
  created_by: string | null;
}

export interface AssetGroupRow {
  id: string;
  name: string;
  description: string | null;
  parent_id: string | null;
  created_at: number;
  updated_at: number;
}

export interface AssetAccountRow {
  id: string;
  asset_id: string;
  username: string;
  credential_id: string;
  enabled: number;
  created_at: number;
  updated_at: number;
}

export interface CredentialRow {
  id: string;
  name: string;
  type: CredentialType;
  credential_ciphertext: string;
  credential_nonce: string;
  encrypted_dek: string;
  dek_nonce: string;
  key_version: string;
  algorithm: string;
  created_at: number;
  updated_at: number;
}

export interface SSHHostKeyRow {
  id: string;
  asset_id: string;
  algorithm: string;
  fingerprint: string;
  public_key: string;
  verified_at: number | null;
  verified_by: string | null;
  status: HostKeyStatus;
  created_at: number;
}

export interface SSHSessionRow {
  id: string;
  user_id: string;
  username_snapshot: string;
  asset_id: string;
  asset_name_snapshot: string;
  account_id: string;
  account_name_snapshot: string;
  source_ip: string;
  user_agent: string | null;
  started_at: number;
  ended_at: number | null;
  status: SessionStatus;
  disconnect_reason: string | null;
  client_closed: number;
  terminated_by: string | null;
  recording_status: string;
  recording_path: string | null;
  recording_hash: string | null;
  created_at: number;
}

export interface GroupRow {
  id: string;
  name: string;
  description: string | null;
  created_at: number;
  updated_at: number;
}

export interface GroupMemberRow {
  group_id: string;
  user_id: string;
  joined_at: number;
}

export interface RoleRow {
  id: string;
  name: string;
  description: string | null;
  is_builtin: number;
  created_at: number;
}

export interface PermissionRow {
  id: string;
  code: string;
  description: string;
}

export interface MFARecoveryCodeRow {
  id: string;
  user_id: string;
  code_hash: string;
  used_at: number | null;
  created_at: number;
}

export interface AuthorizationRuleRow {
  id: string;
  name: string;
  description: string | null;
  all_accounts: number;
  enabled: number;
  valid_from: number | null;
  valid_until: number | null;
  created_at: number;
  updated_at: number;
  created_by: string | null;
}

export interface AuditEventRow {
  id: string;
  timestamp: number;
  actor_user_id: string | null;
  actor_username_snapshot: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  resource_name_snapshot: string | null;
  source_ip: string;
  user_agent: string | null;
  result: 'success' | 'failure' | 'denied';
  metadata_json: string | null;
}

export interface SystemSettingRow {
  key: string;
  value: string;
  updated_at: number;
  updated_by: string | null;
}

export interface AuthenticatedUser {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  roles: string[];
  permissions: Set<string>;
}

