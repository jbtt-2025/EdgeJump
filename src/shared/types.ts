// Shared API Types for EdgeJump Bastion

export type SystemRole = 'role_super_admin' | 'role_asset_admin' | 'role_security_auditor' | 'role_user';
export type AuthorizationAction = 'connect' | 'sftp_read' | 'sftp_upload' | 'sftp_download' | 'port_forward';
export type { PermissionCode } from './permissions.ts';

export interface UserSummary {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  status: 'active' | 'disabled' | 'locked';
  mfaEnabled: boolean;
  roles: string[];
  createdAt: number;
  lastLoginAt: number | null;
}

export interface AssetSummary {
  id: string;
  name: string;
  hostname: string;
  port: number;
  description: string | null;
  platform: string;
  environment: string;
  enabled: boolean;
  groupIds: string[];
}

export interface AssetAccountSummary {
  id: string;
  assetId: string;
  username: string;
  credentialId: string;
  credentialType: 'password' | 'private_key';
  credentialName: string;
  enabled: boolean;
}

export interface AssetGroupSummary {
  id: string;
  name: string;
  description: string | null;
  parentId: string | null;
  assetCount?: number;
}

export interface CredentialSummary {
  id: string;
  name: string;
  type: 'password' | 'private_key';
  keyVersion: string;
  createdAt: number;
  updatedAt: number;
}

export interface AuthorizationRuleSummary {
  id: string;
  name: string;
  description: string | null;
  allAccounts: boolean;
  enabled: boolean;
  validFrom: number | null;
  validUntil: number | null;
  userIds: string[];
  groupIds: string[];
  assetIds: string[];
  assetGroupIds: string[];
  accountIds: string[];
  actions: string[];
}

export interface SessionTicketResponse {
  sessionId: string;
  ticket: string;
  wsUrl: string;
  expiresAt: number;
}

export interface OnlineSessionSummary {
  id: string;
  userId: string;
  username: string;
  assetId: string;
  assetName: string;
  accountId: string;
  accountName: string;
  sourceIp: string;
  startedAt: number;
  status: string;
  recordingStatus: string;
}

export interface HistoricalSessionSummary extends OnlineSessionSummary {
  endedAt: number | null;
  disconnectReason: string | null;
  recordingPath: string | null;
  recordingHash: string | null;
  exitCode?: number | null;
  exitSignal?: string | null;
}

export interface AuditEventSummary {
  id: string;
  timestamp: number;
  actorUserId: string | null;
  actorUsername: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  resourceName: string | null;
  sourceIp: string;
  result: 'success' | 'failure' | 'denied';
  metadataJson: string | null;
}

export interface LoginResponse {
  mfaRequired?: boolean;
  tempToken?: string;
  user?: UserSummary;
}

export interface MeResponse {
  user: Pick<UserSummary, 'id' | 'username' | 'displayName' | 'email' | 'roles'> & { mfaEnabled: boolean; mfaPending: boolean; mfaRequired: boolean };
  permissions: string[];
  deployType?: string;
}

export interface AuthorizedAssetAccount {
  id: string;
  username: string;
  credentialType: 'password' | 'private_key';
  credentialName: string;
}

export interface AuthorizedAsset {
  id: string;
  name: string;
  hostname: string;
  port: number;
  description: string | null;
  platform: string;
  environment: string;
  accounts: AuthorizedAssetAccount[];
  groupIds: string[];
  groups?: { id: string; name: string; parentId: string | null }[];
}

export type TerminalEventType = 'connect' | 'stdout' | 'resize' | 'disconnect';
export interface TerminalEvent {
  seq: number;
  t: number;
  type: TerminalEventType;
  data?: unknown;
  cols?: number;
  rows?: number;
  reason?: string;
}
export interface RecordingManifest {
  sessionId: string;
  chunkCount: number;
  firstChunkHash: string | null;
  finalHash: string | null;
  startedAt: number;
  endedAt: number;
  recordingPath: string;
  firstChunk?: string | null;
  lastChunk?: string | null;
  chunks?: { index: number; path: string; hash: string; rollingHash: string }[];
}

export interface AdminUserSummary extends UserSummary { groups: string[]; updatedAt: number }
export interface UserGroupSummary { id: string; name: string; description: string | null; memberCount: number; memberIds: string[] }
export interface RoleSummary { id: string; name: string; description: string | null; permissions: string[] }
export interface HostKeySummary {
  id: string; algorithm: string; fingerprint: string; status: 'verified' | 'unverified' | 'changed';
  verified_at: number | null; created_at: number; candidate_fingerprint: string | null;
}
