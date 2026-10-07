// Shared API Types for EdgeJump Bastion

export type SystemRole = 'role_super_admin' | 'role_asset_admin' | 'role_security_auditor' | 'role_user';

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
  user: UserSummary;
  permissions: string[];
}
