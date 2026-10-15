// EdgeJump Frontend API Client
import type { AssetSummary, AssetAccountSummary, AssetGroupSummary, CredentialSummary, AuthorizationRuleSummary,
  AdminUserSummary, UserGroupSummary, RoleSummary, HostKeySummary, AuthorizedAsset, AuthorizedAssetAccount,
  HistoricalSessionSummary, OnlineSessionSummary, AuditEventSummary, MeResponse, SessionTicketResponse } from '../../../src/shared/types';
import type { RecordingManifest, TerminalEvent } from '../../../src/shared/types';

let csrfPromise: Promise<string> | null = null;
async function getCsrfToken(): Promise<string> {
  csrfPromise ??= fetch('/api/auth/csrf', { credentials: 'same-origin' }).then(async (response) => {
    if (!response.ok) throw new Error('无法获取安全校验令牌，请刷新页面');
    return (await response.json()).csrfToken as string;
  }).catch((error) => { csrfPromise = null; throw error; });
  return csrfPromise;
}

export class ApiError extends Error {
  public status: number;
  public details?: unknown;
  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (!['GET', 'HEAD', 'OPTIONS'].includes((options.method ?? 'GET').toUpperCase())) {
    headers.set('X-CSRF-Token', await getCsrfToken());
  }
  if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(path, {
    ...options,
    headers,
    credentials: 'same-origin', // Send session cookie
  });

  if (response.status === 204) {
    return {} as T;
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new ApiError(data.error || response.statusText || 'Request failed', response.status, data.details);
  }

  return data as T;
}

export const api = {
  // Auth
  getBootstrapStatus: () => request<{ bootstrapNeeded: boolean; deployType?: string }>('/api/auth/bootstrap/status'),
  bootstrap: (data: any) => request('/api/auth/bootstrap', { method: 'POST', body: JSON.stringify(data) }),
  login: (data: unknown) => request<{ mfaRequired: boolean; challengeToken?: string; mfaSetupRequired?: boolean }>('/api/auth/login', { method: 'POST', body: JSON.stringify(data) }),
  completeMfa: (challengeToken: string, totpCode?: string, recoveryCode?: string) => request<{ mfaRequired: boolean }>('/api/auth/mfa', { method: 'POST', body: JSON.stringify({ challengeToken, totpCode, recoveryCode }) }),
  logout: () => request('/api/auth/logout', { method: 'POST' }),
  getMe: () => request<MeResponse>('/api/me'),
  setupMfa: () => request<{ secret: string; uri: string; recoveryCodes: string[] }>('/api/auth/mfa/setup', { method: 'POST' }),
  confirmMfa: (code: string) => request('/api/auth/mfa/confirm', { method: 'POST', body: JSON.stringify({ code }) }),
  disableMfa: (password: string, code: string) => request('/api/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ password, code }) }),

  // Assets (User Visible)
  getVisibleAssets: () => request<AuthorizedAsset[]>('/api/assets'),
  getAssetAccounts: (assetId: string) => request<AuthorizedAssetAccount[]>(`/api/assets/${assetId}/accounts`),

  // Sessions
  createSession: (assetId: string, accountId: string) =>
    request<{ sessionId: string; ticket: string; wsUrl: string; expiresAt: number }>('/api/sessions', {
      method: 'POST',
      body: JSON.stringify({ assetId, accountId }),
    }),
  disconnectSession: (sessionId: string) =>
    request(`/api/sessions/${sessionId}/disconnect`, { method: 'POST' }),
  listMySessions: () => request<HistoricalSessionSummary[]>('/api/sessions'),
  getMySession: (id: string) => request<HistoricalSessionSummary>(`/api/sessions/${id}`),
  resumeSession: (sessionId: string) => request<SessionTicketResponse>(`/api/sessions/${sessionId}/resume-ticket`, { method: 'POST' }),

  // Admin Assets
  listAdminAssets: () => request<AssetSummary[]>('/api/admin/assets'),
  createAsset: (data: any) => request('/api/admin/assets', { method: 'POST', body: JSON.stringify(data) }),
  updateAsset: (id: string, data: any) => request(`/api/admin/assets/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAsset: (id: string) => request(`/api/admin/assets/${id}`, { method: 'DELETE' }),

  listAssetAccounts: (assetId: string) => request<AssetAccountSummary[]>(`/api/admin/assets/${assetId}/accounts`),
  createAssetAccount: (assetId: string, data: any) => request(`/api/admin/assets/${assetId}/accounts`, { method: 'POST', body: JSON.stringify(data) }),
  updateAssetAccount: (assetId: string, id: string, data: unknown) => request(`/api/admin/assets/${assetId}/accounts/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAssetAccount: (assetId: string, id: string) => request(`/api/admin/assets/${assetId}/accounts/${id}`, { method: 'DELETE' }),

  listAssetGroups: () => request<AssetGroupSummary[]>('/api/admin/asset-groups'),
  createAssetGroup: (data: any) => request('/api/admin/asset-groups', { method: 'POST', body: JSON.stringify(data) }),
  updateAssetGroup: (id: string, data: unknown) => request(`/api/admin/asset-groups/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAssetGroup: (id: string) => request(`/api/admin/asset-groups/${id}`, { method: 'DELETE' }),

  // Admin Credentials
  listCredentials: () => request<CredentialSummary[]>('/api/admin/credentials'),
  createCredential: (data: any) => request('/api/admin/credentials', { method: 'POST', body: JSON.stringify(data) }),
  replaceCredential: (id: string, secret: string) => request(`/api/admin/credentials/${id}`, { method: 'PUT', body: JSON.stringify({ secret }) }),
  deleteCredential: (id: string) => request(`/api/admin/credentials/${id}`, { method: 'DELETE' }),
  rewrapCredential: (id: string, version: string) => request(`/api/admin/credentials/${id}/rewrap`, { method: 'POST', body: JSON.stringify({ version }) }),

  // Admin Authorizations
  listAuthorizations: () => request<AuthorizationRuleSummary[]>('/api/admin/authorizations'),
  getAuthorizationOptions: () => request<{ users: { id: string; username: string; displayName: string }[]; groups: { id: string; name: string }[] }>('/api/admin/authorization-options'),
  createAuthorization: (data: any) => request('/api/admin/authorizations', { method: 'POST', body: JSON.stringify(data) }),
  updateAuthorization: (id: string, data: any) => request(`/api/admin/authorizations/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAuthorization: (id: string) => request(`/api/admin/authorizations/${id}`, { method: 'DELETE' }),

  // Admin Users & Groups
  listUsers: () => request<AdminUserSummary[]>('/api/admin/users'),
  createUser: (data: any) => request('/api/admin/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id: string, data: any) => request(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  disableUser: (id: string) => request(`/api/admin/users/${id}/disable`, { method: 'POST' }),
  enableUser: (id: string) => request(`/api/admin/users/${id}/enable`, { method: 'POST' }),
  resetUserPassword: (id: string, password: string) => request(`/api/admin/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) }),
  listUserGroups: () => request<UserGroupSummary[]>('/api/admin/groups'),
  createUserGroup: (data: any) => request('/api/admin/groups', { method: 'POST', body: JSON.stringify(data) }),
  updateUserGroup: (id: string, data: unknown) => request(`/api/admin/groups/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteUserGroup: (id: string) => request(`/api/admin/groups/${id}`, { method: 'DELETE' }),
  listRoles: () => request<RoleSummary[]>('/api/admin/roles'),
  setAuditorTermination: (canTerminate: boolean) => request('/api/admin/roles/role_security_auditor', { method: 'PATCH', body: JSON.stringify({ canTerminate }) }),

  // Host Keys
  getHostKey: (assetId: string) => request<HostKeySummary[]>(`/api/admin/assets/${assetId}/host-key`),
  resetHostKey: (assetId: string) => request(`/api/admin/assets/${assetId}/host-key/reset`, { method: 'POST' }),
  approveHostKey: (assetId: string, algorithm: string, fingerprint: string) => request(`/api/admin/assets/${assetId}/host-key/approve`, { method: 'POST', body: JSON.stringify({ algorithm, fingerprint }) }),

  // Settings
  getSettings: () => request<Record<string, string>>('/api/admin/settings'),
  updateSetting: (key: string, value: string) => request('/api/admin/settings', { method: 'PATCH', body: JSON.stringify({ key, value }) }),
  cleanupExpiredRecordings: () => request<{ cleanedCount: number; expiredSessionIds: string[]; retentionDays: number; storageOperations: number; budgetExhausted: boolean }>('/api/admin/recordings/cleanup', { method: 'POST' }),

  // Admin Sessions & Audit
  listOnlineSessions: () => request<OnlineSessionSummary[]>('/api/admin/sessions?type=online'),
  listHistoricalSessions: () => request<HistoricalSessionSummary[]>('/api/admin/sessions?type=historical'),
  terminateSession: (id: string) => request(`/api/admin/sessions/${id}/terminate`, { method: 'POST' }),
  listAuditEvents: (limit = 50, resourceId?: string) => request<AuditEventSummary[]>(`/api/admin/audit?limit=${limit}${resourceId ? `&resourceId=${encodeURIComponent(resourceId)}` : ''}`),
  getSessionCommands: (id: string) => request<any[]>(`/api/admin/sessions/${id}/commands`),
  getSessionRecording: (id: string) => request<{ manifest: RecordingManifest; integrity: string }>(`/api/admin/sessions/${id}/recording`),
  getRecordingChunk: (id: string, index: number) => request<TerminalEvent[]>(`/api/admin/sessions/${id}/recording/${index}`),
};
