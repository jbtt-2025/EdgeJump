// EdgeJump Frontend API Client

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
  login: (data: any) => request<{ mfaRequired: boolean; user?: any; permissions?: string[]; deployType?: string }>('/api/auth/login', { method: 'POST', body: JSON.stringify(data) }),
  logout: () => request('/api/auth/logout', { method: 'POST' }),
  getMe: () => request<{ user: any; permissions: string[]; deployType?: string }>('/api/me'),

  // Assets (User Visible)
  getVisibleAssets: () => request<any[]>('/api/assets'),
  getAssetAccounts: (assetId: string) => request<any[]>(`/api/assets/${assetId}/accounts`),

  // Sessions
  createSession: (assetId: string, accountId: string) =>
    request<{ sessionId: string; ticket: string; wsUrl: string; expiresAt: number }>('/api/sessions', {
      method: 'POST',
      body: JSON.stringify({ assetId, accountId }),
    }),
  disconnectSession: (sessionId: string) =>
    request(`/api/sessions/${sessionId}/disconnect`, { method: 'POST' }),

  // Admin Assets
  listAdminAssets: () => request<any[]>('/api/admin/assets'),
  createAsset: (data: any) => request('/api/admin/assets', { method: 'POST', body: JSON.stringify(data) }),
  updateAsset: (id: string, data: any) => request(`/api/admin/assets/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAsset: (id: string) => request(`/api/admin/assets/${id}`, { method: 'DELETE' }),

  listAssetAccounts: (assetId: string) => request<any[]>(`/api/admin/assets/${assetId}/accounts`),
  createAssetAccount: (assetId: string, data: any) => request(`/api/admin/assets/${assetId}/accounts`, { method: 'POST', body: JSON.stringify(data) }),

  listAssetGroups: () => request<any[]>('/api/admin/asset-groups'),
  createAssetGroup: (data: any) => request('/api/admin/asset-groups', { method: 'POST', body: JSON.stringify(data) }),

  // Admin Credentials
  listCredentials: () => request<any[]>('/api/admin/credentials'),
  createCredential: (data: any) => request('/api/admin/credentials', { method: 'POST', body: JSON.stringify(data) }),
  replaceCredential: (id: string, secret: string) => request(`/api/admin/credentials/${id}`, { method: 'PUT', body: JSON.stringify({ secret }) }),
  deleteCredential: (id: string) => request(`/api/admin/credentials/${id}`, { method: 'DELETE' }),

  // Admin Authorizations
  listAuthorizations: () => request<any[]>('/api/admin/authorizations'),
  createAuthorization: (data: any) => request('/api/admin/authorizations', { method: 'POST', body: JSON.stringify(data) }),
  updateAuthorization: (id: string, data: any) => request(`/api/admin/authorizations/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAuthorization: (id: string) => request(`/api/admin/authorizations/${id}`, { method: 'DELETE' }),

  // Admin Users & Groups
  listUsers: () => request<any[]>('/api/admin/users'),
  createUser: (data: any) => request('/api/admin/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id: string, data: any) => request(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  disableUser: (id: string) => request(`/api/admin/users/${id}/disable`, { method: 'POST' }),
  enableUser: (id: string) => request(`/api/admin/users/${id}/enable`, { method: 'POST' }),
  resetUserPassword: (id: string, password: string) => request(`/api/admin/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) }),
  listUserGroups: () => request<any[]>('/api/admin/groups'),
  createUserGroup: (data: any) => request('/api/admin/groups', { method: 'POST', body: JSON.stringify(data) }),

  // Host Keys
  getHostKey: (assetId: string) => request<any>(`/api/admin/assets/${assetId}/host-key`),
  resetHostKey: (assetId: string) => request(`/api/admin/assets/${assetId}/host-key/reset`, { method: 'POST' }),

  // Settings
  getSettings: () => request<Record<string, string>>('/api/admin/settings'),
  updateSetting: (key: string, value: string) => request('/api/admin/settings', { method: 'PATCH', body: JSON.stringify({ key, value }) }),
  cleanupExpiredRecordings: () => request<{ cleanedCount: number; expiredSessionIds: string[]; retentionDays: number }>('/api/admin/recordings/cleanup', { method: 'POST' }),

  // Admin Sessions & Audit
  listOnlineSessions: () => request<any[]>('/api/admin/sessions?type=online'),
  listHistoricalSessions: () => request<any[]>('/api/admin/sessions?type=historical'),
  terminateSession: (id: string) => request(`/api/admin/sessions/${id}/terminate`, { method: 'POST' }),
  listAuditEvents: (limit = 50) => request<any[]>(`/api/admin/audit?limit=${limit}`),
  getSessionCommands: (id: string) => request<any[]>(`/api/admin/sessions/${id}/commands`),
  getSessionRecording: (id: string) => request<any>(`/api/admin/sessions/${id}/recording`),
};
