// System RBAC Definitions & Helper Functions

export const Permissions = {
  USER_READ: 'user.read',
  USER_CREATE: 'user.create',
  USER_UPDATE: 'user.update',
  USER_DISABLE: 'user.disable',

  GROUP_READ: 'group.read',
  GROUP_WRITE: 'group.write',

  ASSET_READ: 'asset.read',
  ASSET_CREATE: 'asset.create',
  ASSET_UPDATE: 'asset.update',
  ASSET_DELETE: 'asset.delete',

  CREDENTIAL_CREATE: 'credential.create',
  CREDENTIAL_REPLACE: 'credential.replace',
  CREDENTIAL_DELETE: 'credential.delete',

  AUTHORIZATION_READ: 'authorization.read',
  AUTHORIZATION_WRITE: 'authorization.write',

  SESSION_VIEW_OWN: 'session.view_own',
  SESSION_VIEW_ALL: 'session.view_all',
  SESSION_MONITOR: 'session.monitor',
  SESSION_TERMINATE: 'session.terminate',

  AUDIT_READ: 'audit.read',

  SETTINGS_READ: 'settings.read',
  SETTINGS_WRITE: 'settings.write',
} as const;

export type PermissionCode = typeof Permissions[keyof typeof Permissions];

export function hasPermission(userPermissions: Set<string>, requiredPermission: string): boolean {
  if (userPermissions.has('*')) return true;
  if (userPermissions.has(requiredPermission)) return true;

  // Prefix wildcard check, e.g. "asset.*" matches "asset.read"
  const prefix = requiredPermission.split('.')[0] + '.*';
  return userPermissions.has(prefix);
}

export function hasAnyPermission(userPermissions: Set<string>, requiredPermissions: string[]): boolean {
  return requiredPermissions.some(perm => hasPermission(userPermissions, perm));
}

export function hasAllPermissions(userPermissions: Set<string>, requiredPermissions: string[]): boolean {
  return requiredPermissions.every(perm => hasPermission(userPermissions, perm));
}
