export { Permissions, type PermissionCode } from '../shared/permissions.ts';

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
