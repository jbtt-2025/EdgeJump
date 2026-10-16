import { logError } from '../logging.ts';
// User, Group, and Role Management Service (System RBAC Control Plane)

import type { Env, UserRow, GroupRow, RoleRow, PermissionRow, AuthenticatedUser } from '../types.ts';
import { hashUserPassword } from '../auth/password-service.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';
import { terminateSession } from '../sessions/session-service.ts';
import { getSetting } from '../settings/settings-service.ts';
import { getAccountPolicy } from '../shared/account-policy.ts';

export interface UserSummary {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  status: string;
  mfaEnabled: boolean;
  roles: string[];
  groups: string[];
  lastLoginAt: number | null;
  createdAt: number;
  updatedAt: number;
}

export interface CreateUserInput {
  username: string;
  password: string;
  displayName?: string;
  email?: string;
  roles?: string[];
  groups?: string[];
}

export interface UpdateUserInput {
  displayName?: string;
  email?: string;
  roles?: string[];
  groups?: string[];
}

export interface GroupSummary {
  id: string;
  name: string;
  description: string | null;
  memberCount: number;
  memberIds?: string[];
  createdAt: number;
  updatedAt: number;
}

/**
 * List all users without exposing password hash or secrets.
 */
export async function listUsers(db: D1Database): Promise<UserSummary[]> {
  const users = await db
    .prepare('SELECT id, username, display_name, email, status, mfa_enabled, last_login_at, created_at, updated_at FROM users ORDER BY created_at DESC')
    .all<UserRow>();

  const results: UserSummary[] = [];

  for (const user of users.results || []) {
    // Fetch roles
    const rolesResult = await db
      .prepare('SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?')
      .bind(user.id)
      .all<{ name: string }>();

    // Fetch groups
    const groupsResult = await db
      .prepare('SELECT g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?')
      .bind(user.id)
      .all<{ name: string }>();

    results.push({
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      email: user.email,
      status: user.status,
      mfaEnabled: user.mfa_enabled === 1,
      roles: (rolesResult.results || []).map(r => r.name),
      groups: (groupsResult.results || []).map(g => g.name),
      lastLoginAt: user.last_login_at,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
    });
  }

  return results;
}

/**
 * Creates a new user with PBKDF2 hashed password, roles, and groups.
 */
export async function createUser(
  input: CreateUserInput,
  actorUserId: string,
  env: Env,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<UserSummary> {
  const username = typeof input.username === 'string' ? input.username.trim().toLowerCase() : '';
  if (!username) throw new Error('Username is required');
  if (typeof input.password !== 'string' || !input.password) throw new Error('Password is required');
  if (input.password.length < getAccountPolicy(env.DEPLOY_TYPE).passwordMinLength) {
    throw new Error('Password must be at least 8 characters');
  }

  // Check unique username
  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?')
    .bind(username)
    .first();
  if (existing) {
    throw new Error('Username already exists');
  }

  const userId = `usr_${crypto.randomUUID()}`;
  const now = Date.now();
  const { hash, salt, iterations } = await hashUserPassword(userId, input.password, env);
  const displayName = input.displayName?.trim() || username;

  await env.DB.prepare(
    `INSERT INTO users (
      id, username, display_name, email, password_hash, password_algorithm,
      password_params, password_salt, status, mfa_enabled, created_at, updated_at, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, ?, ?, ?)`
  )
    .bind(
      userId,
      username,
      displayName,
      input.email ?? null,
      hash,
      'pbkdf2-sha256',
      JSON.stringify({ iterations }),
      salt,
      now,
      now,
      actorUserId
    )
    .run();

  // Assign roles
  const roles = input.roles && input.roles.length > 0 ? input.roles : ['User'];
  for (const roleName of roles) {
    const role = await env.DB.prepare('SELECT id FROM roles WHERE name = ?')
      .bind(roleName)
      .first<{ id: string }>();
    if (role) {
      await env.DB.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)')
        .bind(userId, role.id)
        .run();
    }
  }

  // Assign groups
  if (input.groups && input.groups.length > 0) {
    for (const groupName of input.groups) {
      const grp = await env.DB.prepare('SELECT id FROM groups WHERE name = ?')
        .bind(groupName)
        .first<{ id: string }>();
      if (grp) {
        await env.DB.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)')
          .bind(grp.id, userId, now)
          .run();
      }
    }
  }

  await recordAuditEvent(
    {
      actorUserId,
      action: 'USER_CREATED',
      resourceType: 'user',
      resourceId: userId,
      resourceName: username,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
      metadata: { roles, groups: input.groups || [] },
    },
    env.DB
  );

  return {
    id: userId,
    username,
    displayName,
    email: input.email ?? null,
    status: 'active',
    mfaEnabled: false,
    roles,
    groups: input.groups || [],
    lastLoginAt: null,
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Updates a user's display name, email, roles, or groups.
 */
export async function updateUser(
  userId: string,
  input: UpdateUserInput,
  actorUserId: string,
  db: D1Database,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<void> {
  const user = await db.prepare('SELECT id, username FROM users WHERE id = ?')
    .bind(userId)
    .first<{ id: string; username: string }>();
  if (!user) throw new Error('User not found');

  const now = Date.now();
  if (input.displayName !== undefined || input.email !== undefined) {
    await db.prepare('UPDATE users SET display_name = COALESCE(?, display_name), email = COALESCE(?, email), updated_at = ? WHERE id = ?')
      .bind(input.displayName ?? null, input.email ?? null, now, userId)
      .run();
  }

  // Sync roles if provided
  if (input.roles) {
    await db.prepare('DELETE FROM user_roles WHERE user_id = ?').bind(userId).run();
    for (const roleName of input.roles) {
      const role = await db.prepare('SELECT id FROM roles WHERE name = ?').bind(roleName).first<{ id: string }>();
      if (role) {
        await db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').bind(userId, role.id).run();
      }
    }
  }

  // Sync groups if provided
  if (input.groups) {
    await db.prepare('DELETE FROM group_members WHERE user_id = ?').bind(userId).run();
    for (const groupName of input.groups) {
      const grp = await db.prepare('SELECT id FROM groups WHERE name = ?').bind(groupName).first<{ id: string }>();
      if (grp) {
        await db.prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)').bind(grp.id, userId, now).run();
      }
    }
  }

  await recordAuditEvent(
    {
      actorUserId,
      action: 'USER_UPDATED',
      resourceType: 'user',
      resourceId: userId,
      resourceName: user.username,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
      metadata: { displayName: input.displayName, email: input.email, roles: input.roles, groups: input.groups },
    },
    db
  );
}

/**
 * Disables a user per Section 60:
 * 1. Mark status = 'disabled'
 * 2. Revoke all active login sessions in auth_sessions
 * 3. If terminate_active_sessions_on_disable (default true), terminate all active SSH sessions
 */
export async function disableUser(
  userId: string,
  actorUserId: string,
  env: Env,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<void> {
  const user = await env.DB.prepare('SELECT id, username FROM users WHERE id = ?')
    .bind(userId)
    .first<{ id: string; username: string }>();
  if (!user) throw new Error('User not found');

  const now = Date.now();
  await env.DB.prepare("UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ?")
    .bind(now, userId)
    .run();

  // Revoke all auth sessions
  await env.DB.prepare('UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL')
    .bind(now, userId)
    .run();

  const failedSessions: string[] = [];
  // Terminate active SSH sessions if setting is true
  const terminateSetting = await getSetting('terminate_active_sessions_on_disable', env.DB, 'true');
  if (terminateSetting === 'true') {
    const activeSessions = await env.DB.prepare(
      "SELECT id FROM ssh_sessions WHERE user_id = ? AND status IN ('creating', 'connecting', 'active')"
    )
      .bind(userId)
      .all<{ id: string }>();

    for (const session of activeSessions.results || []) {
      try {
        await terminateSession(session.id, actorUserId, env, 'User account was disabled', { sourceIp: clientIp, userAgent });
      } catch (err) {
        logError(`Failed to terminate active session ${session.id}:`, err);
        failedSessions.push(session.id);
      }
    }
  }

  await recordAuditEvent(
    {
      actorUserId,
      action: 'USER_DISABLED',
      resourceType: 'user',
      resourceId: userId,
      resourceName: user.username,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
      metadata: { failedSessionIds: failedSessions },
    },
    env.DB
  );
  if (failedSessions.length) throw new Error('User disabled; some active sessions could not be terminated. Retry termination from online sessions.');
}

/**
 * Enables a user.
 */
export async function enableUser(
  userId: string,
  actorUserId: string,
  db: D1Database,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<void> {
  const user = await db.prepare('SELECT id, username FROM users WHERE id = ?')
    .bind(userId)
    .first<{ id: string; username: string }>();
  if (!user) throw new Error('User not found');

  const now = Date.now();
  await db.prepare("UPDATE users SET status = 'active', updated_at = ? WHERE id = ?")
    .bind(now, userId)
    .run();

  await recordAuditEvent(
    {
      actorUserId,
      action: 'USER_ENABLED',
      resourceType: 'user',
      resourceId: userId,
      resourceName: user.username,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
    },
    db
  );
}

/**
 * Resets a user's password, invalidating existing auth sessions.
 */
export async function resetUserPassword(
  userId: string,
  newPassword: string,
  actorUserId: string,
  env: Env,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<void> {
  if (typeof newPassword !== 'string' || !newPassword) throw new Error('Password is required');
  if (newPassword.length < getAccountPolicy(env.DEPLOY_TYPE).passwordMinLength) {
    throw new Error('Password must be at least 8 characters');
  }

  const user = await env.DB.prepare('SELECT id, username FROM users WHERE id = ?')
    .bind(userId)
    .first<{ id: string; username: string }>();
  if (!user) throw new Error('User not found');

  const { hash, salt, iterations } = await hashUserPassword(userId, newPassword, env);
  const now = Date.now();

  await env.DB.prepare(
    'UPDATE users SET password_hash = ?, password_salt = ?, password_params = ?, updated_at = ? WHERE id = ?'
  )
    .bind(hash, salt, JSON.stringify({ iterations }), now, userId)
    .run();

  // Revoke all login sessions
  await env.DB.prepare('UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL')
    .bind(now, userId)
    .run();

  await recordAuditEvent(
    {
      actorUserId,
      action: 'USER_UPDATED',
      resourceType: 'user',
      resourceId: userId,
      resourceName: user.username,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
      metadata: { reason: 'Password reset' },
    },
    env.DB
  );
}

// --- USER GROUPS ---

export async function listGroups(db: D1Database): Promise<GroupSummary[]> {
  const groups = await db.prepare('SELECT * FROM groups ORDER BY name ASC').all<GroupRow>();
  const results: GroupSummary[] = [];

  for (const g of groups.results || []) {
    const countRes = await db
      .prepare('SELECT COUNT(*) as count FROM group_members WHERE group_id = ?')
      .bind(g.id)
      .first<{ count: number }>();

    results.push({
      id: g.id,
      name: g.name,
      description: g.description,
      memberCount: countRes?.count ?? 0,
      memberIds: (await db.prepare('SELECT user_id FROM group_members WHERE group_id = ?').bind(g.id).all<{ user_id: string }>()).results.map((row) => row.user_id),
      createdAt: g.created_at,
      updatedAt: g.updated_at,
    });
  }

  return results;
}

export async function createGroup(
  input: { name: string; description?: string },
  actorUserId: string,
  db: D1Database,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<GroupSummary> {
  const name = input.name.trim();
  if (!name) throw new Error('Group name is required');

  const groupId = `grp_${crypto.randomUUID()}`;
  const now = Date.now();

  await db.prepare('INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind(groupId, name, input.description ?? null, now, now)
    .run();

  await recordAuditEvent(
    {
      actorUserId,
      action: 'GROUP_CREATED',
      resourceType: 'group',
      resourceId: groupId,
      resourceName: name,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
    },
    db
  );

  return {
    id: groupId,
    name,
    description: input.description ?? null,
    memberCount: 0,
    createdAt: now,
    updatedAt: now,
  };
}

export async function updateGroup(
  groupId: string,
  input: { name?: string; description?: string; members?: string[] },
  actorUserId: string,
  db: D1Database,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<void> {
  const group = await db.prepare('SELECT id, name FROM groups WHERE id = ?').bind(groupId).first<GroupRow>();
  if (!group) throw new Error('Group not found');

  const now = Date.now();
  if (input.name !== undefined || input.description !== undefined) {
    await db.prepare('UPDATE groups SET name = COALESCE(?, name), description = COALESCE(?, description), updated_at = ? WHERE id = ?')
      .bind(input.name ?? null, input.description ?? null, now, groupId)
      .run();
  }

  if (input.members) {
    await db.prepare('DELETE FROM group_members WHERE group_id = ?').bind(groupId).run();
    for (const userId of input.members) {
      await db.prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)').bind(groupId, userId, now).run();
    }
  }

  await recordAuditEvent(
    {
      actorUserId,
      action: 'GROUP_UPDATED',
      resourceType: 'group',
      resourceId: groupId,
      resourceName: group.name,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
    },
    db
  );
}

export async function deleteGroup(
  groupId: string,
  actorUserId: string,
  db: D1Database,
  clientIp: string = '127.0.0.1',
  userAgent?: string
): Promise<void> {
  const group = await db.prepare('SELECT id, name FROM groups WHERE id = ?').bind(groupId).first<GroupRow>();
  if (!group) throw new Error('Group not found');

  await db.prepare('DELETE FROM groups WHERE id = ?').bind(groupId).run();

  await recordAuditEvent(
    {
      actorUserId,
      action: 'GROUP_DELETED',
      resourceType: 'group',
      resourceId: groupId,
      resourceName: group.name,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
    },
    db
  );
}

// --- ROLES & PERMISSIONS ---

export async function listRoles(db: D1Database): Promise<Array<{ id: string; name: string; description: string | null; permissions: string[] }>> {
  const roles = await db.prepare('SELECT * FROM roles ORDER BY name ASC').all<RoleRow>();
  const results = [];

  for (const r of roles.results || []) {
    const perms = await db
      .prepare('SELECT p.code FROM permissions p JOIN role_permissions rp ON p.id = rp.permission_id WHERE rp.role_id = ?')
      .bind(r.id)
      .all<{ code: string }>();

    results.push({
      id: r.id,
      name: r.name,
      description: r.description,
      permissions: (perms.results || []).map(p => p.code),
    });
  }

  return results;
}
