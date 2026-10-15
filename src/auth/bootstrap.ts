import type { Env, UserRow } from '../types.ts';
import type { UserSummary } from '../shared/types.ts';
import { PASSWORD_ALGORITHM } from '../crypto/password.ts';
import { hashUserPassword } from './password-service.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';

export interface BootstrapInput {
  bootstrapToken: string;
  username: string;
  password: string;
  displayName?: string;
  email?: string;
  clientIp?: string;
  userAgent?: string;
}

/**
 * Check whether system bootstrap is needed.
 * Returns true if setup has not been completed AND no super admin user exists.
 */
export async function isBootstrapNeeded(db: D1Database): Promise<boolean> {
  // 1. Check system_settings for setup_complete flag
  const setting = await db
    .prepare("SELECT value FROM system_settings WHERE key = 'setup_complete'")
    .first<{ value: string }>();

  if (setting && setting.value === '1') {
    return false;
  }

  // 2. Check if any super admin exists in user_roles
  const adminRole = await db
    .prepare("SELECT COUNT(*) as count FROM user_roles WHERE role_id = 'role_super_admin'")
    .first<{ count: number }>();

  if (adminRole && adminRole.count > 0) {
    return false;
  }

  // 3. Check if any user exists at all
  const anyUser = await db
    .prepare('SELECT COUNT(*) as count FROM users')
    .first<{ count: number }>();

  if (anyUser && anyUser.count > 0) {
    return false;
  }

  return true;
}

/**
 * Perform one-time system bootstrap to create initial Super Admin.
 * Permanently disables bootstrap upon completion per AGENTS.md Section 9.
 */
export async function bootstrapSuperAdmin(
  input: BootstrapInput,
  env: Env
): Promise<{ success: boolean; user: UserSummary }> {
  const needed = await isBootstrapNeeded(env.DB);
  if (!needed) {
    throw new Error('System setup is already completed. Bootstrap is permanently disabled.');
  }

  // Validate BOOTSTRAP_TOKEN
  const expectedToken = env.BOOTSTRAP_TOKEN;
  if (!expectedToken || !input.bootstrapToken || input.bootstrapToken !== expectedToken) {
    await recordAuditEvent(
      {
        action: 'BOOTSTRAP_FAILED',
        resourceType: 'system',
        sourceIp: input.clientIp ?? '127.0.0.1',
        userAgent: input.userAgent,
        result: 'denied',
        metadata: { reason: 'Invalid or missing bootstrap token' },
      },
      env.DB
    );
    throw new Error('Invalid bootstrap token');
  }

  const username = input.username.trim().toLowerCase();
  if (!username || username.length < 3) {
    throw new Error('Username must be at least 3 characters long');
  }

  if (!input.password || input.password.length < 8) {
    throw new Error('Password must be at least 8 characters long');
  }

  const now = Date.now();
  const userId = `usr_${crypto.randomUUID()}`;
  const hashedPassword = await hashUserPassword(userId, input.password, env);

  const passwordParams = JSON.stringify({ iterations: hashedPassword.iterations });

  // 1. Create Super Admin user record
  await env.DB.prepare(
    `INSERT INTO users (
      id, username, display_name, email,
      password_hash, password_algorithm, password_params, password_salt,
      status, mfa_enabled, created_at, updated_at, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, ?, ?, 'bootstrap')`
  )
    .bind(
      userId,
      username,
      input.displayName || 'Super Administrator',
      input.email ?? null,
      hashedPassword.hash,
      PASSWORD_ALGORITHM,
      passwordParams,
      hashedPassword.salt,
      now,
      now
    )
    .run();

  // 2. Assign role_super_admin to user
  await env.DB.prepare(
    'INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)'
  )
    .bind(userId, 'role_super_admin')
    .run();

  // 3. Mark setup_complete = 1 permanently in system_settings
  await env.DB.prepare(
    `INSERT OR REPLACE INTO system_settings (key, value, updated_at, updated_by)
     VALUES ('setup_complete', '1', ?, 'bootstrap')`
  )
    .bind(now)
    .run();

  // 4. Record audit event
  await recordAuditEvent(
    {
      actorUserId: userId,
      actorUsername: username,
      action: 'SYSTEM_BOOTSTRAPPED',
      resourceType: 'user',
      resourceId: userId,
      resourceName: username,
      sourceIp: input.clientIp ?? '127.0.0.1',
      userAgent: input.userAgent,
      result: 'success',
      metadata: { role: 'role_super_admin' },
    },
    env.DB
  );

  return {
    success: true,
    user: {
      id: userId,
      username,
      displayName: input.displayName || 'Super Administrator',
      email: input.email ?? null,
      status: 'active',
      mfaEnabled: false,
      roles: ['role_super_admin'],
      createdAt: now,
      lastLoginAt: null,
    },
  };
}
