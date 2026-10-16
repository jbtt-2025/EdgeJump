import type { Env } from '../types.ts';
import type { UserSummary } from '../shared/types.ts';
import { PASSWORD_ALGORITHM } from '../crypto/password.ts';
import { hashUserPassword } from './password-service.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';
import { getAccountPolicy } from '../shared/account-policy.ts';
import { BootstrapError, bootstrapFailure } from './bootstrap-errors.ts';

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
  try {
    return await readBootstrapStatus(db);
  } catch (error) {
    throw bootstrapFailure(error, 'BOOTSTRAP_STATUS_UNAVAILABLE');
  }
}

async function readBootstrapStatus(db: D1Database): Promise<boolean> {
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
    throw new BootstrapError('BOOTSTRAP_COMPLETED');
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
    ).catch((error) => { throw bootstrapFailure(error, 'BOOTSTRAP_SAVE_FAILED'); });
    throw new BootstrapError(expectedToken ? 'BOOTSTRAP_TOKEN_INVALID' : 'BOOTSTRAP_TOKEN_NOT_CONFIGURED');
  }

  const policy = getAccountPolicy(env.DEPLOY_TYPE);
  const username = typeof input.username === 'string' ? input.username.trim().toLowerCase() : '';
  if (!username) throw new BootstrapError('BOOTSTRAP_USERNAME_REQUIRED');
  if (username.length < policy.bootstrapUsernameMinLength) {
    throw new BootstrapError('BOOTSTRAP_USERNAME_TOO_SHORT');
  }

  if (typeof input.password !== 'string' || !input.password) throw new BootstrapError('BOOTSTRAP_PASSWORD_REQUIRED');
  if (input.password.length < policy.passwordMinLength) {
    throw new BootstrapError('BOOTSTRAP_PASSWORD_TOO_SHORT');
  }
  if ((input.displayName !== undefined && typeof input.displayName !== 'string') ||
      (input.email !== undefined && typeof input.email !== 'string')) {
    throw new BootstrapError('BOOTSTRAP_INVALID_REQUEST');
  }

  const now = Date.now();
  const userId = `usr_${crypto.randomUUID()}`;
  const hashedPassword = await hashUserPassword(userId, input.password, env).catch((error) => {
    throw bootstrapFailure(error, 'BOOTSTRAP_PASSWORD_SERVICE_UNAVAILABLE');
  });

  const passwordParams = JSON.stringify({ iterations: hashedPassword.iterations });

  // 1. Create Super Admin user record
  try {
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
  } catch (error) {
    throw bootstrapFailure(error, 'BOOTSTRAP_SAVE_FAILED');
  }

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
  ).catch((error) => { throw bootstrapFailure(error, 'BOOTSTRAP_AUDIT_FAILED'); });

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
