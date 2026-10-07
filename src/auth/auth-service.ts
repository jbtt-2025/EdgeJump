import type { Env, UserRow, AuthSessionRow, AuthenticatedUser } from '../types.ts';
import type { UserSummary } from '../shared/types.ts';
import { verifyPassword } from '../crypto/password.ts';
import {
  generateSessionToken,
  hashToken,
  generateRecoveryCode,
  hashRecoveryCode,
} from '../crypto/token.ts';
import {
  generateTotpSecret,
  verifyTotpCode,
  getTotpUri,
} from '../crypto/totp.ts';
import {
  encodeUtf8,
  decodeUtf8,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  toBufferSource,
} from '../crypto/utils.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';

export const SESSION_TTL_MS = 8 * 3600 * 1000; // 8 hours absolute TTL per Section 7
export const COOKIE_NAME = 'edgejump_session';

export interface LoginInput {
  username: string;
  password: string;
  totpCode?: string;
  recoveryCode?: string;
  clientIp: string;
  userAgent?: string;
}

export interface LoginSuccessResult {
  mfaRequired: false;
  sessionToken: string;
  cookie: string;
  user: UserSummary;
  roles: string[];
  permissions: string[];
}

export interface LoginMfaRequiredResult {
  mfaRequired: true;
  userId: string;
  username: string;
}

export type LoginResult = LoginSuccessResult | LoginMfaRequiredResult;

/**
 * Builds the HttpOnly Secure SameSite=Strict cookie header for EdgeJump web sessions.
 */
export function buildSessionCookie(token: string, maxAgeSeconds: number = 8 * 3600): string {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

/**
 * Builds the cookie header to clear/invalidate the session cookie in browser.
 */
export function buildClearSessionCookie(): string {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/**
 * Encrypt a TOTP secret using AES-256-GCM and Master KEK for secure storage in users table.
 */
async function encryptTotpSecret(
  secret: string,
  userId: string,
  masterKekHex: string
): Promise<{ ciphertext: string; nonce: string }> {
  const masterKeyBytes = hexToBytes(masterKekHex.trim());
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const masterKey = await crypto.subtle.importKey(
    'raw',
    toBufferSource(masterKeyBytes),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  const aad = encodeUtf8(`${userId}:totp`);
  const plaintextBytes = encodeUtf8(secret);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBufferSource(nonce), additionalData: toBufferSource(aad) },
    masterKey,
    toBufferSource(plaintextBytes)
  );

  return {
    ciphertext: bytesToBase64(new Uint8Array(cipherBuffer)),
    nonce: bytesToBase64(nonce),
  };
}

/**
 * Decrypt a stored TOTP secret using AES-256-GCM and Master KEK.
 */
async function decryptTotpSecret(
  ciphertextB64: string,
  nonceB64: string,
  userId: string,
  masterKekHex: string
): Promise<string> {
  const masterKeyBytes = hexToBytes(masterKekHex.trim());
  const nonce = base64ToBytes(nonceB64);
  const cipherBytes = base64ToBytes(ciphertextB64);
  const masterKey = await crypto.subtle.importKey(
    'raw',
    toBufferSource(masterKeyBytes),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  const aad = encodeUtf8(`${userId}:totp`);
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBufferSource(nonce), additionalData: toBufferSource(aad) },
    masterKey,
    toBufferSource(cipherBytes)
  );

  return decodeUtf8(new Uint8Array(decryptedBuffer));
}

/**
 * Helper to fetch user roles and permissions from D1.
 */
export async function getUserRolesAndPermissions(
  userId: string,
  db: D1Database
): Promise<{ roles: string[]; permissions: Set<string> }> {
  const { results: roleRows } = await db
    .prepare('SELECT role_id FROM user_roles WHERE user_id = ?')
    .bind(userId)
    .all<{ role_id: string }>();

  const roles = (roleRows || []).map((r) => r.role_id);

  const { results: permRows } = await db
    .prepare(
      `SELECT DISTINCT p.code
       FROM user_roles ur
       JOIN role_permissions rp ON ur.role_id = rp.role_id
       JOIN permissions p ON rp.permission_id = p.id
       WHERE ur.user_id = ?`
    )
    .bind(userId)
    .all<{ code: string }>();

  const permissions = new Set<string>((permRows || []).map((p) => p.code));

  if (roles.includes('role_super_admin')) {
    permissions.add('*');
  }

  return { roles, permissions };
}

/**
 * Authenticates user credentials and optional MFA token, then issues a session token.
 */
export async function login(input: LoginInput, env: Env): Promise<LoginResult> {
  const username = input.username.trim().toLowerCase();

  // 1. Fetch user by username
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?')
    .bind(username)
    .first<UserRow>();

  if (!user) {
    await recordAuditEvent(
      {
        action: 'LOGIN_FAILED',
        resourceType: 'user',
        sourceIp: input.clientIp,
        userAgent: input.userAgent,
        result: 'failure',
        metadata: { username, reason: 'Invalid username or password' },
      },
      env.DB
    );
    throw new Error('Invalid username or password');
  }

  // 2. Validate user status
  if (user.status !== 'active') {
    await recordAuditEvent(
      {
        actorUserId: user.id,
        actorUsername: user.username,
        action: 'LOGIN_FAILED',
        resourceType: 'user',
        resourceId: user.id,
        resourceName: user.username,
        sourceIp: input.clientIp,
        userAgent: input.userAgent,
        result: 'denied',
        metadata: { status: user.status, reason: `User account is ${user.status}` },
      },
      env.DB
    );
    throw new Error(`User account is ${user.status}`);
  }

  // 3. Verify PBKDF2 password
  let iterations = 600000;
  try {
    const params = JSON.parse(user.password_params);
    if (typeof params.iterations === 'number') {
      iterations = params.iterations;
    }
  } catch {
    // default to 600,000
  }

  const pepper = env.AUTH_PEPPER || '';
  const validPassword = await verifyPassword(
    input.password,
    pepper,
    user.password_hash,
    user.password_salt,
    iterations
  );

  if (!validPassword) {
    await recordAuditEvent(
      {
        actorUserId: user.id,
        actorUsername: user.username,
        action: 'LOGIN_FAILED',
        resourceType: 'user',
        resourceId: user.id,
        resourceName: user.username,
        sourceIp: input.clientIp,
        userAgent: input.userAgent,
        result: 'failure',
        metadata: { reason: 'Invalid username or password' },
      },
      env.DB
    );
    throw new Error('Invalid username or password');
  }

  // 4. MFA Validation if mfa_enabled is 1
  if (user.mfa_enabled === 1) {
    if (!input.totpCode && !input.recoveryCode) {
      return {
        mfaRequired: true,
        userId: user.id,
        username: user.username,
      };
    }

    if (input.totpCode) {
      if (!user.totp_secret_ciphertext || !user.totp_secret_nonce) {
        throw new Error('MFA is enabled but TOTP secret is unconfigured');
      }
      const masterKek = env.CREDENTIAL_KEK_V1;
      if (!masterKek) {
        throw new Error('CREDENTIAL_KEK_V1 secret is required for MFA decryption');
      }
      const totpSecret = await decryptTotpSecret(
        user.totp_secret_ciphertext,
        user.totp_secret_nonce,
        user.id,
        masterKek
      );
      const validTotp = await verifyTotpCode(totpSecret, input.totpCode);
      if (!validTotp) {
        await recordAuditEvent(
          {
            actorUserId: user.id,
            actorUsername: user.username,
            action: 'LOGIN_FAILED',
            resourceType: 'user',
            resourceId: user.id,
            resourceName: user.username,
            sourceIp: input.clientIp,
            userAgent: input.userAgent,
            result: 'failure',
            metadata: { reason: 'Invalid TOTP code' },
          },
          env.DB
        );
        throw new Error('Invalid TOTP code');
      }
    } else if (input.recoveryCode) {
      const codeHash = await hashRecoveryCode(input.recoveryCode);
      const recoveryRow = await env.DB.prepare(
        'SELECT id FROM mfa_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL'
      )
        .bind(user.id, codeHash)
        .first<{ id: string }>();

      if (!recoveryRow) {
        await recordAuditEvent(
          {
            actorUserId: user.id,
            actorUsername: user.username,
            action: 'LOGIN_FAILED',
            resourceType: 'user',
            resourceId: user.id,
            resourceName: user.username,
            sourceIp: input.clientIp,
            userAgent: input.userAgent,
            result: 'failure',
            metadata: { reason: 'Invalid or already used recovery code' },
          },
          env.DB
        );
        throw new Error('Invalid or already used recovery code');
      }

      // Mark recovery code used
      await env.DB.prepare('UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ?')
        .bind(Date.now(), recoveryRow.id)
        .run();
    }
  }

  // 5. Create Web Login Session
  const now = Date.now();
  const sessionToken = generateSessionToken();
  const tokenHash = await hashToken(sessionToken);
  const sessionId = `sess_${crypto.randomUUID()}`;
  const expiresAt = now + SESSION_TTL_MS;

  await env.DB.prepare(
    `INSERT INTO auth_sessions (
      id, user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent, revoked_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`
  )
    .bind(sessionId, user.id, tokenHash, now, now, expiresAt, input.clientIp, input.userAgent ?? null)
    .run();

  // Update user's last_login_at
  await env.DB.prepare('UPDATE users SET last_login_at = ? WHERE id = ?')
    .bind(now, user.id)
    .run();

  // Fetch roles and permissions
  const { roles, permissions } = await getUserRolesAndPermissions(user.id, env.DB);

  // Record LOGIN_SUCCESS audit event
  await recordAuditEvent(
    {
      actorUserId: user.id,
      actorUsername: user.username,
      action: 'LOGIN_SUCCESS',
      resourceType: 'session',
      resourceId: sessionId,
      sourceIp: input.clientIp,
      userAgent: input.userAgent,
      result: 'success',
      metadata: { mfaUsed: user.mfa_enabled === 1 },
    },
    env.DB
  );

  const cookie = buildSessionCookie(sessionToken, Math.floor(SESSION_TTL_MS / 1000));

  const userSummary: UserSummary = {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    email: user.email,
    status: user.status,
    mfaEnabled: user.mfa_enabled === 1,
    roles,
    createdAt: user.created_at,
    lastLoginAt: now,
  };

  return {
    mfaRequired: false,
    sessionToken,
    cookie,
    user: userSummary,
    roles,
    permissions: Array.from(permissions),
  };
}

/**
 * Validates a session token from Cookie or header and returns the authenticated user context.
 */
export async function validateSession(
  sessionToken: string,
  db: D1Database
): Promise<AuthenticatedUser | null> {
  if (!sessionToken || sessionToken.trim() === '') {
    return null;
  }

  const tokenHash = await hashToken(sessionToken);
  const now = Date.now();

  const session = await db
    .prepare('SELECT * FROM auth_sessions WHERE token_hash = ? AND revoked_at IS NULL')
    .bind(tokenHash)
    .first<AuthSessionRow>();

  if (!session) {
    return null;
  }

  if (session.expires_at <= now) {
    return null;
  }

  // Update last_seen_at
  await db
    .prepare('UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?')
    .bind(now, session.id)
    .run();

  // Fetch user
  const user = await db
    .prepare('SELECT * FROM users WHERE id = ?')
    .bind(session.user_id)
    .first<UserRow>();

  if (!user || user.status !== 'active') {
    return null;
  }

  const { roles, permissions } = await getUserRolesAndPermissions(user.id, db);

  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    email: user.email,
    roles,
    permissions,
  };
}

/**
 * Revokes an existing login session in D1 auth_sessions and records LOGOUT audit event.
 */
export async function logout(
  sessionToken: string,
  db: D1Database,
  actorUserId?: string,
  clientIp: string = '127.0.0.1'
): Promise<string> {
  if (!sessionToken) {
    return buildClearSessionCookie();
  }

  const tokenHash = await hashToken(sessionToken);
  const now = Date.now();

  const session = await db
    .prepare('SELECT * FROM auth_sessions WHERE token_hash = ?')
    .bind(tokenHash)
    .first<AuthSessionRow>();

  if (session) {
    await db
      .prepare('UPDATE auth_sessions SET revoked_at = ? WHERE id = ?')
      .bind(now, session.id)
      .run();

    await recordAuditEvent(
      {
        actorUserId: actorUserId ?? session.user_id,
        action: 'LOGOUT',
        resourceType: 'session',
        resourceId: session.id,
        sourceIp: clientIp,
        result: 'success',
      },
      db
    );
  }

  return buildClearSessionCookie();
}

/**
 * Initiates TOTP MFA setup for a user: generates secret, recovery codes, and saves encrypted secret.
 */
export async function setupMfa(
  userId: string,
  env: Env
): Promise<{ secret: string; uri: string; recoveryCodes: string[] }> {
  const masterKek = env.CREDENTIAL_KEK_V1;
  if (!masterKek) {
    throw new Error('CREDENTIAL_KEK_V1 is required for MFA setup');
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?')
    .bind(userId)
    .first<UserRow>();

  if (!user) {
    throw new Error('User not found');
  }

  const secret = generateTotpSecret();
  const uri = getTotpUri(secret, user.username, 'EdgeJump');
  const recoveryCodes: string[] = [];
  const now = Date.now();

  // Generate 8 recovery codes
  for (let i = 0; i < 8; i++) {
    recoveryCodes.push(generateRecoveryCode());
  }

  // Encrypt TOTP secret
  const { ciphertext, nonce } = await encryptTotpSecret(secret, userId, masterKek);

  // Save encrypted secret on users table (mfa_enabled stays 0 until confirmMfa)
  await env.DB.prepare(
    'UPDATE users SET totp_secret_ciphertext = ?, totp_secret_nonce = ?, updated_at = ? WHERE id = ?'
  )
    .bind(ciphertext, nonce, now, userId)
    .run();

  // Clear any existing recovery codes and insert new ones
  await env.DB.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?')
    .bind(userId)
    .run();

  for (const code of recoveryCodes) {
    const codeHash = await hashRecoveryCode(code);
    await env.DB.prepare(
      'INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)'
    )
      .bind(`rec_${crypto.randomUUID()}`, userId, codeHash, now)
      .run();
  }

  return { secret, uri, recoveryCodes };
}

/**
 * Confirms and activates TOTP MFA for a user by verifying the candidate code.
 */
export async function confirmMfa(
  userId: string,
  code: string,
  env: Env,
  clientIp: string = '127.0.0.1'
): Promise<boolean> {
  const masterKek = env.CREDENTIAL_KEK_V1;
  if (!masterKek) {
    throw new Error('CREDENTIAL_KEK_V1 is required for MFA confirmation');
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?')
    .bind(userId)
    .first<UserRow>();

  if (!user || !user.totp_secret_ciphertext || !user.totp_secret_nonce) {
    throw new Error('MFA setup has not been initiated for this user');
  }

  const secret = await decryptTotpSecret(
    user.totp_secret_ciphertext,
    user.totp_secret_nonce,
    userId,
    masterKek
  );

  const isValid = await verifyTotpCode(secret, code);
  if (!isValid) {
    return false;
  }

  const now = Date.now();
  await env.DB.prepare('UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?')
    .bind(now, userId)
    .run();

  await recordAuditEvent(
    {
      actorUserId: userId,
      actorUsername: user.username,
      action: 'MFA_ENABLED',
      resourceType: 'user',
      resourceId: userId,
      resourceName: user.username,
      sourceIp: clientIp,
      result: 'success',
    },
    env.DB
  );

  return true;
}

/**
 * Disables MFA for a user and cleans up secrets & recovery codes.
 */
export async function disableMfa(
  userId: string,
  db: D1Database,
  clientIp: string = '127.0.0.1'
): Promise<void> {
  const now = Date.now();
  const user = await db.prepare('SELECT username FROM users WHERE id = ?').bind(userId).first<{ username: string }>();

  await db.prepare(
    'UPDATE users SET mfa_enabled = 0, totp_secret_ciphertext = NULL, totp_secret_nonce = NULL, updated_at = ? WHERE id = ?'
  )
    .bind(now, userId)
    .run();

  await db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?')
    .bind(userId)
    .run();

  await recordAuditEvent(
    {
      actorUserId: userId,
      actorUsername: user?.username ?? 'user',
      action: 'MFA_DISABLED',
      resourceType: 'user',
      resourceId: userId,
      sourceIp: clientIp,
      result: 'success',
    },
    db
  );
}
