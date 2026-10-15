import type { Env, AuthenticatedUser } from '../types.ts';
import {
  jsonResponse,
  jsonError,
  validateCsrfOrigin,
  hasValidWebSocketOrigin,
  validateCsrfToken, issueCsrfToken,
} from '../http-security.ts';
import {
  login,
  logout,
  validateSession,
  buildSessionCookie,
  buildClearSessionCookie,
  COOKIE_NAME,
  setupMfa, confirmMfa, disableMfa, isMfaRequired,
} from '../auth/auth-service.ts';
import { isBootstrapNeeded, bootstrapSuperAdmin } from '../auth/bootstrap.ts';
import {
  listAssets,
  getAsset,
  createAsset,
  updateAsset,
  deleteAsset,
  listAssetGroups,
  createAssetGroup,
  updateAssetGroup,
  deleteAssetGroup,
  listAssetAccounts,
  createAssetAccount,
  updateAssetAccount,
  deleteAssetAccount,
  getHostKeyForAsset,
  resetHostKeyForAsset,
  listHostKeysForAsset, approveHostKeyForAsset,
} from '../assets/asset-service.ts';
import {
  listCredentials,
  createCredential,
  replaceCredential,
  deleteCredential,
  rewrapCredential,
} from '../credentials/credential-service.ts';
import {
  getAuthorizedAssetsForUser,
  listAuthorizationRules,
  createAuthorizationRule,
  updateAuthorizationRule,
  deleteAuthorizationRule,
} from '../authorization/authorization-service.ts';
import {
  createSession,
  listOnlineSessions,
  listHistoricalSessions,
  terminateSession,
  getSessionDetail,
  getSessionCommands,
  getSessionRecording,
  getSessionRecordingChunk,
  getSession, enforcePermissionRevocation,
} from '../sessions/session-service.ts';
import {
  listUsers,
  createUser,
  updateUser,
  disableUser,
  enableUser,
  resetUserPassword,
  listGroups,
  createGroup,
  updateGroup,
  deleteGroup,
  listRoles,
} from '../users/user-service.ts';
import { getAllSettings, updateSetting } from '../settings/settings-service.ts';
import { recordAuditEvent, listAuditEvents } from '../audit/audit-service.ts';
import { hasPermission, Permissions } from '../rbac/permissions.ts';
import { getRecordingStorage } from '../storage/recording-storage.ts';
import { cleanupExpiredRecordings } from '../sessions/cleanup-service.ts';
import { verifyTicket, parseTicketPayload } from '../backend/security.ts';
import { hashToken } from '../crypto/token.ts';
import { PasswordKdfUnavailableError } from '../auth/password-service.ts';
import { logError } from '../logging.ts';
import { verifyTotpCode } from '../crypto/totp.ts';
import { verifyMfaProof } from '../auth/auth-service.ts';

export function isDemoMode(env: Env): boolean {
  return env.DEPLOY_TYPE?.toLowerCase() === 'demo';
}

async function isUserAdministrator(userId: string, db: D1Database): Promise<boolean> {
  const user = await db
    .prepare('SELECT username FROM users WHERE id = ?')
    .bind(userId)
    .first<{ username: string }>();
  if (user?.username === 'admin') return true;

  const roles = await db
    .prepare(
      `SELECT r.name
       FROM roles r
       JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = ?`
    )
    .bind(userId)
    .all<{ name: string }>();

  return (roles.results || []).some(
    (r) =>
      r.name.toLowerCase().includes('admin') ||
      r.name === 'Super Admin' ||
      r.name === 'Asset Admin'
  );
}

function extractSessionToken(request: Request): string | null {
  const cookieHeader = request.headers.get('Cookie');
  if (cookieHeader) {
    const cookies = cookieHeader.split(';').map((c) => c.trim());
    for (const c of cookies) {
      if (c.startsWith(`${COOKIE_NAME}=`)) {
        return c.substring(COOKIE_NAME.length + 1);
      }
    }
  }
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

function getClientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ??
    request.headers.get('x-forwarded-for')?.split(',')[0].trim() ??
    '127.0.0.1'
  );
}

export async function handleApiRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();
  const clientIp = getClientIp(request);
  const userAgent = request.headers.get('User-Agent') ?? undefined;

  if (path === '/api/auth/csrf' && method === 'GET') return issueCsrfToken(request);

  // CSRF validation on mutating HTTP requests
  if (!validateCsrfOrigin(request) || !validateCsrfToken(request)) {
    return jsonError('CSRF protection: Invalid Origin or cross-site request', 403);
  }

  // --- 1. BOOTSTRAP ENDPOINT ---
  if (path === '/api/auth/bootstrap' && method === 'POST') {
    const needed = await isBootstrapNeeded(env.DB);
    if (!needed) {
      return jsonError('Bootstrap is already completed or permanently disabled', 403);
    }
    const tokenHeader = request.headers.get('x-bootstrap-token') ?? '';
    const body = await request.json<any>().catch(() => ({}));
    const result = await bootstrapSuperAdmin(
      {
        bootstrapToken: tokenHeader || body.bootstrapToken,
        username: body.username,
        password: body.password,
        displayName: body.displayName,
        email: body.email,
        clientIp,
        userAgent,
      },
      env
    );
    return jsonResponse({ success: true, user: result.user }, 201);
  }

  // Check if bootstrap is needed
  if (path === '/api/auth/bootstrap/status' && method === 'GET') {
    const needed = await isBootstrapNeeded(env.DB);
    return jsonResponse({ bootstrapNeeded: needed, deployType: env.DEPLOY_TYPE || 'production' });
  }

  // --- 2. AUTHENTICATION (LOGIN, LOGOUT) ---
  if ((path === '/api/auth/login' || path === '/api/auth/mfa') && method === 'POST') {
    const body = await request.json<any>().catch(() => ({}));
    if (path === '/api/auth/mfa') {
      if (typeof body.challengeToken !== 'string' || (!body.totpCode && !body.recoveryCode)) return jsonError('MFA challenge and code are required', 400);
      const challenge = await env.DB.prepare(`SELECT u.username FROM auth_mfa_challenges c JOIN users u ON u.id = c.user_id
        WHERE c.token_hash = ? AND c.ip = ? AND c.used_at IS NULL AND c.expires_at > ?`)
        .bind(await hashToken(body.challengeToken), clientIp, Date.now()).first<{ username: string }>();
      if (!challenge) return jsonError('Invalid or expired MFA challenge', 401);
      body.username = challenge.username; body.password = '';
    }
    if (typeof body.username !== 'string' || typeof body.password !== 'string' || !body.username.trim() || (!body.password && path !== '/api/auth/mfa')) {
      return jsonError('Username and password are required', 400);
    }

    const username = body.username.trim().toLowerCase();
    const rateStubs = [`ip:${clientIp}`, `user:${username}`].map((key) => ({
      key, stub: env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(key)),
    }));
    const exhaustedScopes: string[] = [];
    const reservations: { key: string; stub: DurableObjectStub; reservationId: string }[] = [];
    const refundReservations = async () => {
      for (const { key, stub, reservationId } of reservations) {
        try {
          const response = await stub.fetch('https://ratelimit.internal/refund', { method: 'POST', body: JSON.stringify({ key, reservationId }) });
          if (!response.ok) throw new Error('Rate limit refund unavailable');
        } catch (error) { logError('login_reservation_refund_failed', error); }
      }
    };
    for (const { key, stub } of rateStubs) {
      const response = await stub.fetch('https://ratelimit.internal/attempt', {
        method: 'POST', body: JSON.stringify({ key }),
      }).catch(() => null);
      if (!response?.ok) {
        await refundReservations();
        return jsonError('Login rate limiter unavailable', 503);
      }
      const check = await response.json<any>();
      if (!check.allowed) {
        await refundReservations();
        await recordAuditEvent({ action: 'LOGIN_LOCKED', resourceType: 'user', sourceIp: clientIp,
          userAgent, result: 'denied', metadata: { username, lockoutTtl: check.lockoutTtl } }, env.DB);
        return jsonError('Too many login attempts. Please try again later', 429);
      }
      reservations.push({ key, stub, reservationId: check.reservationId });
      if (check.remaining === 0) exhaustedScopes.push(key.startsWith('ip:') ? 'ip' : 'username');
    }

    try {
      const loginResult = await login(
        {
          username: body.username,
          password: body.password,
          totpCode: body.totpCode,
          recoveryCode: body.recoveryCode,
          mfaChallenge: path === '/api/auth/mfa' ? body.challengeToken : undefined,
          clientIp,
          userAgent,
        },
        env
      );

      if (loginResult.mfaRequired) {
        return jsonResponse({
          mfaRequired: true,
          userId: loginResult.userId,
          username: loginResult.username,
          challengeToken: loginResult.challengeToken,
        });
      }

      for (const { key, stub } of rateStubs) {
        await stub.fetch('https://ratelimit.internal/reset', { method: 'POST', body: JSON.stringify({ key }) });
      }
      return jsonResponse(
        {
          mfaRequired: false,
          mfaSetupRequired: loginResult.mfaSetupRequired,
          user: loginResult.user,
          roles: loginResult.roles,
          permissions: loginResult.permissions,
        },
        200,
        { 'Set-Cookie': loginResult.cookie }
      );
    } catch (err: any) {
      if (err instanceof PasswordKdfUnavailableError) {
        await refundReservations();
        await recordAuditEvent({ action: 'AUTH_SERVICE_UNAVAILABLE', resourceType: 'system', sourceIp: clientIp,
          userAgent, result: 'failure', metadata: { service: 'password_kdf' } }, env.DB);
        return jsonError(err.message, 503);
      }
      if (exhaustedScopes.length) await recordAuditEvent({ action: 'LOGIN_LOCKED', resourceType: 'user', sourceIp: clientIp,
        userAgent, result: 'denied', metadata: { username, scopes: exhaustedScopes, reason: 'attempt_limit_reached' } }, env.DB);
      return jsonError(err.message || 'Login failed', 401);
    }
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const token = extractSessionToken(request);
    if (token) {
      await logout(token, env.DB, undefined, clientIp, userAgent);
    }
    return jsonResponse(
      { success: true },
      200,
      { 'Set-Cookie': buildClearSessionCookie() }
    );
  }

  // --- AUTHENTICATION REQUIRED FOR ALL SUBSEQUENT ROUTES ---
  const token = extractSessionToken(request);
  if (!token) {
    return jsonError('Authentication required', 401);
  }

  const currentUser = await validateSession(token, env.DB);
  if (!currentUser) {
    return jsonResponse({ error: 'Invalid or expired session' }, 401, { 'Set-Cookie': buildClearSessionCookie() });
  }

  // --- 3. CURRENT USER & VISIBLE ASSETS ---
  if (path === '/api/me' && method === 'GET') {
    return jsonResponse({
      user: {
        id: currentUser.id,
        username: currentUser.username,
        displayName: currentUser.displayName,
        email: currentUser.email,
        roles: currentUser.roles,
        mfaEnabled: currentUser.mfaEnabled,
        mfaPending: currentUser.mfaPending,
        mfaRequired: await isMfaRequired(currentUser.id, env.DB),
      },
      permissions: currentUser.mfaPending ? [] : Array.from(currentUser.permissions),
      deployType: env.DEPLOY_TYPE || 'production',
    });
  }

  const audit = async (action: string, resourceType: string, resourceId: string, resourceName?: string, metadata?: Record<string, unknown>) =>
    recordAuditEvent({ actorUserId: currentUser.id, actorUsername: currentUser.username, action, resourceType,
      resourceId, resourceName, sourceIp: clientIp, userAgent, result: 'success', metadata }, env.DB);
  const context = { sourceIp: clientIp, userAgent };

  if (method === 'POST' && ['/api/auth/mfa/confirm', '/api/auth/mfa/disable'].includes(path)) {
    const key = `mfa:${currentUser.id}`;
    const response = await env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(key)).fetch('https://ratelimit.internal/attempt', {
      method: 'POST', body: JSON.stringify({ key }),
    });
    if (!response.ok) return jsonError('MFA rate limiter unavailable', 503);
    if (!(await response.json<any>()).allowed) return jsonError('Too many MFA attempts. Please try again later', 429);
  }

  if (path === '/api/auth/mfa/setup' && method === 'POST') {
    return jsonResponse(await setupMfa(currentUser.id, env));
  }
  if (path === '/api/auth/mfa/confirm' && method === 'POST') {
    const body = await request.json<any>();
    if (!await confirmMfa(currentUser.id, body.code, env, clientIp, userAgent)) return jsonError('Invalid TOTP code', 400);
    await env.DB.prepare('UPDATE auth_sessions SET mfa_pending = 0 WHERE token_hash = ?').bind(await hashToken(token)).run();
    await env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(`mfa:${currentUser.id}`)).fetch('https://ratelimit.internal/reset', {
      method: 'POST', body: JSON.stringify({ key: `mfa:${currentUser.id}` }),
    });
    return jsonResponse({ success: true });
  }
  if (path === '/api/auth/mfa/disable' && method === 'POST') {
    if (await isMfaRequired(currentUser.id, env.DB)) return jsonError('MFA is required by policy', 403);
    const body = await request.json<any>();
    if (!await verifyMfaProof(currentUser.id, body.password, body.code, env)) return jsonError('Invalid password or TOTP code', 403);
    await disableMfa(currentUser.id, env.DB, clientIp, userAgent);
    return jsonResponse({ success: true });
  }
  if (currentUser.mfaPending) return jsonError('MFA enrollment is required', 403);

  // User-facing Authorized Assets (JumpServer Dynamic Visibility Resolver)
  if (path === '/api/assets' && method === 'GET') {
    const assets = await getAuthorizedAssetsForUser(currentUser.id, env.DB);
    return jsonResponse(assets);
  }

  const accountsMatch = path.match(/^\/api\/assets\/([^\/]+)\/accounts$/);
  if (accountsMatch && method === 'GET') {
    const assetId = accountsMatch[1];
    const assets = await getAuthorizedAssetsForUser(currentUser.id, env.DB);
    const targetAsset = assets.find((a) => a.id === assetId);
    return jsonResponse(targetAsset ? targetAsset.accounts : []);
  }

  const visibleAssetMatch = path.match(/^\/api\/assets\/([^/]+)$/);
  if (visibleAssetMatch && method === 'GET') {
    const asset = (await getAuthorizedAssetsForUser(currentUser.id, env.DB)).find((asset) => asset.id === visibleAssetMatch[1]);
    return asset ? jsonResponse(asset) : jsonError('Asset not found', 404);
  }
  if (path === '/api/groups' && method === 'GET') {
    const assets = await getAuthorizedAssetsForUser(currentUser.id, env.DB);
    const groups = new Map(assets.flatMap((asset) => asset.groups ?? []).map((group) => [group.id, group]));
    return jsonResponse([...groups.values()]);
  }
  const visibleAccountMatch = path.match(/^\/api\/accounts\/([^/]+)$/);
  if (visibleAccountMatch && method === 'GET') {
    const assets = await getAuthorizedAssetsForUser(currentUser.id, env.DB);
    const account = assets.flatMap((asset) => asset.accounts).find((account) => account.id === visibleAccountMatch[1]);
    return account ? jsonResponse(account) : jsonError('Account not found', 404);
  }
  if (path === '/api/sessions' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.SESSION_VIEW_OWN)) return jsonError('Permission denied', 403);
    return jsonResponse(await listHistoricalSessions(env.DB, { userId: currentUser.id, includeActive: true }));
  }
  const ownSessionMatch = path.match(/^\/api\/sessions\/([^/]+)(?:\/(resume-ticket|disconnect))?$/);
  if (ownSessionMatch) {
    if (!hasPermission(currentUser.permissions, Permissions.SESSION_VIEW_OWN)) return jsonError('Permission denied', 403);
    const session = await getSessionDetail(ownSessionMatch[1], env.DB);
    if (!session || session.user_id !== currentUser.id) return jsonError('Session not found', 404);
    if (method === 'GET' && !ownSessionMatch[2]) return jsonResponse(await getSession(session.id, env.DB));
    if (method === 'POST' && ownSessionMatch[2] === 'disconnect') {
      await terminateSession(session.id, currentUser.id, env, 'Client disconnected', { ...context, clientClosed: true });
      return jsonResponse({ success: true });
    }
    if (method === 'POST' && ownSessionMatch[2] === 'resume-ticket') {
      if (!['connecting', 'active'].includes(session.status)) return jsonError('Session is offline', 409);
      const stub = env.SSH_SESSIONS.get(env.SSH_SESSIONS.idFromName(session.id));
      const response = await stub.fetch(new Request('https://session.internal/ticket', { method: 'POST', headers: { 'x-user-id': currentUser.id } }));
      if (!response.ok) return jsonError('Session cannot be resumed', 409);
      const { ticket, expiresAt } = await response.json<any>();
      return jsonResponse({ sessionId: session.id, ticket, expiresAt, wsUrl: `/api/sessions/${session.id}/ws?ticket=${encodeURIComponent(ticket)}` });
    }
  }

  // --- 4. SESSIONS (CREATE, CONNECT WS, DISCONNECT) ---
  if (path === '/api/sessions' && method === 'POST') {
    const body = await request.json<any>().catch(() => ({}));
    if (!body.assetId || !body.accountId) {
      return jsonError('assetId and accountId are required', 400);
    }

    try {
      const ticketResult = await createSession(
        currentUser.id,
        body.assetId,
        body.accountId,
        clientIp,
        userAgent ?? null,
        env
      );
      return jsonResponse(ticketResult, 201);
    } catch (err: any) {
      return jsonError(err.message || 'Failed to create session', 403);
    }
  }

  // WebSocket Upgrade for Terminal
  const wsMatch = path.match(/^\/api\/sessions\/([^\/]+)\/ws$/);
  if (wsMatch) {
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return jsonError('WebSocket upgrade required', 426);
    }
    if (!hasValidWebSocketOrigin(request)) {
      return jsonError('Invalid WebSocket origin', 403);
    }
    const sessionId = wsMatch[1];
    const ticket = url.searchParams.get('ticket');
    if (!ticket) {
      return jsonError('Missing session ticket', 401);
    }

    const session = await getSessionDetail(sessionId, env.DB);
    const payload = parseTicketPayload(ticket);
    if (!session || session.user_id !== currentUser.id || !['creating', 'connecting', 'active'].includes(session.status) ||
      !env.SESSION_TICKET_SECRET || !await verifyTicket(new TextEncoder().encode(env.SESSION_TICKET_SECRET), ticket) ||
      payload?.sessionId !== sessionId || payload?.userId !== currentUser.id ||
      payload?.assetId !== session.asset_id || payload?.accountId !== session.account_id) {
      return jsonError('Invalid session ticket', 403);
    }
    const doId = env.SSH_SESSIONS.idFromName(sessionId);

    const stub = env.SSH_SESSIONS.get(doId);
    const headers = new Headers(request.headers);
    headers.set('x-session-ticket', ticket);
    headers.set('x-client-ip', clientIp);
    headers.set('x-user-id', currentUser.id);

    return stub.fetch(new Request('https://session.internal/connect', { headers }));
  }

  // --- 5. ADMIN MANAGEMENT ROUTES ---

  // Admin Users & Groups CRUD (Section 5, 13, 60, 70)
  if (path === '/api/admin/users' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.USER_READ)) {
      return jsonError('Permission denied', 403);
    }
    const users = await listUsers(env.DB);
    return jsonResponse(users);
  }

  if (path === '/api/admin/users' && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.USER_CREATE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    const user = await createUser(body, currentUser.id, env, clientIp, userAgent);
    return jsonResponse(user, 201);
  }

  const userActionMatch = path.match(/^\/api\/admin\/users\/([^\/]+)(?:\/([^\/]+))?$/);
  if (userActionMatch) {
    const targetUserId = userActionMatch[1];
    const subAction = userActionMatch[2];

    if (!subAction && method === 'PATCH') {
      if (!hasPermission(currentUser.permissions, Permissions.USER_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      await updateUser(targetUserId, body, currentUser.id, env.DB, clientIp, userAgent);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse({ success: true });
    }

    if (subAction === 'disable' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.USER_DISABLE)) {
        return jsonError('Permission denied', 403);
      }
      if (isDemoMode(env) && (await isUserAdministrator(targetUserId, env.DB))) {
        return jsonError('演示模式下禁止禁用管理员账号', 403);
      }
      await disableUser(targetUserId, currentUser.id, env, clientIp, userAgent);
      return jsonResponse({ success: true });
    }

    if (subAction === 'enable' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.USER_DISABLE) && !hasPermission(currentUser.permissions, Permissions.USER_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      await enableUser(targetUserId, currentUser.id, env.DB, clientIp, userAgent);
      return jsonResponse({ success: true });
    }

    if (subAction === 'reset-password' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.USER_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      if (isDemoMode(env) && (await isUserAdministrator(targetUserId, env.DB))) {
        return jsonError('演示模式下禁止修改管理员密码', 403);
      }
      const body = await request.json<any>();
      await resetUserPassword(targetUserId, body.password, currentUser.id, env, clientIp, userAgent);
      return jsonResponse({ success: true });
    }
  }

  // Admin Groups CRUD
  if (path === '/api/admin/groups' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.GROUP_READ)) {
      return jsonError('Permission denied', 403);
    }
    const groups = await listGroups(env.DB);
    return jsonResponse(groups);
  }

  if (path === '/api/admin/groups' && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.GROUP_WRITE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    const group = await createGroup(body, currentUser.id, env.DB, clientIp, userAgent);
    return jsonResponse(group, 201);
  }

  const groupMatch = path.match(/^\/api\/admin\/groups\/([^\/]+)$/);
  if (groupMatch) {
    const groupId = groupMatch[1];
    if (method === 'PATCH') {
      if (!hasPermission(currentUser.permissions, Permissions.GROUP_WRITE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      await updateGroup(groupId, body, currentUser.id, env.DB, clientIp, userAgent);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse({ success: true });
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.GROUP_WRITE)) {
        return jsonError('Permission denied', 403);
      }
      await deleteGroup(groupId, currentUser.id, env.DB, clientIp, userAgent);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse({ success: true });
    }
  }

  // Admin Roles list
  if (path === '/api/admin/roles' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.USER_READ)) {
      return jsonError('Permission denied', 403);
    }
    const roles = await listRoles(env.DB);
    return jsonResponse(roles);
  }

  const rolePermissionMatch = path.match(/^\/api\/admin\/roles\/([^/]+)$/);
  if (rolePermissionMatch && method === 'PATCH') {
    if (!hasPermission(currentUser.permissions, Permissions.SETTINGS_WRITE)) return jsonError('Permission denied', 403);
    if (rolePermissionMatch[1] !== 'role_security_auditor') return jsonError('Only the auditor termination setting is configurable', 400);
    const body = await request.json<any>();
    if (typeof body.canTerminate !== 'boolean') return jsonError('canTerminate must be boolean', 400);
    const permission = await env.DB.prepare("SELECT id FROM permissions WHERE code = 'session.terminate'").first<{ id: string }>();
    if (!permission) return jsonError('Permission not configured', 500);
    if (body.canTerminate) await env.DB.prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)').bind(rolePermissionMatch[1], permission.id).run();
    else await env.DB.prepare('DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?').bind(rolePermissionMatch[1], permission.id).run();
    await audit('ROLE_UPDATED', 'role', rolePermissionMatch[1], 'Security Auditor', { canTerminate: body.canTerminate });
    return jsonResponse({ success: true });
  }

  // Admin Assets CRUD
  if (path === '/api/admin/assets' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.ASSET_READ)) {
      return jsonError('Permission denied', 403);
    }
    const assets = await listAssets(env.DB);
    return jsonResponse(assets);
  }

  if (path === '/api/admin/assets' && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.ASSET_CREATE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    const asset = await createAsset(body, currentUser.id, env.DB);
    await audit('ASSET_CREATED', 'asset', asset.id, asset.name);
    return jsonResponse(asset, 201);
  }

  const adminAssetMatch = path.match(/^\/api\/admin\/assets\/([^\/]+)$/);
  if (adminAssetMatch) {
    const assetId = adminAssetMatch[1];
    if (method === 'PATCH') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      const updated = await updateAsset(assetId, body, env.DB);
      await audit('ASSET_UPDATED', 'asset', assetId, updated.name);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse(updated);
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_DELETE)) {
        return jsonError('Permission denied', 403);
      }
      const asset = await getAsset(assetId, env.DB);
      await deleteAsset(assetId, env.DB);
      await audit('ASSET_DELETED', 'asset', assetId, asset?.name);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse({ success: true });
    }
  }

  // Admin Asset Accounts CRUD
  const adminAccountMatch = path.match(/^\/api\/admin\/assets\/([^\/]+)\/accounts$/);
  if (adminAccountMatch) {
    const assetId = adminAccountMatch[1];
    if (method === 'GET') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_READ)) return jsonError('Permission denied', 403);
      const accounts = await listAssetAccounts(assetId, env.DB);
      return jsonResponse(accounts);
    }
    if (method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_CREATE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      const account = await createAssetAccount({ ...body, assetId }, env.DB);
      await audit('ACCOUNT_CREATED', 'account', account.id, account.username, { assetId });
      return jsonResponse(account, 201);
    }
  }

  const accountDetailMatch = path.match(/^\/api\/admin\/assets\/([^/]+)\/accounts\/([^/]+)$/);
  if (accountDetailMatch) {
    const [, assetId, accountId] = accountDetailMatch;
    if (!hasPermission(currentUser.permissions, method === 'DELETE' ? Permissions.CREDENTIAL_DELETE : Permissions.CREDENTIAL_REPLACE)) return jsonError('Permission denied', 403);
    const accounts = await listAssetAccounts(assetId, env.DB);
    const account = accounts.find((account) => account.id === accountId);
    if (!account) return jsonError('Account not found', 404);
    if (method === 'PATCH') {
      const updated = await updateAssetAccount(accountId, await request.json<any>(), env.DB);
      await audit('ACCOUNT_UPDATED', 'account', accountId, updated.username, { assetId });
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse(updated);
    }
    if (method === 'DELETE') {
      await deleteAssetAccount(accountId, env.DB);
      await audit('ACCOUNT_DELETED', 'account', accountId, account.username, { assetId });
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse({ success: true });
    }
  }
  const assetGroupMatch = path.match(/^\/api\/admin\/asset-groups\/([^/]+)$/);
  if (assetGroupMatch) {
    if (!hasPermission(currentUser.permissions, method === 'DELETE' ? Permissions.ASSET_DELETE : Permissions.ASSET_UPDATE)) return jsonError('Permission denied', 403);
    if (method === 'PATCH') {
      const group = await updateAssetGroup(assetGroupMatch[1], await request.json<any>(), env.DB);
      await audit('ASSET_GROUP_UPDATED', 'asset_group', assetGroupMatch[1], group.name);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse(group);
    }
    if (method === 'DELETE') {
      await deleteAssetGroup(assetGroupMatch[1], env.DB);
      await audit('ASSET_GROUP_DELETED', 'asset_group', assetGroupMatch[1]);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse({ success: true });
    }
  }

  // Admin Asset Groups CRUD
  if (path === '/api/admin/asset-groups' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.ASSET_READ)) return jsonError('Permission denied', 403);
    const groups = await listAssetGroups(env.DB);
    return jsonResponse(groups);
  }

  if (path === '/api/admin/asset-groups' && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.ASSET_CREATE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    const group = await createAssetGroup(body, env.DB);
    await audit('ASSET_GROUP_CREATED', 'asset_group', group.id, group.name);
    return jsonResponse(group, 201);
  }

  // Admin Credentials (Envelope Encrypted, Write-Only / Replace-Only)
  if (path === '/api/admin/credentials' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_CREATE)) {
      return jsonError('Permission denied', 403);
    }
    const credentials = await listCredentials(env.DB);
    return jsonResponse(credentials);
  }

  if (path === '/api/admin/credentials' && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_CREATE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    if (!env.CREDENTIAL_KEK_V1) return jsonError('Master KEK is not configured on server', 500);
    const credential = await createCredential(body, env.CREDENTIAL_KEK_V1, env.DB);
    await audit('CREDENTIAL_CREATED', 'credential', credential.id, credential.name);
    return jsonResponse(credential, 201);
  }

  const credMatch = path.match(/^\/api\/admin\/credentials\/([^\/]+)$/);
  if (credMatch) {
    const credId = credMatch[1];
    if (method === 'PUT') {
      if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_REPLACE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      if (!env.CREDENTIAL_KEK_V1) return jsonError('Master KEK is not configured', 500);
      const updated = await replaceCredential(credId, body.secret, env.CREDENTIAL_KEK_V1, env.DB);
      await audit('CREDENTIAL_REPLACED', 'credential', credId, updated.name);
      return jsonResponse(updated);
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_DELETE)) {
        return jsonError('Permission denied', 403);
      }
      await deleteCredential(credId, env.DB);
      await audit('CREDENTIAL_DELETED', 'credential', credId);
      return jsonResponse({ success: true });
    }
  }

  const rewrapMatch = path.match(/^\/api\/admin\/credentials\/([^/]+)\/rewrap$/);
  if (rewrapMatch && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_REPLACE)) return jsonError('Permission denied', 403);
    const body = await request.json<any>();
    await rewrapCredential(rewrapMatch[1], body.version, env);
    await audit('CREDENTIAL_REWRAPPED', 'credential', rewrapMatch[1], undefined, { version: body.version });
    return jsonResponse({ success: true });
  }

  // Admin Authorization Rules (JumpServer Model)
  if (path === '/api/admin/authorization-options' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.AUTHORIZATION_WRITE)) return jsonError('Permission denied', 403);
    const users = await env.DB.prepare('SELECT id, username, display_name AS displayName FROM users WHERE status = ?').bind('active').all();
    const groups = await env.DB.prepare('SELECT id, name FROM groups ORDER BY name').all();
    return jsonResponse({ users: users.results, groups: groups.results });
  }
  if (path === '/api/admin/authorizations' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.AUTHORIZATION_READ)) {
      return jsonError('Permission denied', 403);
    }
    const rules = await listAuthorizationRules(env.DB);
    return jsonResponse(rules);
  }

  if (path === '/api/admin/authorizations' && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.AUTHORIZATION_WRITE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    const rule = await createAuthorizationRule(body, currentUser.id, env.DB);
    await audit('AUTHORIZATION_CREATED', 'authorization', rule.id, rule.name, { allAccounts: rule.allAccounts });
    return jsonResponse(rule, 201);
  }

  const authRuleMatch = path.match(/^\/api\/admin\/authorizations\/([^\/]+)$/);
  if (authRuleMatch) {
    const ruleId = authRuleMatch[1];
    if (method === 'PATCH') {
      if (!hasPermission(currentUser.permissions, Permissions.AUTHORIZATION_WRITE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      const updated = await updateAuthorizationRule(ruleId, body, env.DB);
      await audit('AUTHORIZATION_UPDATED', 'authorization', ruleId, updated.name, { allAccounts: updated.allAccounts });
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse(updated);
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.AUTHORIZATION_WRITE)) {
        return jsonError('Permission denied', 403);
      }
      await deleteAuthorizationRule(ruleId, env.DB);
      await audit('AUTHORIZATION_DELETED', 'authorization', ruleId);
      await enforcePermissionRevocation(env, currentUser.id, context);
      return jsonResponse({ success: true });
    }
  }

  // Admin Online & Historical Sessions
  if (path === '/api/admin/sessions' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.SESSION_VIEW_ALL)) {
      return jsonError('Permission denied', 403);
    }
    const mode = url.searchParams.get('type') ?? 'online';
    if (mode === 'historical') {
      const sessions = await listHistoricalSessions(env.DB);
      return jsonResponse(sessions);
    } else {
      const sessions = await listOnlineSessions(env.DB);
      return jsonResponse(sessions);
    }
  }

  // Admin Force Terminate
  const adminTermMatch = path.match(/^\/api\/admin\/sessions\/([^\/]+)\/terminate$/);
  if (adminTermMatch && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.SESSION_TERMINATE)) {
      return jsonError('Permission denied', 403);
    }
    const sessionId = adminTermMatch[1];
    await terminateSession(sessionId, currentUser.id, env, 'Terminated by administrator', context);
    return jsonResponse({ success: true });
  }

  // Admin Live Monitor WebSocket Upgrade
  const adminMonitorMatch = path.match(/^\/api\/admin\/sessions\/([^\/]+)\/monitor$/);
  if (adminMonitorMatch) {
    if (!hasPermission(currentUser.permissions, Permissions.SESSION_MONITOR)) {
      return jsonError('Permission denied', 403);
    }
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return jsonError('WebSocket upgrade required', 426);
    }
    if (!hasValidWebSocketOrigin(request)) return jsonError('Invalid WebSocket origin', 403);

    const sessionId = adminMonitorMatch[1];
    const session = await getSessionDetail(sessionId, env.DB);
    if (!session || !['connecting', 'active'].includes(session.status)) return jsonError('Session is offline', 409);
    const doId = env.SSH_SESSIONS.idFromName(sessionId);

    const stub = env.SSH_SESSIONS.get(doId);
    const headers = new Headers(request.headers);
    headers.set('x-user-id', currentUser.id);
    return stub.fetch(new Request('https://session.internal/monitor', { headers }));
  }

  // Host Key Management (Section 39, 41, 42)
  const hostKeyMatch = path.match(/^\/api\/admin\/assets\/([^\/]+)\/host-key(?:\/([^\/]+))?$/);
  if (hostKeyMatch) {
    const assetId = hostKeyMatch[1];
    const subAction = hostKeyMatch[2];

    if (!subAction && method === 'GET') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_READ)) {
        return jsonError('Permission denied', 403);
      }
      const hostKey = await listHostKeysForAsset(assetId, env.DB);
      return jsonResponse(hostKey ?? null);
    }

    if (subAction === 'approve' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_UPDATE)) return jsonError('Permission denied', 403);
      const body = await request.json<any>();
      await approveHostKeyForAsset(assetId, body.algorithm, body.fingerprint, currentUser.id, env.DB);
      await audit('HOST_KEY_APPROVED', 'host_key', assetId, undefined, { algorithm: body.algorithm, fingerprint: body.fingerprint });
      return jsonResponse({ success: true });
    }

    if (subAction === 'reset' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      await resetHostKeyForAsset(assetId, currentUser.id, env.DB);
      await audit('HOST_KEY_RESET', 'host_key', assetId);
      return jsonResponse({ success: true });
    }
  }

  // Session Details, Commands & Recording (Section 56, 73)
  const recordingChunkMatch = path.match(/^\/api\/admin\/sessions\/([^/]+)\/recording\/(\d+)$/);
  if (recordingChunkMatch && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.AUDIT_READ) && !hasPermission(currentUser.permissions, Permissions.SESSION_VIEW_ALL)) return jsonError('Permission denied', 403);
    const events = await getSessionRecordingChunk(recordingChunkMatch[1], Number(recordingChunkMatch[2]), env);
    return events ? jsonResponse(events) : jsonError('Recording not found', 404);
  }
  const sessionDetailMatch = path.match(/^\/api\/admin\/sessions\/([^\/]+)(?:\/([^\/]+))?$/);
  if (sessionDetailMatch) {
    const sessionId = sessionDetailMatch[1];
    const subAction = sessionDetailMatch[2];

    if (!subAction && method === 'GET') {
      if (!hasPermission(currentUser.permissions, Permissions.SESSION_VIEW_ALL)) {
        return jsonError('Permission denied', 403);
      }
      const session = await getSessionDetail(sessionId, env.DB);
      if (!session) return jsonError('Session not found', 404);
      return jsonResponse(session);
    }

    if (subAction === 'commands' && method === 'GET') {
      if (
        !hasPermission(currentUser.permissions, Permissions.AUDIT_READ) &&
        !hasPermission(currentUser.permissions, Permissions.SESSION_VIEW_ALL)
      ) {
        return jsonError('Permission denied', 403);
      }
      const commands = await getSessionCommands(sessionId, env.DB);
      return jsonResponse(commands);
    }

    if (subAction === 'recording' && method === 'GET') {
      if (
        !hasPermission(currentUser.permissions, Permissions.AUDIT_READ) &&
        !hasPermission(currentUser.permissions, Permissions.SESSION_VIEW_ALL)
      ) {
        return jsonError('Permission denied', 403);
      }
      const storage = getRecordingStorage(env);
      if (!storage) {
        return jsonError('Session recording replay is not available (Neither R2 nor S3/B2 storage is configured)', 404);
      }
      const recording = await getSessionRecording(sessionId, env);
      if (!recording) return jsonError('Recording not found', 404);
      return jsonResponse({ manifest: recording, integrity: 'verified' });
    }
  }

  // System Settings (Section 45, 60, 61)
  if (path === '/api/admin/settings' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.SETTINGS_READ)) {
      return jsonError('Permission denied', 403);
    }
    const settings = await getAllSettings(env.DB);
    return jsonResponse(settings);
  }

  if (path === '/api/admin/settings' && method === 'PATCH') {
    if (!hasPermission(currentUser.permissions, Permissions.SETTINGS_WRITE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    if (typeof body.key !== 'string' || typeof body.value !== 'string') {
      return jsonError('key and value strings are required', 400);
    }
    if (isDemoMode(env) && body.key === 'recording_retention_days') {
      return jsonError('演示模式下禁止修改录像保留时间', 403);
    }
    await updateSetting(body.key, body.value, currentUser.id, env.DB, clientIp, userAgent);
    return jsonResponse({ success: true });
  }

  // Admin Manual Recording Retention Cleanup Trigger
  if (path === '/api/admin/recordings/cleanup' && method === 'POST') {
    if (
      !hasPermission(currentUser.permissions, Permissions.SETTINGS_WRITE)
    ) {
      return jsonError('Permission denied', 403);
    }
    const result = await cleanupExpiredRecordings(env, 'manual', { actorUserId: currentUser.id, actorUsername: currentUser.username, ...context });
    return jsonResponse(result);
  }

  // Admin Audit Log Viewer
  if (path === '/api/admin/audit' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.AUDIT_READ)) {
      return jsonError('Permission denied', 403);
    }
    const limit = Number(url.searchParams.get('limit') ?? 50);
    const events = await listAuditEvents(env.DB, { limit, resourceId: url.searchParams.get('resourceId') ?? undefined });
    return jsonResponse(events);
  }

  return jsonError('Not found', 404);
}
