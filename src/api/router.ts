import type { Env, AuthenticatedUser } from '../types.ts';
import {
  jsonResponse,
  jsonError,
  validateCsrfOrigin,
  hasValidWebSocketOrigin,
} from '../http-security.ts';
import {
  login,
  logout,
  validateSession,
  buildSessionCookie,
  buildClearSessionCookie,
  COOKIE_NAME,
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
} from '../assets/asset-service.ts';
import {
  listCredentials,
  createCredential,
  replaceCredential,
  deleteCredential,
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
import { listAuditEvents } from '../audit/audit-service.ts';
import { hasPermission, Permissions } from '../rbac/permissions.ts';

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

  // CSRF validation on mutating HTTP requests
  if (!validateCsrfOrigin(request)) {
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
      },
      env
    );
    return jsonResponse({ success: true, user: result.user }, 201);
  }

  // Check if bootstrap is needed
  if (path === '/api/auth/bootstrap/status' && method === 'GET') {
    const needed = await isBootstrapNeeded(env.DB);
    return jsonResponse({ bootstrapNeeded: needed });
  }

  // --- 2. AUTHENTICATION (LOGIN, LOGOUT) ---
  if (path === '/api/auth/login' && method === 'POST') {
    const body = await request.json<any>().catch(() => ({}));
    if (!body.username || !body.password) {
      return jsonError('Username and password are required', 400);
    }

    // Rate Limiting check via RateLimitDO
    const rateLimitKey = `${clientIp}:${body.username}`;
    const rateLimitStub = env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(rateLimitKey));
    const rateCheckRes = await rateLimitStub.fetch('https://ratelimit.internal/check', {
      method: 'POST',
      body: JSON.stringify({ ip: clientIp, username: body.username }),
    });
    const rateCheck = await rateCheckRes.json<any>().catch(() => ({ allowed: true }));
    if (!rateCheck.allowed) {
      return jsonError(
        `Too many failed login attempts. Please try again in ${rateCheck.lockoutTtl} seconds`,
        429
      );
    }

    try {
      const loginResult = await login(
        {
          username: body.username,
          password: body.password,
          totpCode: body.totpCode,
          recoveryCode: body.recoveryCode,
          clientIp,
          userAgent,
        },
        env
      );

      // Reset rate limit on success
      await rateLimitStub.fetch('https://ratelimit.internal/reset', {
        method: 'POST',
        body: JSON.stringify({ ip: clientIp, username: body.username }),
      });

      if (loginResult.mfaRequired) {
        return jsonResponse({
          mfaRequired: true,
          userId: loginResult.userId,
          username: loginResult.username,
        });
      }

      return jsonResponse(
        {
          mfaRequired: false,
          user: loginResult.user,
          roles: loginResult.roles,
          permissions: loginResult.permissions,
        },
        200,
        { 'Set-Cookie': loginResult.cookie }
      );
    } catch (err: any) {
      // Record failure on rate limit
      await rateLimitStub.fetch('https://ratelimit.internal/fail', {
        method: 'POST',
        body: JSON.stringify({ ip: clientIp, username: body.username }),
      });
      return jsonError(err.message || 'Login failed', 401);
    }
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const token = extractSessionToken(request);
    if (token) {
      await logout(token, env.DB, undefined, clientIp);
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
    return jsonError('Invalid or expired session', 401, {
      headers: { 'Set-Cookie': buildClearSessionCookie() },
    });
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
      },
      permissions: Array.from(currentUser.permissions),
    });
  }

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

    let doId: DurableObjectId;
    try {
      doId = env.SSH_SESSIONS.idFromString(sessionId);
    } catch {
      return jsonError('Invalid session identifier', 400);
    }

    const stub = env.SSH_SESSIONS.get(doId);
    const headers = new Headers(request.headers);
    headers.set('x-session-ticket', ticket);
    headers.set('x-client-ip', clientIp);
    headers.set('x-user-id', currentUser.id);

    return stub.fetch(new Request('https://session.internal/connect', { headers }));
  }

  const disconnectMatch = path.match(/^\/api\/sessions\/([^\/]+)\/disconnect$/);
  if (disconnectMatch && method === 'POST') {
    const sessionId = disconnectMatch[1];
    await terminateSession(sessionId, currentUser.id, env, 'Client disconnected');
    return jsonResponse({ success: true });
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
    const user = await createUser(body, currentUser.id, env);
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
      await updateUser(targetUserId, body, currentUser.id, env.DB);
      return jsonResponse({ success: true });
    }

    if (subAction === 'disable' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.USER_DISABLE)) {
        return jsonError('Permission denied', 403);
      }
      await disableUser(targetUserId, currentUser.id, env);
      return jsonResponse({ success: true });
    }

    if (subAction === 'enable' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.USER_DISABLE) && !hasPermission(currentUser.permissions, Permissions.USER_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      await enableUser(targetUserId, currentUser.id, env.DB);
      return jsonResponse({ success: true });
    }

    if (subAction === 'reset-password' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.USER_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      await resetUserPassword(targetUserId, body.password, currentUser.id, env);
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
    const group = await createGroup(body, currentUser.id, env.DB);
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
      await updateGroup(groupId, body, currentUser.id, env.DB);
      return jsonResponse({ success: true });
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.GROUP_WRITE)) {
        return jsonError('Permission denied', 403);
      }
      await deleteGroup(groupId, currentUser.id, env.DB);
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
      return jsonResponse(updated);
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_DELETE)) {
        return jsonError('Permission denied', 403);
      }
      await deleteAsset(assetId, env.DB);
      return jsonResponse({ success: true });
    }
  }

  // Admin Asset Accounts CRUD
  const adminAccountMatch = path.match(/^\/api\/admin\/assets\/([^\/]+)\/accounts$/);
  if (adminAccountMatch) {
    const assetId = adminAccountMatch[1];
    if (method === 'GET') {
      const accounts = await listAssetAccounts(assetId, env.DB);
      return jsonResponse(accounts);
    }
    if (method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_CREATE)) {
        return jsonError('Permission denied', 403);
      }
      const body = await request.json<any>();
      const account = await createAssetAccount({ ...body, assetId }, env.DB);
      return jsonResponse(account, 201);
    }
  }

  // Admin Asset Groups CRUD
  if (path === '/api/admin/asset-groups' && method === 'GET') {
    const groups = await listAssetGroups(env.DB);
    return jsonResponse(groups);
  }

  if (path === '/api/admin/asset-groups' && method === 'POST') {
    if (!hasPermission(currentUser.permissions, Permissions.ASSET_CREATE)) {
      return jsonError('Permission denied', 403);
    }
    const body = await request.json<any>();
    const group = await createAssetGroup(body, env.DB);
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
      return jsonResponse(updated);
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.CREDENTIAL_DELETE)) {
        return jsonError('Permission denied', 403);
      }
      await deleteCredential(credId, env.DB);
      return jsonResponse({ success: true });
    }
  }

  // Admin Authorization Rules (JumpServer Model)
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
      return jsonResponse(updated);
    }
    if (method === 'DELETE') {
      if (!hasPermission(currentUser.permissions, Permissions.AUTHORIZATION_WRITE)) {
        return jsonError('Permission denied', 403);
      }
      await deleteAuthorizationRule(ruleId, env.DB);
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
    await terminateSession(sessionId, currentUser.id, env, 'Terminated by administrator');
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
    let doId: DurableObjectId;
    try {
      doId = env.SSH_SESSIONS.idFromString(sessionId);
    } catch {
      return jsonError('Invalid session identifier', 400);
    }

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
      const hostKey = await getHostKeyForAsset(assetId, env.DB);
      return jsonResponse(hostKey ?? null);
    }

    if (subAction === 'reset' && method === 'POST') {
      if (!hasPermission(currentUser.permissions, Permissions.ASSET_UPDATE)) {
        return jsonError('Permission denied', 403);
      }
      await resetHostKeyForAsset(assetId, currentUser.id, env.DB);
      return jsonResponse({ success: true });
    }
  }

  // Session Details, Commands & Recording (Section 56, 73)
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
      const recording = await getSessionRecording(sessionId, env);
      if (!recording) return jsonError('Recording not found', 404);
      return jsonResponse(recording);
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
    await updateSetting(body.key, body.value, currentUser.id, env.DB);
    return jsonResponse({ success: true });
  }

  // Admin Audit Log Viewer
  if (path === '/api/admin/audit' && method === 'GET') {
    if (!hasPermission(currentUser.permissions, Permissions.AUDIT_READ)) {
      return jsonError('Permission denied', 403);
    }
    const limit = Number(url.searchParams.get('limit') ?? 50);
    const events = await listAuditEvents(env.DB, { limit });
    return jsonResponse(events);
  }

  return jsonError('Not found', 404);
}
