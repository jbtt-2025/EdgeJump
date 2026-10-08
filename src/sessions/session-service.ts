import type { Env, SSHSessionRow, UserRow, AssetRow, AssetAccountRow } from '../types.ts';
import type {
  SessionTicketResponse,
  OnlineSessionSummary,
  HistoricalSessionSummary,
} from '../shared/types.ts';
import { checkUserAssetAccountAccess } from '../authorization/authorization-service.ts';
import { getDecryptedCredential } from '../credentials/credential-service.ts';
import { createTicket } from '../backend/security.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';

export interface CreateSessionOptions {
  userId: string;
  assetId: string;
  accountId: string;
  clientIp: string;
  userAgent?: string | null;
}

/**
 * Creates an SSH session for an authorized user, asset, and account.
 * Double-checks permissions, decrypts credential in memory, records audit snapshot,
 * dispatches initialization to SSHSessionDO, and issues a short-lived session ticket.
 */
export async function createSession(
  userId: string,
  assetId: string,
  accountId: string,
  clientIp: string,
  userAgent: string | null = null,
  env: Env
): Promise<SessionTicketResponse> {
  // 1. Validate user is active
  const user = await env.DB.prepare('SELECT id, username, status FROM users WHERE id = ?')
    .bind(userId)
    .first<UserRow>();

  if (!user) {
    throw new Error('User not found');
  }
  if (user.status !== 'active') {
    throw new Error(`User account is ${user.status}`);
  }

  // 2. Validate asset is enabled
  const asset = await env.DB.prepare(
    'SELECT id, name, hostname, port, enabled, host_key_policy FROM assets WHERE id = ?'
  )
    .bind(assetId)
    .first<AssetRow>();

  if (!asset) {
    throw new Error('Asset not found');
  }
  if (asset.enabled !== 1) {
    throw new Error('Asset is disabled');
  }

  // 3. Validate account is enabled and bound to asset
  const account = await env.DB.prepare(
    'SELECT id, asset_id, username, credential_id, enabled FROM asset_accounts WHERE id = ?'
  )
    .bind(accountId)
    .first<AssetAccountRow>();

  if (!account) {
    throw new Error('Account not found');
  }
  if (account.asset_id !== assetId) {
    throw new Error('Account does not belong to specified asset');
  }
  if (account.enabled !== 1) {
    throw new Error('Account is disabled');
  }

  // 4. Validate authorization rule (and time window)
  const authResult = await checkUserAssetAccountAccess(
    userId,
    assetId,
    accountId,
    'connect',
    env.DB
  );

  if (!authResult.authorized) {
    await recordAuditEvent(
      {
        actorUserId: user.id,
        actorUsername: user.username,
        action: 'SESSION_DENIED',
        resourceType: 'asset',
        resourceId: asset.id,
        resourceName: asset.name,
        sourceIp: clientIp,
        userAgent,
        result: 'denied',
        metadata: {
          accountId: account.id,
          accountUsername: account.username,
          reason: authResult.reason ?? 'Access denied',
        },
      },
      env.DB
    );
    throw new Error(`Access denied: ${authResult.reason ?? 'Unauthorized'}`);
  }

  // 5. Fetch credential and decrypt with Master KEK
  const masterKek = env.CREDENTIAL_KEK_V1;
  if (!masterKek) {
    throw new Error('CREDENTIAL_KEK_V1 secret is required to decrypt credential');
  }

  const decryptedCred = await getDecryptedCredential(account.credential_id, masterKek, env.DB);

  // 6. Create ssh_sessions record with immutable snapshot fields
  const sessionId = `sess_${crypto.randomUUID()}`;
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO ssh_sessions (
      id, user_id, username_snapshot,
      asset_id, asset_name_snapshot,
      account_id, account_name_snapshot,
      source_ip, user_agent,
      started_at, ended_at, status,
      disconnect_reason, client_closed, terminated_by,
      recording_status, recording_path, recording_hash, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'creating', NULL, 0, NULL, 'none', NULL, NULL, ?)`
  )
    .bind(
      sessionId,
      user.id,
      user.username,
      asset.id,
      asset.name,
      account.id,
      account.username,
      clientIp,
      userAgent,
      now,
      now
    )
    .run();

  // 7. Issue session ticket & dispatch to SSHSessionDO
  const ticketSecret = env.AUTH_PEPPER || env.CREDENTIAL_KEK_V1 || 'default-ticket-secret';
  const ticketSecretBytes = new TextEncoder().encode(ticketSecret);

  const { ticket, expiresAt } = await createTicket(ticketSecretBytes, clientIp, {
    sessionId,
    userId: user.id,
    assetId: asset.id,
    accountId: account.id,
  });

  if (env.SSH_SESSIONS) {
    try {
      const doId = env.SSH_SESSIONS.idFromName(sessionId);
      const stub = env.SSH_SESSIONS.get(doId);
      await stub.fetch(
        new Request('http://internal/init', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sessionId,
            userId: user.id,
            username: user.username,
            asset: {
              id: asset.id,
              name: asset.name,
              hostname: asset.hostname,
              port: asset.port,
              hostKeyPolicy: asset.host_key_policy,
            },
            account: {
              id: account.id,
              username: account.username,
            },
            credential: {
              type: decryptedCred.type,
              plaintext: decryptedCred.plaintext,
            },
            ticket,
            clientIp,
          }),
        })
      );
    } catch (err) {
      console.warn('DO dispatch error:', err);
    }
  }

  // 8. Record audit event
  await recordAuditEvent(
    {
      actorUserId: user.id,
      actorUsername: user.username,
      action: 'SESSION_CREATED',
      resourceType: 'session',
      resourceId: sessionId,
      resourceName: `${asset.name} (${account.username})`,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
      metadata: {
        assetId: asset.id,
        accountId: account.id,
        matchedRuleId: authResult.matchedRuleId,
      },
    },
    env.DB
  );

  return {
    sessionId,
    ticket,
    wsUrl: `/api/sessions/${sessionId}/ws?ticket=${encodeURIComponent(ticket)}`,
    expiresAt,
  };
}

/**
 * Returns session information by ID.
 */
export async function getSession(
  sessionId: string,
  db: D1Database
): Promise<HistoricalSessionSummary | null> {
  const row = await db
    .prepare('SELECT * FROM ssh_sessions WHERE id = ?')
    .bind(sessionId)
    .first<SSHSessionRow>();

  if (!row) return null;

  return {
    id: row.id,
    userId: row.user_id,
    username: row.username_snapshot,
    assetId: row.asset_id,
    assetName: row.asset_name_snapshot,
    accountId: row.account_id,
    accountName: row.account_name_snapshot,
    sourceIp: row.source_ip,
    startedAt: row.started_at,
    status: row.status,
    recordingStatus: row.recording_status,
    endedAt: row.ended_at,
    disconnectReason: row.disconnect_reason,
    recordingPath: row.recording_path,
    recordingHash: row.recording_hash,
  };
}

/**
 * Lists active/online sessions.
 */
export async function listOnlineSessions(db: D1Database): Promise<OnlineSessionSummary[]> {
  const { results } = await db
    .prepare(
      `SELECT * FROM ssh_sessions
       WHERE status IN ('creating', 'connecting', 'active')
       ORDER BY started_at DESC`
    )
    .all<SSHSessionRow>();

  return (results || []).map((row) => ({
    id: row.id,
    userId: row.user_id,
    username: row.username_snapshot,
    assetId: row.asset_id,
    assetName: row.asset_name_snapshot,
    accountId: row.account_id,
    accountName: row.account_name_snapshot,
    sourceIp: row.source_ip,
    startedAt: row.started_at,
    status: row.status,
    recordingStatus: row.recording_status,
  }));
}

/**
 * Lists historical sessions.
 */
export async function listHistoricalSessions(
  db: D1Database,
  options: { limit?: number; offset?: number; userId?: string } = {}
): Promise<HistoricalSessionSummary[]> {
  const limit = Math.min(options.limit ?? 50, 200);
  const offset = options.offset ?? 0;

  let query = 'SELECT * FROM ssh_sessions';
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.userId) {
    conditions.push('user_id = ?');
    params.push(options.userId);
  }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }

  query += ' ORDER BY started_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const { results } = await db.prepare(query).bind(...params).all<SSHSessionRow>();

  return (results || []).map((row) => ({
    id: row.id,
    userId: row.user_id,
    username: row.username_snapshot,
    assetId: row.asset_id,
    assetName: row.asset_name_snapshot,
    accountId: row.account_id,
    accountName: row.account_name_snapshot,
    sourceIp: row.source_ip,
    startedAt: row.started_at,
    status: row.status,
    recordingStatus: row.recording_status,
    endedAt: row.ended_at,
    disconnectReason: row.disconnect_reason,
    recordingPath: row.recording_path,
    recordingHash: row.recording_hash,
  }));
}

/**
 * Force terminates an active session.
 */
export async function terminateSession(
  sessionId: string,
  terminatedBy: string,
  env: Env,
  reason: string = 'Terminated by administrator'
): Promise<void> {
  const now = Date.now();

  const session = await env.DB.prepare('SELECT * FROM ssh_sessions WHERE id = ?')
    .bind(sessionId)
    .first<SSHSessionRow>();

  if (!session) {
    throw new Error('Session not found');
  }

  await env.DB.prepare(
    `UPDATE ssh_sessions SET
      status = 'terminated',
      ended_at = ?,
      disconnect_reason = ?,
      terminated_by = ?
    WHERE id = ?`
  )
    .bind(now, reason, terminatedBy, sessionId)
    .run();

  if (env.SSH_SESSIONS) {
    try {
      const doId = env.SSH_SESSIONS.idFromName(sessionId);
      const stub = env.SSH_SESSIONS.get(doId);
      await stub.fetch(
        new Request('http://internal/terminate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId, terminatedBy, reason }),
        })
      );
    } catch (err) {
      console.warn('DO terminate dispatch error:', err);
    }
  }

  await recordAuditEvent(
    {
      actorUserId: terminatedBy,
      action: 'SESSION_TERMINATED',
      resourceType: 'session',
      resourceId: sessionId,
      resourceName: `${session.asset_name_snapshot} (${session.account_name_snapshot})`,
      sourceIp: '127.0.0.1',
      result: 'success',
      metadata: { reason },
    },
    env.DB
  );
}

/**
 * Gets detailed metadata for a single session.
 */
export async function getSessionDetail(
  sessionId: string,
  db: D1Database
): Promise<SSHSessionRow | null> {
  return db.prepare('SELECT * FROM ssh_sessions WHERE id = ?').bind(sessionId).first<SSHSessionRow>();
}

/**
 * Gets command history for a session from session_commands.
 */
export async function getSessionCommands(
  sessionId: string,
  db: D1Database
): Promise<Array<{ id: string; timestamp: number; command: string; source: string; redacted: boolean }>> {
  const rows = await db
    .prepare('SELECT id, timestamp, command, source, redacted FROM session_commands WHERE session_id = ? ORDER BY timestamp ASC')
    .bind(sessionId)
    .all<{ id: string; timestamp: number; command: string; source: string; redacted: number }>();

  return (rows.results || []).map(r => ({
    id: r.id,
    timestamp: r.timestamp,
    command: r.command,
    source: r.source,
    redacted: r.redacted === 1,
  }));
}

/**
 * Retrieves the session recording manifest and chunks from R2.
 */
export async function getSessionRecording(
  sessionId: string,
  env: Env
): Promise<{ manifest: any; chunks: string[] } | null> {
  const session = await getSessionDetail(sessionId, env.DB);
  if (!session) return null;

  if (!env.RECORDINGS || !session.recording_path || session.recording_status === 'none') {
    return null;
  }

  const prefix = session.recording_path;

  const manifestObj = await env.RECORDINGS.get(`${prefix}/manifest.json`);
  let manifest = null;
  if (manifestObj) {
    try {
      manifest = await manifestObj.json();
    } catch {
      // fallback
    }
  }

  return {
    manifest: manifest ?? { sessionId, finalHash: session.recording_hash },
    chunks: [],
  };
}

