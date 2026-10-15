import { computeChunkHash, computeRollingHash, decompressGzip, type RecordingManifest, type TerminalEvent } from '../durable/recording.ts';
import type { Env, SSHSessionRow, UserRow, AssetRow, AssetAccountRow } from '../types.ts';
import type {
  SessionTicketResponse,
  OnlineSessionSummary,
  HistoricalSessionSummary,
} from '../shared/types.ts';
import { checkUserAssetAccountAccess } from '../authorization/authorization-service.ts';
import { createTicket } from '../backend/security.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';
import { getRecordingStorage } from '../storage/recording-storage.ts';
import { getSetting } from '../settings/settings-service.ts';

export async function enforcePermissionRevocation(
  env: Env, actorId: string, context: { sourceIp?: string; userAgent?: string | null } = {}
): Promise<void> {
  if (await getSetting('terminate_sessions_on_permission_revocation', env.DB) !== 'true') return;
  for (const session of await listOnlineSessions(env.DB)) {
    if (!(await checkUserAssetAccountAccess(session.userId, session.assetId, session.accountId, 'connect', env.DB)).authorized) {
      await terminateSession(session.id, actorId, env, 'Asset permission was revoked', context);
    }
  }
}

export interface CreateSessionOptions {
  userId: string;
  assetId: string;
  accountId: string;
  clientIp: string;
  userAgent?: string | null;
}

/**
 * Creates an SSH session for an authorized user, asset, and account.
 * Double-checks permissions, records audit snapshot,
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

  // Host key changes are blocked before allocating a session or issuing a ticket.
  const blockedKey = await env.DB.prepare("SELECT id FROM ssh_host_keys WHERE asset_id = ? AND status != 'verified'")
    .bind(assetId).first();
  if (blockedKey || asset.host_key_policy === 'approval_required') {
    throw new Error('Host key requires administrator approval');
  }
  if (!env.SESSION_TICKET_SECRET) throw new Error('Session ticket secret is not configured');

  const sessionId = `sess_${crypto.randomUUID()}`;
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO ssh_sessions (
    id, user_id, username_snapshot, asset_id, asset_name_snapshot, account_id, account_name_snapshot,
    source_ip, user_agent, started_at, status, recording_status, created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'creating', 'none', ?)`)
    .bind(sessionId, user.id, user.username, asset.id, asset.name, account.id, account.username,
      clientIp, userAgent, now, now).run();

  const { ticket, expiresAt } = await createTicket(new TextEncoder().encode(env.SESSION_TICKET_SECRET), clientIp, {
    sessionId, userId: user.id, assetId: asset.id, accountId: account.id,
  });
  try {
    const stub = env.SSH_SESSIONS.get(env.SSH_SESSIONS.idFromName(sessionId));
    const response = await stub.fetch(new Request('https://session.internal/init', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, userId: user.id, usernameSnapshot: user.username,
        assetId: asset.id, assetNameSnapshot: asset.name, accountId: account.id,
        accountNameSnapshot: account.username, host: asset.hostname, port: asset.port,
        username: account.username, sourceIp: clientIp, userAgent, ticket, expiresAt, createdAt: now }),
    }));
    if (!response.ok) throw new Error('Session initialization failed');
  } catch {
    await env.DB.prepare("UPDATE ssh_sessions SET status = 'failed', ended_at = ?, disconnect_reason = 'initialization_failed' WHERE id = ?")
      .bind(Date.now(), sessionId).run();
    await recordAuditEvent({ actorUserId: user.id, actorUsername: user.username, action: 'SESSION_FAILED',
      resourceType: 'session', resourceId: sessionId, sourceIp: clientIp, userAgent,
      result: 'failure', metadata: { reason: 'initialization_failed' } }, env.DB);
    throw new Error('Session initialization failed');
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
    exitCode: row.exit_code,
    exitSignal: row.exit_signal,
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
  options: { limit?: number; offset?: number; userId?: string; includeActive?: boolean } = {}
): Promise<HistoricalSessionSummary[]> {
  const limit = Math.min(options.limit ?? 50, 200);
  const offset = options.offset ?? 0;

  let query = 'SELECT * FROM ssh_sessions';
  const conditions: string[] = [];
  const params: unknown[] = [];
  if (!options.includeActive) conditions.push("status IN ('closed', 'failed', 'terminated', 'timeout')");

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
    exitCode: row.exit_code,
    exitSignal: row.exit_signal,
  }));
}

/**
 * Force terminates an active session.
 */
export async function terminateSession(
  sessionId: string,
  terminatedBy: string,
  env: Env,
  reason: string = 'Terminated by administrator',
  context: { sourceIp?: string; userAgent?: string | null; clientClosed?: boolean } = {}
): Promise<void> {
  const session = await getSessionDetail(sessionId, env.DB);
  if (!session) throw new Error('Session not found');
  if (!['creating', 'connecting', 'active'].includes(session.status)) return;
  const actor = await env.DB.prepare('SELECT username FROM users WHERE id = ?').bind(terminatedBy).first<{ username: string }>();
  const stub = env.SSH_SESSIONS.get(env.SSH_SESSIONS.idFromName(sessionId));
  const response = await stub.fetch(new Request('https://session.internal/terminate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ actorId: terminatedBy, actorUsername: actor?.username, reason, ...context }),
  }));
  if (!response.ok) throw new Error('Session termination failed');
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
export async function getSessionRecording(sessionId: string, env: Env): Promise<RecordingManifest | null> {
  const session = await getSessionDetail(sessionId, env.DB);
  const storage = getRecordingStorage(env);
  if (!session || !storage || !session.recording_path || session.recording_status !== 'completed') return null;
  const cleanup = await env.DB.prepare(`SELECT session_id FROM recording_cleanup_jobs WHERE session_id = ?
    AND chunk_count IS NOT NULL AND (next_chunk > 1 OR lease_id IS NOT NULL)`)
    .bind(sessionId).first();
  if (cleanup) return null;
  const object = await storage.get(`${session.recording_path}/manifest.json`);
  if (!object) throw new Error('Recording manifest is missing');
  const manifest = await object.json<RecordingManifest>();
  if (manifest.sessionId !== sessionId || !Number.isSafeInteger(manifest.chunkCount) || manifest.chunkCount < 1 || manifest.chunkCount > 100000) {
    throw new Error('Recording manifest is invalid');
  }
  // Older manifests contain only a final hash; reconstruct their descriptors.
  if (!manifest.chunks) {
    manifest.chunks = [];
    let rolling: string | null = null;
    for (let index = 1; index <= manifest.chunkCount; index++) {
      const path = `${session.recording_path}/chunk-${String(index).padStart(6, '0')}.jsonl.gz`;
      const chunk = await storage.get(path);
      if (!chunk) throw new Error('Recording chunk is missing');
      const hash = await computeChunkHash(new Uint8Array(await chunk.arrayBuffer()));
      rolling = await computeRollingHash(rolling, hash);
      manifest.chunks.push({ index, path, hash, rollingHash: rolling });
    }
  }
  if (manifest.chunks.length !== manifest.chunkCount) throw new Error('Recording chunk count mismatch');
  let rolling: string | null = null;
  for (const [index, chunk] of manifest.chunks.entries()) {
    if (chunk.index !== index + 1 || !/^[a-f0-9]{64}$/.test(chunk.hash)) throw new Error('Recording chunk descriptor is invalid');
    rolling = await computeRollingHash(rolling, chunk.hash);
    if (chunk.rollingHash !== rolling) throw new Error('Recording hash chain mismatch');
    // Never trust object paths from a mutable manifest.
    chunk.path = `${session.recording_path}/chunk-${String(index + 1).padStart(6, '0')}.jsonl.gz`;
  }
  if (rolling !== manifest.finalHash || rolling !== session.recording_hash) throw new Error('Recording integrity check failed');
  return manifest;
}

export async function getSessionRecordingChunk(sessionId: string, index: number, env: Env) {
  const manifest = await getSessionRecording(sessionId, env);
  if (!manifest || !Number.isSafeInteger(index) || index < 1 || index > manifest.chunkCount) return null;
  const descriptor = manifest.chunks![index - 1];
  const object = await getRecordingStorage(env)!.get(descriptor.path);
  if (!object) throw new Error('Recording chunk is missing');
  const bytes = new Uint8Array(await object.arrayBuffer());
  if (await computeChunkHash(bytes) !== descriptor.hash) throw new Error('Recording chunk integrity check failed');
  const text = new TextDecoder().decode(await decompressGzip(bytes));
  return text.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line) as TerminalEvent);
}
