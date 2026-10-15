import type { AuditEventRow } from '../types.ts';
import type { AuditEventSummary } from '../shared/types.ts';

export interface CreateAuditEventInput {
  actorUserId?: string | null;
  actorUsername?: string | null;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  resourceName?: string | null;
  sourceIp: string;
  userAgent?: string | null;
  result: 'success' | 'failure' | 'denied';
  metadata?: Record<string, unknown> | null;
}

const SENSITIVE_KEY_PATTERNS = [
  /pass/i,
  /secret/i,
  /token/i,
  /key/i,
  /dek/i,
  /kek/i,
  /cipher/i,
  /salt/i,
  /pepper/i,
  /totp/i,
  /cookie/i,
  /credential.*plain/i,
  /authorization/i,
];

/**
 * Recursively sanitize metadata object to ensure no sensitive credentials,
 * passwords, keys, or tokens are ever logged into audit_events per AGENTS.md.
 */
export function sanitizeAuditMetadata(val: unknown): unknown {
  if (val === null || val === undefined) return val;
  if (typeof val !== 'object') return val;

  if (Array.isArray(val)) {
    return val.map(sanitizeAuditMetadata);
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(val as Record<string, unknown>)) {
    const isSensitive = SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key));
    if (isSensitive) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof v === 'object' && v !== null) {
      sanitized[key] = sanitizeAuditMetadata(v);
    } else {
      sanitized[key] = v;
    }
  }
  return sanitized;
}

export async function recordAuditEvent(
  event: CreateAuditEventInput,
  db: D1Database
): Promise<string> {
  const id = `audit_${crypto.randomUUID()}`;
  const timestamp = Date.now();

  let metadataJson: string | null = null;
  const actor = event.actorUsername === undefined && event.actorUserId
    ? await db.prepare('SELECT username FROM users WHERE id = ?').bind(event.actorUserId).first<{ username: string }>() : null;
  if (event.metadata) {
    const cleanMeta = sanitizeAuditMetadata(event.metadata);
    metadataJson = JSON.stringify(cleanMeta);
  }

  await db
    .prepare(
      `INSERT INTO audit_events (
        id, timestamp, actor_user_id, actor_username_snapshot,
        action, resource_type, resource_id, resource_name_snapshot,
        source_ip, user_agent, result, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      timestamp,
      event.actorUserId ?? null,
      event.actorUsername ?? actor?.username ?? 'system',
      event.action,
      event.resourceType,
      event.resourceId ?? null,
      event.resourceName ?? null,
      event.sourceIp,
      event.userAgent ?? null,
      event.result,
      metadataJson
    )
    .run();

  return id;
}

export async function listAuditEvents(
  db: D1Database,
  options: {
    limit?: number;
    offset?: number;
    action?: string;
    actorUserId?: string;
    resourceId?: string;
  } = {}
): Promise<AuditEventSummary[]> {
  const limit = Math.min(options.limit ?? 50, 200);
  const offset = options.offset ?? 0;

  let query = 'SELECT * FROM audit_events';
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.action) {
    conditions.push('action = ?');
    params.push(options.action);
  }
  if (options.actorUserId) {
    conditions.push('actor_user_id = ?');
    params.push(options.actorUserId);
  }
  if (options.resourceId) { conditions.push('resource_id = ?'); params.push(options.resourceId); }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }

  query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const { results } = await db
    .prepare(query)
    .bind(...params)
    .all<AuditEventRow>();

  return (results || []).map((row) => ({
    id: row.id,
    timestamp: row.timestamp,
    actorUserId: row.actor_user_id,
    actorUsername: row.actor_username_snapshot ?? 'unknown',
    action: row.action,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    resourceName: row.resource_name_snapshot,
    sourceIp: row.source_ip,
    result: row.result,
    metadataJson: row.metadata_json,
  }));
}

export async function getAuditEvent(
  id: string,
  db: D1Database
): Promise<AuditEventSummary | null> {
  const row = await db
    .prepare('SELECT * FROM audit_events WHERE id = ?')
    .bind(id)
    .first<AuditEventRow>();

  if (!row) return null;

  return {
    id: row.id,
    timestamp: row.timestamp,
    actorUserId: row.actor_user_id,
    actorUsername: row.actor_username_snapshot ?? 'unknown',
    action: row.action,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    resourceName: row.resource_name_snapshot,
    sourceIp: row.source_ip,
    result: row.result,
    metadataJson: row.metadata_json,
  };
}
