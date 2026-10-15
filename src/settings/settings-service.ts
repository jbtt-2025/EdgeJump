// System Settings Management Service

import type { SystemSettingRow } from '../types.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';

export const DEFAULT_SETTINGS: Record<string, string> = {
  session_idle_timeout: '1800', // 30 minutes in seconds
  session_max_duration: '28800', // 8 hours in seconds
  terminate_active_sessions_on_disable: 'true',
  terminate_sessions_on_permission_revocation: 'false',
  require_mfa_for_all: 'false',
  auth_session_absolute_ttl: '28800',
  auth_session_idle_ttl: '1800',
  disconnect_on_browser_close: 'true',
  recording_retention_days: '0', // Infrastructure retention is preferred; application deletion is opt-in.
};

/**
 * Gets a specific setting value or fallback.
 */
export async function getSetting(
  key: string,
  db: D1Database,
  fallback?: string
): Promise<string> {
  const row = await db
    .prepare('SELECT value FROM system_settings WHERE key = ?')
    .bind(key)
    .first<SystemSettingRow>();

  return row?.value ?? fallback ?? DEFAULT_SETTINGS[key] ?? '';
}

/**
 * Retrieves all configured settings merged with defaults.
 */
export async function getAllSettings(db: D1Database): Promise<Record<string, string>> {
  const rows = await db.prepare('SELECT key, value FROM system_settings').all<SystemSettingRow>();
  const settings: Record<string, string> = { ...DEFAULT_SETTINGS };

  for (const row of rows.results || []) {
    settings[row.key] = row.value;
  }

  return settings;
}

/**
 * Updates a system setting and records an audit event.
 */
export async function updateSetting(
  key: string,
  value: string,
  actorUserId: string,
  db: D1Database,
  clientIp = '127.0.0.1',
  userAgent?: string
): Promise<void> {
  if (!(key in DEFAULT_SETTINGS)) throw new Error('Unknown system setting');
  if (DEFAULT_SETTINGS[key] === 'true' || DEFAULT_SETTINGS[key] === 'false') {
    if (value !== 'true' && value !== 'false') throw new Error('Setting must be true or false');
  } else if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) ||
    (key !== 'recording_retention_days' && Number(value) < 1)) {
    throw new Error('Setting must be a valid duration');
  }
  const now = Date.now();
  await db
    .prepare(
      'INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by'
    )
    .bind(key, value, now, actorUserId)
    .run();

  await recordAuditEvent(
    {
      actorUserId,
      action: 'SETTING_CHANGED',
      resourceType: 'system_setting',
      resourceId: key,
      sourceIp: clientIp,
      userAgent,
      result: 'success',
      metadata: { key, value },
    },
    db
  );
}
