import type { Env } from '../types.ts';
import { getSetting } from '../settings/settings-service.ts';
import { getRecordingStorage } from '../storage/recording-storage.ts';
import { recordAuditEvent, type CreateAuditEventInput } from '../audit/audit-service.ts';

// Leave room under Free's 50 external subrequests for the surrounding invocation.
export const CLEANUP_OBJECT_BUDGET = 40;
const LEASE_MS = 10 * 60_000;

export interface CleanupResult {
  cleanedCount: number;
  expiredSessionIds: string[];
  retentionDays: number;
  storageOperations: number;
  budgetExhausted: boolean;
}

interface CleanupCursor { chunk_count: number | null; next_chunk: number }

/** Deletes bounded object slices; only fully deleted recordings become expired. */
export async function cleanupExpiredRecordings(
  env: Env,
  trigger = 'cron',
  actor: Partial<CreateAuditEventInput> = {}
): Promise<CleanupResult> {
  const retentionDays = parseInt(await getSetting('recording_retention_days', env.DB, '0'), 10) || 0;
  const result: CleanupResult = { cleanedCount: 0, expiredSessionIds: [], retentionDays: Math.max(0, retentionDays), storageOperations: 0, budgetExhausted: false };
  // Cleanup resumes on the next invocation, rather than SDK retries consuming the budget.
  const storage = getRecordingStorage(env, { retries: 0 });
  if (retentionDays <= 0 || !storage) return result;

  const now = Date.now();
  const cutoffMs = now - retentionDays * 86_400_000;
  const { results: sessions } = await env.DB.prepare(
    `SELECT s.id, s.recording_path FROM ssh_sessions s
     LEFT JOIN recording_cleanup_jobs j ON j.session_id = s.id
     WHERE s.recording_status = 'completed' AND s.recording_path IS NOT NULL AND s.recording_path != ''
       AND COALESCE(s.ended_at, s.started_at) < ? AND (j.session_id IS NULL OR j.lease_until <= ?)
     ORDER BY COALESCE(s.ended_at, s.started_at), s.id LIMIT 20`
  ).bind(cutoffMs, now).all<{ id: string; recording_path: string }>();

  for (const session of sessions || []) {
    if (result.storageOperations >= CLEANUP_OBJECT_BUDGET) break;
    await env.DB.prepare('INSERT OR IGNORE INTO recording_cleanup_jobs (session_id) VALUES (?)').bind(session.id).run();
    const leaseId = crypto.randomUUID();
    const cursor = await env.DB.prepare(
      `UPDATE recording_cleanup_jobs SET lease_id = ?, lease_until = ?
       WHERE session_id = ? AND lease_until <= ? RETURNING chunk_count, next_chunk`
    ).bind(leaseId, Date.now() + LEASE_MS, session.id, Date.now()).first<CleanupCursor>();
    if (!cursor) continue; // Another cron/manual invocation owns this recording.

    const prefix = session.recording_path.replace(/\/+$/, '');
    const manifestKey = `${prefix}/manifest.json`;
    let retryAfter = 0;
    try {
      if (cursor.chunk_count === null) {
        result.storageOperations++;
        const object = await storage.get(manifestKey);
        if (!object) throw new Error('Recording manifest missing');
        const manifest = await object.json<{ chunkCount: number }>();
        if (!Number.isSafeInteger(manifest.chunkCount) || manifest.chunkCount < 0) throw new Error('Invalid recording manifest');
        cursor.chunk_count = manifest.chunkCount;
        // Save inventory before deleting anything; resume does not need the manifest again.
        await env.DB.prepare('UPDATE recording_cleanup_jobs SET chunk_count = ? WHERE session_id = ? AND lease_id = ?')
          .bind(cursor.chunk_count, session.id, leaseId).run();
      }
      while (cursor.next_chunk <= cursor.chunk_count && result.storageOperations < CLEANUP_OBJECT_BUDGET) {
        result.storageOperations++;
        await storage.delete(`${prefix}/chunk-${String(cursor.next_chunk).padStart(6, '0')}.jsonl.gz`);
        cursor.next_chunk++;
      }
      if (cursor.next_chunk > cursor.chunk_count && result.storageOperations < CLEANUP_OBJECT_BUDGET) {
        result.storageOperations++;
        await storage.delete(manifestKey);
        await env.DB.batch([
          env.DB.prepare("UPDATE ssh_sessions SET recording_status = 'expired', recording_path = NULL WHERE id = ?").bind(session.id),
          env.DB.prepare('DELETE FROM recording_cleanup_jobs WHERE session_id = ? AND lease_id = ?').bind(session.id, leaseId),
        ]);
        await recordAuditEvent({
          actorUserId: actor.actorUserId, actorUsername: actor.actorUsername, userAgent: actor.userAgent,
          action: 'RECORDING_EXPIRED_CLEANED', resourceType: 'session_recording', resourceId: session.id,
          sourceIp: actor.sourceIp || '', result: 'success',
          metadata: { trigger, retentionDays, recordingPath: session.recording_path },
        }, env.DB);
        result.expiredSessionIds.push(session.id);
      }
    } catch {
      // Keep the cursor and D1 metadata on object locks/provider failures. Try next slice later.
      retryAfter = Date.now() + 15 * 60_000;
      await recordAuditEvent({
        actorUserId: actor.actorUserId, actorUsername: actor.actorUsername, userAgent: actor.userAgent,
        action: 'RECORDING_CLEANUP_FAILED', resourceType: 'session_recording', resourceId: session.id,
        sourceIp: actor.sourceIp || '', result: 'failure', metadata: { trigger, reason: 'storage_cleanup_failed' },
      }, env.DB);
    } finally {
      // At worst a crash repeats this slice's idempotent deletes; it never skips an object.
      await env.DB.prepare(`UPDATE recording_cleanup_jobs SET next_chunk = ?, lease_id = NULL, lease_until = ?
        WHERE session_id = ? AND lease_id = ?`).bind(cursor.next_chunk, retryAfter, session.id, leaseId).run();
    }
  }
  result.cleanedCount = result.expiredSessionIds.length;
  result.budgetExhausted = result.storageOperations >= CLEANUP_OBJECT_BUDGET;
  return result;
}
