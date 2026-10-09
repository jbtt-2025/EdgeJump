// Session Audit Recording Retention & Lifecycle Cleanup Service

import type { Env } from '../types.ts';
import { getSetting } from '../settings/settings-service.ts';
import { getRecordingStorage } from '../storage/recording-storage.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';

export interface CleanupResult {
  cleanedCount: number;
  expiredSessionIds: string[];
  retentionDays: number;
}

interface ExpiredSessionRow {
  id: string;
  recording_path: string;
  recording_status: string;
}

/**
 * Scans D1 for expired session recordings according to recording_retention_days,
 * purges manifest and chunk files from R2 / S3 / Backblaze B2,
 * marks recording_status = 'expired', and records audit logs.
 */
export async function cleanupExpiredRecordings(
  env: Env,
  trigger: string = 'cron'
): Promise<CleanupResult> {
  const retentionDaysStr = await getSetting('recording_retention_days', env.DB, '7');
  const retentionDays = parseInt(retentionDaysStr, 10);

  // If retentionDays <= 0, retention is set to indefinite (disabled)
  if (isNaN(retentionDays) || retentionDays <= 0) {
    return { cleanedCount: 0, expiredSessionIds: [], retentionDays: 0 };
  }

  const cutoffMs = Date.now() - retentionDays * 86400 * 1000;

  const { results: expiredSessions } = await env.DB.prepare(
    `SELECT id, recording_path, recording_status
     FROM ssh_sessions
     WHERE recording_status = 'completed'
       AND recording_path IS NOT NULL
       AND recording_path != ''
       AND (
         (ended_at IS NOT NULL AND ended_at < ?)
         OR (ended_at IS NULL AND started_at < ?)
       )
     LIMIT 100`
  )
    .bind(cutoffMs, cutoffMs)
    .all<ExpiredSessionRow>();

  if (!expiredSessions || expiredSessions.length === 0) {
    return { cleanedCount: 0, expiredSessionIds: [], retentionDays };
  }

  const storage = getRecordingStorage(env);
  const cleanedIds: string[] = [];

  for (const session of expiredSessions) {
    const recordingPrefix = session.recording_path.replace(/\/+$/, '');

    if (storage) {
      try {
        const manifestKey = `${recordingPrefix}/manifest.json`;
        const manifestObj = await storage.get(manifestKey);
        if (manifestObj) {
          const manifest = await manifestObj.json<{ chunkCount?: number }>().catch(() => null);
          const chunkCount = manifest?.chunkCount || 0;

          // Delete all chunks
          for (let i = 1; i <= chunkCount; i++) {
            const chunkKey = `${recordingPrefix}/chunk-${String(i).padStart(6, '0')}.jsonl.gz`;
            await storage.delete(chunkKey).catch((err) => {
              console.warn(`[Cleanup] Failed to delete chunk ${chunkKey}:`, err);
            });
          }
        }

        // Delete manifest
        await storage.delete(manifestKey).catch((err) => {
          console.warn(`[Cleanup] Failed to delete manifest ${manifestKey}:`, err);
        });
      } catch (err) {
        console.error(`[Cleanup] Error purging storage objects for session ${session.id}:`, err);
      }
    }

    // Update D1 record status to 'expired' and nullify recording_path
    await env.DB.prepare(
      "UPDATE ssh_sessions SET recording_status = 'expired', recording_path = NULL WHERE id = ?"
    )
      .bind(session.id)
      .run();

    await recordAuditEvent(
      {
        actorUserId: 'system',
        action: 'RECORDING_EXPIRED_CLEANED',
        resourceType: 'session_recording',
        resourceId: session.id,
        sourceIp: '127.0.0.1',
        result: 'success',
        metadata: {
          trigger,
          retentionDays,
          recordingPath: session.recording_path,
        },
      },
      env.DB
    );

    cleanedIds.push(session.id);
  }

  return {
    cleanedCount: cleanedIds.length,
    expiredSessionIds: cleanedIds,
    retentionDays,
  };
}
