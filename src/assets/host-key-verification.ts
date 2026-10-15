import type { Env, SSHHostKeyRow } from '../types.ts';
import { recordAuditEvent, type CreateAuditEventInput } from '../audit/audit-service.ts';

export async function verifyAssetHostKey(
  env: Env, assetId: string, algorithm: string, fingerprint: string, publicKey: string,
  actor: Pick<CreateAuditEventInput, 'actorUserId' | 'actorUsername' | 'sourceIp' | 'userAgent'>,
): Promise<void> {
  const asset = await env.DB.prepare('SELECT host_key_policy FROM assets WHERE id = ?').bind(assetId)
    .first<{ host_key_policy: string }>();
  if (!asset) throw new Error('Asset not found');
  const id = crypto.randomUUID();
  const now = Date.now();
  // A conditional insert makes TOFU an asset-wide, first-use operation even
  // when two independent session DOs race with different algorithms.
  const inserted = await env.DB.prepare(`INSERT INTO ssh_host_keys
    (id, asset_id, algorithm, fingerprint, public_key, verified_at, verified_by, status, created_at)
    SELECT ?, ?, ?, ?, ?, ?, 'system-tofu', 'verified', ?
    WHERE NOT EXISTS (SELECT 1 FROM ssh_host_keys WHERE asset_id = ?)
      AND EXISTS (SELECT 1 FROM assets WHERE id = ? AND host_key_policy = 'strict')`)
    .bind(id, assetId, algorithm, fingerprint, publicKey, now, now, assetId, assetId).run();
  if (inserted.meta.changes) {
    await env.DB.prepare('UPDATE assets SET last_seen_host_key = ? WHERE id = ?').bind(fingerprint, assetId).run();
    await recordAuditEvent({ ...actor, action: 'HOST_KEY_TRUSTED', resourceType: 'ssh_host_key', resourceId: id,
      result: 'success', metadata: { assetId, algorithm, fingerprint } }, env.DB);
    return;
  }
  const { results = [] } = await env.DB.prepare('SELECT * FROM ssh_host_keys WHERE asset_id = ?')
    .bind(assetId).all<SSHHostKeyRow>();
  const trusted = results.find((row) => row.algorithm === algorithm);
  if (asset.host_key_policy !== 'approval_required' && results.some((row) => row.status === 'changed')) {
    throw new Error('Host key changed: administrator approval is required');
  }
  const blocked = asset.host_key_policy === 'approval_required' || results.some((row) => row.status !== 'verified');
  if (!blocked && trusted?.fingerprint === fingerprint) return;

  // Keep both the original key and the observed replacement for an explicit
  // administrator decision. Once changed, every algorithm remains blocked.
  await env.DB.batch([
    env.DB.prepare("UPDATE ssh_host_keys SET status = 'changed' WHERE asset_id = ?").bind(assetId),
    env.DB.prepare(`INSERT INTO ssh_host_keys
      (id, asset_id, algorithm, fingerprint, public_key, status, created_at, candidate_fingerprint, candidate_public_key)
      VALUES (?, ?, ?, ?, ?, 'changed', ?, ?, ?)
      ON CONFLICT(asset_id, algorithm) DO UPDATE SET candidate_fingerprint = excluded.candidate_fingerprint,
      candidate_public_key = excluded.candidate_public_key, status = 'changed'`)
      .bind(id, assetId, algorithm, fingerprint, publicKey, now, fingerprint, publicKey),
  ]);
  await recordAuditEvent({ ...actor, action: 'HOST_KEY_CHANGED', resourceType: 'ssh_host_key', resourceId: trusted?.id ?? id,
    result: 'failure', metadata: { assetId, algorithm, expectedFingerprint: trusted?.fingerprint, actualFingerprint: fingerprint } }, env.DB);
  throw new Error('Host key verification blocked: administrator approval of the fingerprint is required');
}
