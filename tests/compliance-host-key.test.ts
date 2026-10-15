import { seedSessionMetadata } from './compliance-helpers.ts';
// Supplementary verification tests for the v1-compliance-review spec: Host Key (SEC-10, SEC-11).
//
// Design reference: .kiro/specs/v1-compliance-review/design.md C6.3 (file plan), C6.5 (compliance-host-key),
// C6.7 (isolation) and C6.8 (todo rules); tasks.md 9.1–9.3.
//
// Observation surface (read-only, business code is never modified):
// - SSHSessionDO is constructed as `new SSHSessionDO(undefined, env)` and initialised through its own `/init`
//   endpoint with native SSHSessionInitConfig fields. No credential is sent and `/connect` is never called,
//   so no SSH connection is attempted.
// - The private `processHostKeyTOFU(algorithm, fingerprint, hostKeyBlob)` is invoked directly, the same access
//   path as tests/session-recording.test.ts › "tofu: Host key TOFU auto-trusts ...". In a real handshake it is
//   called right after verifyHostKeySignature() (src/durable/SSHSessionDO.ts, step 4); exercising the full
//   handshake needs a real SSH server and is recorded as an audit limitation.
// - D1 is createTestDatabase() (real migrations, including UNIQUE(asset_id, algorithm) and the
//   ssh_host_keys.asset_id -> assets(id) foreign key), so the DO's ON CONFLICT upsert runs against the real
//   constraint instead of a hand-written mock.
// - Host key blobs are synthetic `string(algorithm) || string(key bytes)`; algorithm and fingerprint are
//   derived with the implementation's own getHostKeyAlgorithm() / computeHostKeyFingerprint().

import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import type { SSHHostKeyRow } from '../src/types.ts';
import type { SSHSessionInitConfig } from '../src/durable/SSHSessionDO.ts';
import type { ApiResult, ComplianceContext, DemoTopology, Rng } from './compliance-helpers.ts';
import { SSHSessionDO } from '../src/durable/SSHSessionDO.ts';
import { computeHostKeyFingerprint, getHostKeyAlgorithm } from '../src/ssh/host-key.ts';
import { concat, encodeString, toBase64 } from '../src/ssh/utils.ts';
import { bytesToHex, hexToBytes } from '../src/crypto/utils.ts';
import { createAsset } from '../src/assets/asset-service.ts';
import {
  PROPERTY_RUNS,
  api,
  createContext,
  forAll,
  insertUser,
  seedDemoTopology,
  seedFromEnv,
} from './compliance-helpers.ts';

// -------------------------------------------------------------
// In-file helpers (shared by tasks 9.1–9.3)
// -------------------------------------------------------------

const DEFAULT_HOST_KEY_ALGORITHM = 'ssh-ed25519';
const DEFAULT_PROBE_USER_ID = 'usr_compliance_hostkey_probe';
const DEFAULT_PROBE_ACCOUNT_ID = 'acc_compliance_hostkey_probe';
const DO_BASE_URL = 'https://ssh-session.do.internal';

interface HostKeyMaterial {
  algorithm: string;
  fingerprint: string;
  blob: Uint8Array;
  /** Base64 of the blob: the value the DO stores in ssh_host_keys.public_key. */
  publicKey: string;
}

/**
 * Builds a synthetic host key blob `string(algorithm) || string(keyBytes)` from a hex string (use 64 hex chars
 * for an Ed25519-sized key). Algorithm and fingerprint come from the implementation's own helpers, exactly as
 * the handshake derives them before calling processHostKeyTOFU().
 */
async function makeHostKey(keyHex: string, algorithm: string = DEFAULT_HOST_KEY_ALGORITHM): Promise<HostKeyMaterial> {
  const blob = concat(encodeString(algorithm), encodeString(hexToBytes(keyHex)));
  return {
    algorithm: getHostKeyAlgorithm(blob),
    fingerprint: await computeHostKeyFingerprint(blob),
    blob,
    publicKey: toBase64(blob),
  };
}

interface HostKeyTarget {
  assetId: string;
  assetName: string;
  hostname: string;
  port: number;
  userId: string;
  username: string;
}

/**
 * Inserts a User-role user (placeholder password, cannot log in) and an asset through the implementation's
 * createAsset(). The asset row must exist before any ssh_host_keys row because of the foreign key.
 */
async function seedHostKeyTarget(
  ctx: ComplianceContext,
  opts: { assetName?: string; hostname?: string; port?: number } = {},
): Promise<HostKeyTarget> {
  const suffix = randomUUID().slice(0, 8);
  const user = await insertUser(ctx.db, { username: `hk-user-${suffix}`, roles: ['User'] });
  const asset = await createAsset(
    {
      name: opts.assetName ?? `hk-asset-${suffix}`,
      hostname: opts.hostname ?? '8.8.8.8',
      port: opts.port ?? 22,
      platform: 'linux',
      environment: 'production',
    },
    null,
    ctx.db,
  );
  return {
    assetId: asset.id,
    assetName: asset.name,
    hostname: asset.hostname,
    port: asset.port,
    userId: user.id,
    username: user.username,
  };
}

interface HostKeyDo {
  instance: SSHSessionDO;
  sessionId: string;
  assetId: string;
}

/**
 * Constructs `new SSHSessionDO(undefined, ctx.env)`, registers it with ctx.track() (so ctx.cleanup() terminates
 * it) and POSTs `/init` with native SSHSessionInitConfig fields built from the D1 asset row.
 */
async function newHostKeyDo(
  ctx: ComplianceContext,
  assetId: string,
  opts: { userId?: string; username?: string; accountId?: string; sessionId?: string } = {},
): Promise<HostKeyDo> {
  const asset = await ctx.db
    .prepare('SELECT id, name, hostname, port FROM assets WHERE id = ?')
    .bind(assetId)
    .first<{ id: string; name: string; hostname: string; port: number }>();
  assert.ok(asset, 'fixture: asset row must exist before the DO is initialised');

  const sessionId = opts.sessionId ?? `sess_hk_${randomUUID()}`;
  const config: SSHSessionInitConfig = {
    sessionId,
    userId: opts.userId ?? DEFAULT_PROBE_USER_ID,
    usernameSnapshot: opts.username ?? 'hostkey-probe',
    assetId: asset.id,
    assetNameSnapshot: asset.name,
    accountId: opts.accountId ?? DEFAULT_PROBE_ACCOUNT_ID,
    accountNameSnapshot: 'deploy',
    host: asset.hostname,
    port: Number(asset.port),
    username: 'deploy',
    authMethod: 'password',
    sourceIp: '127.0.0.1',
    userAgent: 'compliance-test',
  };

  await seedSessionMetadata(ctx.db, config);
  const instance = ctx.track(new SSHSessionDO(undefined, ctx.env));
  const response = await instance.fetch(
    new Request(`${DO_BASE_URL}/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    }),
  );
  assert.equal(response.status, 200, 'fixture: SSHSessionDO /init must succeed');
  return { instance, sessionId, assetId: asset.id };
}

type PresentOutcome = { accepted: true } | { accepted: false; message: string };

interface TofuProbe {
  processHostKeyTOFU(algorithm: string, fingerprint: string, hostKeyBlob: Uint8Array): Promise<void>;
}

/** Presents a host key to the DO the way the handshake does (after signature verification) and reports the outcome. */
async function presentHostKey(sessionDo: HostKeyDo | SSHSessionDO, key: HostKeyMaterial): Promise<PresentOutcome> {
  const instance = sessionDo instanceof SSHSessionDO ? sessionDo : sessionDo.instance;
  try {
    await (instance as unknown as TofuProbe).processHostKeyTOFU(key.algorithm, key.fingerprint, key.blob);
    return { accepted: true };
  } catch (err) {
    return { accepted: false, message: err instanceof Error ? err.message : String(err) };
  }
}

/** Inserts an ssh_host_keys row directly (e.g. a pre-existing 'unverified' or 'changed' record). */
async function insertHostKeyRow(
  db: D1Database,
  assetId: string,
  key: HostKeyMaterial,
  status: SSHHostKeyRow['status'],
  opts: { id?: string; verifiedBy?: string | null } = {},
): Promise<string> {
  const id = opts.id ?? `hk_${randomUUID()}`;
  const now = Date.now();
  const verified = status !== 'unverified';
  await db
    .prepare(
      `INSERT INTO ssh_host_keys (id, asset_id, algorithm, fingerprint, public_key, verified_at, verified_by, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      assetId,
      key.algorithm,
      key.fingerprint,
      key.publicKey,
      verified ? now : null,
      verified ? (opts.verifiedBy ?? 'compliance-test') : null,
      status,
      now,
    )
    .run();
  return id;
}

async function hostKeyRows(db: D1Database, assetId: string): Promise<SSHHostKeyRow[]> {
  const { results } = await db
    .prepare(
      `SELECT id, asset_id, algorithm, fingerprint, public_key, verified_at, verified_by, status, created_at
       FROM ssh_host_keys WHERE asset_id = ? ORDER BY algorithm, id`
    )
    .bind(assetId)
    .all<SSHHostKeyRow>();
  return (results ?? []).map((row) => ({ ...row }));
}

interface AuditRow {
  action: string;
  actorUserId: string | null;
  resourceType: string;
  resourceId: string | null;
  result: string;
  metadata: Record<string, unknown> | null;
}

/** Audit events in insertion order, optionally filtered by action. */
async function auditEvents(db: D1Database, actions?: readonly string[]): Promise<AuditRow[]> {
  const { results } = await db
    .prepare(
      `SELECT action, actor_user_id, resource_type, resource_id, result, metadata_json
       FROM audit_events ORDER BY timestamp, rowid`
    )
    .all<{
      action: string;
      actor_user_id: string | null;
      resource_type: string;
      resource_id: string | null;
      result: string;
      metadata_json: string | null;
    }>();
  return (results ?? [])
    .filter((row) => !actions || actions.includes(row.action))
    .map((row) => ({
      action: row.action,
      actorUserId: row.actor_user_id,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      result: row.result,
      metadata: row.metadata_json ? (JSON.parse(row.metadata_json) as Record<string, unknown>) : null,
    }));
}

async function auditActions(db: D1Database): Promise<string[]> {
  return (await auditEvents(db)).map((row) => row.action);
}

async function sessionRow(
  db: D1Database,
  sessionId: string,
): Promise<{ status: string; disconnect_reason: string | null } | null> {
  return db
    .prepare('SELECT status, disconnect_reason FROM ssh_sessions WHERE id = ?')
    .bind(sessionId)
    .first<{ status: string; disconnect_reason: string | null }>();
}

async function lastSeenHostKey(db: D1Database, assetId: string): Promise<string | null> {
  return db.prepare('SELECT last_seen_host_key FROM assets WHERE id = ?').bind(assetId).first<string>('last_seen_host_key');
}

// -------------------------------------------------------------
// Task 9.2 helpers (Property 6)
// -------------------------------------------------------------

/** Whole-table snapshot of ssh_host_keys (every asset), in a stable order. */
async function allHostKeyRows(db: D1Database): Promise<SSHHostKeyRow[]> {
  const { results } = await db
    .prepare(
      `SELECT id, asset_id, algorithm, fingerprint, public_key, verified_at, verified_by, status, created_at
       FROM ssh_host_keys ORDER BY asset_id, algorithm, id`
    )
    .all<SSHHostKeyRow>();
  return (results ?? []).map((row) => ({ ...row }));
}

function randomKeyHex(): string {
  return bytesToHex(new Uint8Array(randomBytes(32)));
}

interface ChangedHostKeyState {
  /** The key trusted by TOFU on the first connection. */
  trusted: HostKeyMaterial;
  /** The different key (same algorithm) that drove the record to 'changed'. */
  rogue: HostKeyMaterial;
  rowId: string;
}

/**
 * Drives an asset's host key to 'changed' through the implementation's own code path: a first session trusts
 * `trusted` by TOFU, a second session presents a different key of the same algorithm and is blocked.
 */
async function driveHostKeyToChanged(
  ctx: ComplianceContext,
  assetId: string,
  actor: { id: string; username: string },
  algorithm: string = DEFAULT_HOST_KEY_ALGORITHM,
): Promise<ChangedHostKeyState> {
  const trusted = await makeHostKey(randomKeyHex(), algorithm);
  const rogue = await makeHostKey(randomKeyHex(), algorithm);
  const doOpts = { userId: actor.id, username: actor.username };

  const first = await newHostKeyDo(ctx, assetId, doOpts);
  assert.equal((await presentHostKey(first, trusted)).accepted, true, 'fixture: the first host key is trusted by TOFU');
  const second = await newHostKeyDo(ctx, assetId, doOpts);
  assert.equal((await presentHostKey(second, rogue)).accepted, false, 'fixture: a different fingerprint is blocked');

  const rows = await hostKeyRows(ctx.db, assetId);
  assert.equal(rows.length, 1, 'fixture: exactly one host key row exists for the asset');
  assert.equal(rows[0].status, 'changed', 'fixture: the asset host key is now in the changed state');
  return { trusted, rogue, rowId: rows[0].id };
}

const PROPERTY_HOST_KEY_ALGORITHMS = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'] as const;

interface FingerprintPresentation {
  /** Index into FingerprintSequenceCase.keyHexes: 0 = first trusted key, 1 = first changed key, >= 2 = other new keys. */
  keyIndex: number;
  /** true: a new session (new DO, §33) presents the key; false: the previous session's DO presents it again. */
  freshDo: boolean;
}

interface FingerprintSequenceCase {
  /** One algorithm per sequence: processHostKeyTOFU keys records by (asset_id, algorithm). */
  algorithm: string;
  /** 2–4 distinct 32-byte keys. */
  keyHexes: string[];
  /** Re-presentations of the trusted key before the change (0–3). */
  prefix: FingerprintPresentation[];
  /** The first different fingerprint (keyIndex = 1). */
  change: FingerprintPresentation;
  /** Presentations after the change (1–5): original key, the changed key or other new keys. */
  tail: FingerprintPresentation[];
}

function genFingerprintSequence(rng: Rng): FingerprintSequenceCase {
  const algorithm = rng.pick(PROPERTY_HOST_KEY_ALGORITHMS);
  const keyCount = rng.int(2, 4);
  const keys = new Set<string>();
  while (keys.size < keyCount) keys.add(rng.hex(32));
  return {
    algorithm,
    keyHexes: [...keys],
    prefix: Array.from({ length: rng.int(0, 3) }, () => ({ keyIndex: 0, freshDo: rng.bool() })),
    change: { keyIndex: 1, freshDo: rng.bool() },
    tail: Array.from({ length: rng.int(1, 5) }, () => ({ keyIndex: rng.int(0, keyCount - 1), freshDo: rng.bool(0.7) })),
  };
}

function describeKeyIndex(keyIndex: number): string {
  if (keyIndex === 0) return '原指纹';
  if (keyIndex === 1) return '首个变化指纹';
  return '其它新指纹';
}

interface SweepCall {
  method: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
}

interface SweepResult extends SweepCall {
  status: number;
}

/**
 * Every route of design.md C6.6 that a logged-in User can send (public, user, admin read, admin mutation, both
 * WebSocket routes), with fixture-only bodies. The host-key routes target the asset whose key is 'changed'.
 * POST /api/auth/logout is deliberately last because it revokes the caller's login session.
 */
function userReachableSweep(topo: DemoTopology, sessionId: string, ticket: string): SweepCall[] {
  const assetId = topo.prodWeb01.id;
  const upgrade = { Upgrade: 'websocket' };
  return [
    // Public
    {
      method: 'POST',
      path: '/api/auth/bootstrap',
      body: { token: 'compliance-invalid-bootstrap-token', username: 'sweep-intruder', password: 'Sweep-Password-123!' },
    },
    { method: 'GET', path: '/api/auth/bootstrap/status' },
    { method: 'POST', path: '/api/auth/login', body: { username: topo.alice.username, password: 'compliance-wrong-password' } },
    { method: 'GET', path: '/api/health' },
    // User
    { method: 'GET', path: '/api/me' },
    { method: 'GET', path: '/api/assets' },
    { method: 'GET', path: `/api/assets/${assetId}/accounts` },
    { method: 'GET', path: `/api/sessions/${sessionId}/ws?ticket=${encodeURIComponent(ticket)}`, headers: upgrade },
    // Admin read
    { method: 'GET', path: '/api/admin/users' },
    { method: 'GET', path: '/api/admin/groups' },
    { method: 'GET', path: '/api/admin/roles' },
    { method: 'GET', path: '/api/admin/assets' },
    { method: 'GET', path: `/api/admin/assets/${assetId}/accounts` },
    { method: 'GET', path: '/api/admin/asset-groups' },
    { method: 'GET', path: '/api/admin/credentials' },
    { method: 'GET', path: '/api/admin/authorizations' },
    { method: 'GET', path: '/api/admin/sessions?type=online' },
    { method: 'GET', path: '/api/admin/sessions?type=historical' },
    { method: 'GET', path: `/api/admin/sessions/${sessionId}` },
    { method: 'GET', path: `/api/admin/sessions/${sessionId}/commands` },
    { method: 'GET', path: `/api/admin/sessions/${sessionId}/recording` },
    { method: 'GET', path: `/api/admin/assets/${assetId}/host-key` },
    { method: 'GET', path: '/api/admin/settings' },
    { method: 'GET', path: '/api/admin/audit' },
    { method: 'GET', path: `/api/admin/sessions/${sessionId}/monitor`, headers: upgrade },
    // Admin mutation
    { method: 'POST', path: '/api/admin/users', body: { username: 'sweep-user', password: 'Sweep-Password-123!', displayName: 'Sweep' } },
    { method: 'PATCH', path: `/api/admin/users/${topo.bob.id}`, body: { displayName: 'Sweep' } },
    { method: 'POST', path: `/api/admin/users/${topo.bob.id}/disable`, body: {} },
    { method: 'POST', path: `/api/admin/users/${topo.bob.id}/enable`, body: {} },
    { method: 'POST', path: `/api/admin/users/${topo.bob.id}/reset-password`, body: { password: 'Sweep-Password-123!' } },
    { method: 'POST', path: '/api/admin/groups', body: { name: 'sweep-group' } },
    { method: 'PATCH', path: `/api/admin/groups/${topo.developers.id}`, body: { name: topo.developers.name } },
    { method: 'DELETE', path: `/api/admin/groups/${topo.developers.id}` },
    { method: 'POST', path: '/api/admin/assets', body: { name: 'sweep-asset', hostname: '9.9.9.9', port: 22 } },
    { method: 'PATCH', path: `/api/admin/assets/${assetId}`, body: { description: 'sweep' } },
    { method: 'DELETE', path: `/api/admin/assets/${assetId}` },
    { method: 'POST', path: `/api/admin/assets/${assetId}/accounts`, body: { username: 'sweep', credentialId: topo.deployKey.id } },
    { method: 'POST', path: '/api/admin/asset-groups', body: { name: 'sweep-asset-group' } },
    { method: 'POST', path: '/api/admin/credentials', body: { name: 'sweep-credential', type: 'password', secret: 'sweep-placeholder' } },
    { method: 'PUT', path: `/api/admin/credentials/${topo.deployKey.id}`, body: { secret: 'sweep-placeholder' } },
    { method: 'DELETE', path: `/api/admin/credentials/${topo.deployKey.id}` },
    {
      method: 'POST',
      path: '/api/admin/authorizations',
      body: { name: 'sweep-rule', userIds: [topo.alice.id], assetIds: [assetId], accountIds: [topo.root.id], actions: ['connect'] },
    },
    { method: 'PATCH', path: `/api/admin/authorizations/${topo.rule.id}`, body: { enabled: true } },
    { method: 'DELETE', path: `/api/admin/authorizations/${topo.rule.id}` },
    { method: 'POST', path: `/api/admin/sessions/${sessionId}/terminate`, body: {} },
    { method: 'POST', path: `/api/admin/assets/${assetId}/host-key/reset`, body: {} },
    { method: 'PATCH', path: '/api/admin/settings', body: { key: 'session_idle_timeout', value: '1800' } },
    { method: 'POST', path: '/api/admin/recordings/cleanup', body: {} },
    // User session teardown, then logout last
    { method: 'POST', path: `/api/sessions/${sessionId}/disconnect`, body: {} },
    { method: 'POST', path: '/api/auth/logout', body: {} },
  ];
}

function findSweepStatus(results: readonly SweepResult[], method: string, path: string): number | undefined {
  return results.find((r) => r.method === method && r.path === path)?.status;
}

function hostKeyAuditBy(rows: readonly AuditRow[], actorUserId: string): AuditRow[] {
  return rows.filter((row) => row.action.startsWith('HOST_KEY_') && row.actorUserId === actorUserId);
}

async function createSessionAs(ctx: ComplianceContext, topo: DemoTopology): Promise<ApiResult> {
  return api(ctx, 'POST', '/api/sessions', {
    cookie: topo.alice.cookie,
    body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id },
  });
}

function initCallCount(ctx: ComplianceContext): number {
  return ctx.sessions.calls.filter((call) => call.path === '/init').length;
}

// -------------------------------------------------------------
// Task 9.3 helpers (reset → TOFU observation, L9 / EXT-008)
// -------------------------------------------------------------

/** Iterations of the reset observation (not a numbered Property, so PROPERTY_RUNS is not required). */
const RESET_OBSERVATION_RUNS = 20;

/** Which fingerprint the first post-reset connection presents. */
type ResetProbeKey = 'rogue' | 'trusted' | 'fresh';

interface ResetProbeCase {
  algorithm: string;
  /** rogue = the key that drove the record to 'changed'; trusted = the original key; fresh = a never-seen key. */
  presented: ResetProbeKey;
  /** Key bytes for the 'fresh' case (deterministic through the seeded PRNG). */
  freshKeyHex: string;
}

function genResetProbe(rng: Rng, run: number): ResetProbeCase {
  return {
    algorithm: rng.pick(PROPERTY_HOST_KEY_ALGORITHMS),
    // Run 0 always presents the rogue key, the case that matters most for §42.
    presented: run === 0 ? 'rogue' : rng.pick(['rogue', 'trusted', 'fresh'] as const),
    freshKeyHex: rng.hex(32),
  };
}

function describeResetProbe(kind: ResetProbeKey): string {
  if (kind === 'rogue') return '导致 changed 的变化指纹';
  if (kind === 'trusted') return '原已信任指纹';
  return '从未出现过的新指纹';
}

// One context per test (or per property iteration); `after` is a safety net for contexts left open by a failure.
const openContexts = new Set<ComplianceContext>();

async function withContext<T>(fn: (ctx: ComplianceContext) => Promise<T>): Promise<T> {
  const ctx = await createContext();
  openContexts.add(ctx);
  try {
    return await fn(ctx);
  } finally {
    openContexts.delete(ctx);
    await ctx.cleanup();
  }
}

after(async () => {
  for (const ctx of openContexts) await ctx.cleanup();
  openContexts.clear();
});

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

describe('compliance-host-key: SEC-10 / SEC-11 Host Key', () => {
  // Task 9.1: fixture sanity on the real schema (a meaningful baseline for the negative cases of 9.2 / 9.3).
  it('[SEC-10] 夹具：真实 schema 含 UNIQUE(asset_id, algorithm) 与 assets 外键约束', async () => {
    await withContext(async (ctx) => {
      const target = await seedHostKeyTarget(ctx);
      const key = await makeHostKey('11'.repeat(32));

      await insertHostKeyRow(ctx.db, target.assetId, key, 'verified');
      await assert.rejects(
        insertHostKeyRow(ctx.db, target.assetId, key, 'verified'),
        'fixture: a second row for the same (asset_id, algorithm) must violate UNIQUE(asset_id, algorithm)',
      );
      await assert.rejects(
        insertHostKeyRow(ctx.db, `asset_missing_${randomUUID()}`, key, 'verified'),
        'fixture: ssh_host_keys.asset_id must reference an existing asset (foreign key enforced)',
      );
      assert.equal((await hostKeyRows(ctx.db, target.assetId)).length, 1, 'fixture: exactly one host key row remains');
    });
  });

  // Task 9.1: positive control — §40 TOFU on first connection.
  it('[SEC-10] 正向对照：首个指纹被 TOFU 记录为 verified 并写 HOST_KEY_TRUSTED', async () => {
    await withContext(async (ctx) => {
      const target = await seedHostKeyTarget(ctx);
      const hk = await newHostKeyDo(ctx, target.assetId, { userId: target.userId, username: target.username });
      const key = await makeHostKey('a1'.repeat(32));

      assert.deepEqual(await hostKeyRows(ctx.db, target.assetId), [], 'fixture: no host key is stored before the first connection');
      assert.equal((await sessionRow(ctx.db, hk.sessionId))?.status, 'connecting', 'fixture: /init persisted the session as connecting');

      const outcome = await presentHostKey(hk, key);
      assert.equal(outcome.accepted, true, '[判定] 首次连接出示的 Host Key 应被 TOFU 接受（§40）');

      const rows = await hostKeyRows(ctx.db, target.assetId);
      assert.equal(rows.length, 1, '[判定] 首次信任应在 ssh_host_keys 中写入恰好一条记录（§39、§40）');
      const [row] = rows;
      assert.equal(row.status, 'verified', '[判定] 首个指纹应被记录为 verified（§40）');
      assert.equal(row.algorithm, key.algorithm, '[判定] 记录的算法应等于出示 Host Key 的算法（§39）');
      assert.equal(row.fingerprint, key.fingerprint, '[判定] 记录的指纹应等于出示 Host Key 的指纹（§39）');
      assert.equal(row.public_key, key.publicKey, '[判定] 记录的公钥应等于出示 Host Key 的公钥（§39）');
      assert.equal(typeof row.verified_at, 'number', '[判定] 首次信任应记录 verified_at（§39）');
      assert.equal(row.verified_by, 'system-tofu', 'observation: TOFU auto-trust records verified_by = system-tofu');
      assert.equal(await lastSeenHostKey(ctx.db, target.assetId), key.fingerprint, 'observation: assets.last_seen_host_key is updated');

      const trusted = await auditEvents(ctx.db, ['HOST_KEY_TRUSTED']);
      assert.equal(trusted.length, 1, '[判定] 首次信任应写入恰好一条 HOST_KEY_TRUSTED 审计事件（§40、§57）');
      assert.equal(trusted[0].result, 'success', '[判定] HOST_KEY_TRUSTED 的 result 应为 success');
      assert.equal(trusted[0].resourceType, 'ssh_host_key', 'observation: HOST_KEY_TRUSTED resource_type = ssh_host_key');
      assert.equal(trusted[0].resourceId, row.id, '[判定] HOST_KEY_TRUSTED 应指向新建的 ssh_host_keys 记录');
      assert.equal(trusted[0].actorUserId, target.userId, 'observation: the actor is the connecting user');
      assert.equal(trusted[0].metadata?.fingerprint, key.fingerprint, '[判定] HOST_KEY_TRUSTED 元数据应包含被信任的指纹');
      assert.equal(trusted[0].metadata?.algorithm, key.algorithm, '[判定] HOST_KEY_TRUSTED 元数据应包含算法');
      assert.equal(trusted[0].metadata?.assetId, target.assetId, '[判定] HOST_KEY_TRUSTED 元数据应包含资产 ID');

      assert.equal((await auditEvents(ctx.db, ['HOST_KEY_CHANGED'])).length, 0, '[判定] 首次信任不应产生 HOST_KEY_CHANGED');
      assert.equal((await sessionRow(ctx.db, hk.sessionId))?.status, 'connecting', '[判定] 首次信任不应使会话失败');
      assert.deepEqual(ctx.network.attempts, [], 'fixture: the DO-level probe never touches the network');
    });
  });

  // Task 9.1: positive control for the "changed fingerprint is blocked" negatives of 9.2 — the same key is accepted
  // again, both by the same DO and by the DO of a later session (one DO per session, §33).
  it('[SEC-10] 正向对照：已信任的同一指纹再次出示时通过校验且记录与审计不变', async () => {
    await withContext(async (ctx) => {
      const target = await seedHostKeyTarget(ctx);
      const key = await makeHostKey('b2'.repeat(32));
      const first = await newHostKeyDo(ctx, target.assetId, { userId: target.userId, username: target.username });

      assert.equal((await presentHostKey(first, key)).accepted, true, 'fixture: first connection is trusted');
      const trustedRows = await hostKeyRows(ctx.db, target.assetId);
      const actionsAfterTrust = await auditActions(ctx.db);

      const sameSession = await presentHostKey(first, key);
      assert.equal(sameSession.accepted, true, '[判定] 已信任指纹在同一会话中再次出示应通过校验（§41）');

      const later = await newHostKeyDo(ctx, target.assetId, { userId: target.userId, username: target.username });
      const laterSession = await presentHostKey(later, key);
      assert.equal(laterSession.accepted, true, '[判定] 已信任指纹在后续会话中出示应透明通过校验（§41）');

      assert.deepEqual(await hostKeyRows(ctx.db, target.assetId), trustedRows, '[判定] 指纹一致时 ssh_host_keys 记录不应变化');
      assert.deepEqual(await auditActions(ctx.db), actionsAfterTrust, '[判定] 指纹一致时不应产生新的 HOST_KEY_* 审计事件');
      assert.equal((await sessionRow(ctx.db, first.sessionId))?.status, 'connecting', '[判定] 指纹一致时首个会话不应失败');
      assert.equal((await sessionRow(ctx.db, later.sessionId))?.status, 'connecting', '[判定] 指纹一致时后续会话不应失败');
    });
  });

  // Task 9.1: positive control on the real UNIQUE(asset_id, algorithm) constraint — the DO's ON CONFLICT upsert
  // upgrades a pre-existing 'unverified' record in place instead of inserting a duplicate.
  it('[SEC-10] an unverified key remains blocked until an administrator approves its fingerprint', async () => {
    await withContext(async (ctx) => {
      const target = await seedHostKeyTarget(ctx);
      const original = await makeHostKey('c3'.repeat(32));
      const presented = await makeHostKey('d4'.repeat(32));
      await insertHostKeyRow(ctx.db, target.assetId, original, 'unverified');
      const hk = await newHostKeyDo(ctx, target.assetId, { userId: target.userId });
      assert.equal((await presentHostKey(hk, presented)).accepted, false);
      const rows = await hostKeyRows(ctx.db, target.assetId);
      assert.equal(rows[0].fingerprint, original.fingerprint);
      assert.equal(rows[0].status, 'changed');
      assert.equal((await auditEvents(ctx.db, ['HOST_KEY_TRUSTED'])).length, 0);
    });
  });

  // -----------------------------------------------------------
  // Task 9.2: Property 6
  // -----------------------------------------------------------

  // Feature: v1-compliance-review, Property 6: Host Key changed 状态粘滞且不可由用户解除
  it('[SEC-10] changed 状态粘滞：随机指纹序列中首个指纹被信任，指纹变化后阻断且此后原指纹或新指纹均被阻断', { timeout: 60_000 }, async () => {
    await forAll(
      genFingerprintSequence,
      async (c) => {
        await withContext(async (ctx) => {
          const target = await seedHostKeyTarget(ctx);
          const keys = await Promise.all(c.keyHexes.map((hex) => makeHostKey(hex, c.algorithm)));
          const doOpts = { userId: target.userId, username: target.username };
          let current = await newHostKeyDo(ctx, target.assetId, doOpts);
          const present = async (p: FingerprintPresentation): Promise<{ outcome: PresentOutcome; sessionId: string }> => {
            if (p.freshDo) current = await newHostKeyDo(ctx, target.assetId, doOpts);
            return { outcome: await presentHostKey(current, keys[p.keyIndex]), sessionId: current.sessionId };
          };

          // 1. First connection: TOFU (§40).
          assert.equal((await presentHostKey(current, keys[0])).accepted, true, '[判定] 首个指纹应被 TOFU 接受（§40）');
          const trustedRows = await hostKeyRows(ctx.db, target.assetId);
          assert.equal(trustedRows.length, 1, '[判定] 首次信任应写入恰好一条 ssh_host_keys 记录（§40）');
          assert.equal(trustedRows[0].status, 'verified', '[判定] 首个指纹应被记录为 verified（§40）');
          assert.equal(trustedRows[0].fingerprint, keys[0].fingerprint, '[判定] 记录的指纹应为首个出示的指纹（§39）');
          const trustedRowId = trustedRows[0].id;
          assert.equal((await auditEvents(ctx.db, ['HOST_KEY_TRUSTED'])).length, 1, '[判定] 首次信任应写入一条 HOST_KEY_TRUSTED（§40）');

          // 2. The trusted key is presented again before any change (§41 transparent verification).
          for (const p of c.prefix) {
            const { outcome, sessionId } = await present(p);
            assert.equal(outcome.accepted, true, '[判定] 指纹变化前再次出示已信任指纹应通过校验（§41）');
            assert.equal((await sessionRow(ctx.db, sessionId))?.status, 'connecting', '[判定] 指纹一致时会话不应失败');
          }
          assert.deepEqual(await hostKeyRows(ctx.db, target.assetId), trustedRows, '[判定] 指纹一致时 ssh_host_keys 记录不应变化');

          // 3. The first different fingerprint: blocked, changed, HOST_KEY_CHANGED, session failed (§42).
          const change = await present(c.change);
          assert.equal(change.outcome.accepted, false, '[判定] 已验证指纹改变时连接应被阻止（§42 BLOCK CONNECTION）');
          const changedRows = await hostKeyRows(ctx.db, target.assetId);
          assert.equal(changedRows.length, 1, '[判定] 指纹变化不应新增 ssh_host_keys 记录（§42）');
          assert.equal(changedRows[0].id, trustedRowId, '[判定] 指纹变化应标记原记录');
          assert.equal(changedRows[0].status, 'changed', '[判定] 指纹变化后状态应改为 changed（§42）');
          assert.equal(changedRows[0].fingerprint, keys[0].fingerprint, '[判定] 指纹变化不得以新指纹覆盖已信任指纹（§42 禁止 auto accept）');
          const changedEvents = await auditEvents(ctx.db, ['HOST_KEY_CHANGED']);
          assert.equal(changedEvents.length, 1, '[判定] 指纹变化应写入一条 HOST_KEY_CHANGED 安全审计事件（§42、§57）');
          assert.equal(changedEvents[0].resourceId, trustedRowId, '[判定] HOST_KEY_CHANGED 应指向被标记的 ssh_host_keys 记录');
          assert.equal(changedEvents[0].result, 'failure', '[判定] HOST_KEY_CHANGED 的 result 应为 failure');
          assert.equal(changedEvents[0].metadata?.expectedFingerprint, keys[0].fingerprint, '[判定] HOST_KEY_CHANGED 元数据应包含期望指纹');
          assert.equal(changedEvents[0].metadata?.actualFingerprint, keys[1].fingerprint, '[判定] HOST_KEY_CHANGED 元数据应包含实际指纹');
          const failed = await sessionRow(ctx.db, change.sessionId);
          assert.equal(failed?.status, 'failed', '[判定] 指纹变化时会话应记为 failed');
          assert.equal(failed?.disconnect_reason, 'host_key_changed', '[判定] 会话失败原因应为 host_key_changed');

          // 4. Afterwards every presentation (original, changed or another new key) stays blocked (§42).
          for (const p of c.tail) {
            const { outcome } = await present(p);
            assert.equal(outcome.accepted, false, `[判定] changed 状态下出示${describeKeyIndex(p.keyIndex)}应被阻止（§42）`);
            const rows = await hostKeyRows(ctx.db, target.assetId);
            assert.equal(rows.length, 1, '[判定] changed 状态下不应新增 ssh_host_keys 记录');
            assert.equal(rows[0].status, 'changed', `[判定] 出示${describeKeyIndex(p.keyIndex)}后状态应保持 changed（§42）`);
            assert.equal(rows[0].fingerprint, keys[0].fingerprint, '[判定] changed 状态下已信任指纹不得被覆盖（§42）');
          }
          assert.equal((await auditEvents(ctx.db, ['HOST_KEY_TRUSTED'])).length, 1, '[判定] 指纹变化后不应再产生 HOST_KEY_TRUSTED（§42）');
          assert.deepEqual(ctx.network.attempts, [], 'fixture: the DO-level probe never touches the network');
        });
      },
      { runs: PROPERTY_RUNS, seed: seedFromEnv() },
    );
  });

  // Positive control for the L8 case below: with a verified host key the same request succeeds.
  it('[SEC-10] 正向对照：资产 Host Key 为 verified 时 POST /api/sessions 返回 201', async () => {
    await withContext(async (ctx) => {
      const topo = await seedDemoTopology(ctx, `EJ-SECRET-${randomKeyHex()}`);
      const key = await makeHostKey(randomKeyHex());
      const first = await newHostKeyDo(ctx, topo.prodWeb01.id, { userId: topo.alice.id, username: topo.alice.username });
      assert.equal((await presentHostKey(first, key)).accepted, true, 'fixture: the first host key is trusted by TOFU');
      assert.equal((await hostKeyRows(ctx.db, topo.prodWeb01.id))[0]?.status, 'verified', 'fixture: host key is verified');

      const initsBefore = initCallCount(ctx);
      const res = await createSessionAs(ctx, topo);
      assert.equal(res.status, 201, '[判定] Host Key 为 verified 且授权有效时应能创建会话（§31）');
      assert.equal(initCallCount(ctx), initsBefore + 1, '[判定] 会话创建成功时应向 SSHSessionDO 下发 /init');
    });
  });

  // §31 step 8 "validate Host Key state" (L8).
  it(
    '[SEC-10] 资产 Host Key 为 changed 时 POST /api/sessions 被拒绝',
    {
    },
    async () => {
      await withContext(async (ctx) => {
        const topo = await seedDemoTopology(ctx, `EJ-SECRET-${randomKeyHex()}`);
        await driveHostKeyToChanged(ctx, topo.prodWeb01.id, topo.alice);

        const initsBefore = initCallCount(ctx);
        const res = await createSessionAs(ctx, topo);
        assert.equal(res.threw, false, 'fixture: the handler returned a response');
        assert.ok(res.status >= 400 && res.status < 500, '[判定] 资产 Host Key 为 changed 时创建会话应被拒绝（§31 第 8 步、§42）');
        assert.equal(initCallCount(ctx), initsBefore, '[判定] 被拒绝的会话不应向 SSHSessionDO 下发 /init（§31、§42）');
        assert.equal((await hostKeyRows(ctx.db, topo.prodWeb01.id))[0]?.status, 'changed', '[判定] 创建会话请求不应改变 changed 状态');
      });
    },
  );

  // Separate finding HK-016 (not part of the single-algorithm property above): records are keyed by
  // (asset_id, algorithm), so a key of another algorithm finds no row and is trusted by TOFU.
  it(
    '[SEC-10] 资产 Host Key 为 changed 时出示其它算法的 Host Key 仍被阻止',
    {
    },
    async () => {
      await withContext(async (ctx) => {
        const target = await seedHostKeyTarget(ctx);
        const state = await driveHostKeyToChanged(ctx, target.assetId, { id: target.userId, username: target.username }, 'ssh-ed25519');
        const otherAlgorithm = await makeHostKey(randomKeyHex(), 'ecdsa-sha2-nistp256');
        assert.notEqual(otherAlgorithm.algorithm, state.trusted.algorithm, 'fixture: the presented key uses another algorithm');

        const later = await newHostKeyDo(ctx, target.assetId, { userId: target.userId, username: target.username });
        const outcome = await presentHostKey(later, otherAlgorithm);
        assert.equal(outcome.accepted, false, '[判定] 资产处于 changed 状态时，任何算法的 Host Key 都应被阻止（§42）');
        const rows = await hostKeyRows(ctx.db, target.assetId);
        assert.ok(rows.every((row) => row.status !== 'verified'), '[判定] changed 资产不应自动信任其它算法的新 Host Key（§42 禁止 auto accept）');
      });
    },
  );

  it('[SEC-11] User 角色遍历全部用户可达路由后 changed Host Key 快照不变且仍阻断连接', { timeout: 60_000 }, async () => {
    await withContext(async (ctx) => {
      const topo = await seedDemoTopology(ctx, `EJ-SECRET-${randomKeyHex()}`);
      const state = await driveHostKeyToChanged(ctx, topo.prodWeb01.id, topo.alice);
      const snapshot = await allHostKeyRows(ctx.db);
      const hostKeyAuditBefore = hostKeyAuditBy(await auditEvents(ctx.db), topo.alice.id).length;

      const me = await api(ctx, 'GET', '/api/me', { cookie: topo.alice.cookie });
      assert.equal(me.status, 200, 'fixture: Alice is logged in, so 403 responses below come from authorization checks');

      // Session routes need a real session id; POST /api/sessions is itself part of the sweep.
      const created = await createSessionAs(ctx, topo);
      const results: SweepResult[] = [
        { method: 'POST', path: '/api/sessions', status: created.status },
      ];
      const sessionId: string = created.json?.sessionId ?? `sess_${randomUUID()}`;
      const ticket: string = created.json?.ticket ?? 'compliance-placeholder-ticket';

      for (const call of userReachableSweep(topo, sessionId, ticket)) {
        const res = await api(ctx, call.method, call.path, { cookie: topo.alice.cookie, body: call.body, headers: call.headers });
        results.push({ ...call, status: res.status });
      }

      const assetId = topo.prodWeb01.id;
      assert.equal(
        findSweepStatus(results, 'POST', `/api/admin/assets/${assetId}/host-key/reset`),
        403,
        '[判定] User 角色调用 host-key reset 应返回 403（§42 必须 Asset Admin 手动重新确认）',
      );
      assert.equal(
        findSweepStatus(results, 'GET', `/api/admin/assets/${assetId}/host-key`),
        403,
        '[判定] User 角色读取 Host Key 管理接口应返回 403（§41）',
      );
      assert.deepEqual(await allHostKeyRows(ctx.db), snapshot, '[判定] User 角色遍历全部可达路由后 ssh_host_keys 快照应不变（§92 第 11 条）');
      assert.equal(
        hostKeyAuditBy(await auditEvents(ctx.db), topo.alice.id).length,
        hostKeyAuditBefore,
        '[判定] User 角色的路由调用不应产生 HOST_KEY_* 事件',
      );

      // The changed state still blocks a later connection with either fingerprint (§42).
      const later = await newHostKeyDo(ctx, assetId, { userId: topo.alice.id, username: topo.alice.username });
      assert.equal((await presentHostKey(later, state.trusted)).accepted, false, '[判定] 路由遍历后出示原指纹仍应被阻止（§42）');
      assert.equal((await presentHostKey(later, state.rogue)).accepted, false, '[判定] 路由遍历后出示变化指纹仍应被阻止（§42）');
      assert.equal((await hostKeyRows(ctx.db, assetId))[0]?.status, 'changed', '[判定] 路由遍历后状态应保持 changed（§42）');
    });
  });

  it('[SEC-11] Security Auditor 调用 host-key reset 返回 403 且 changed 记录不变', async () => {
    await withContext(async (ctx) => {
      const topo = await seedDemoTopology(ctx, `EJ-SECRET-${randomKeyHex()}`);
      await driveHostKeyToChanged(ctx, topo.prodWeb01.id, topo.alice);
      const snapshot = await allHostKeyRows(ctx.db);

      const res = await api(ctx, 'POST', `/api/admin/assets/${topo.prodWeb01.id}/host-key/reset`, {
        cookie: topo.auditor.cookie,
        body: {},
      });
      assert.equal(res.status, 403, '[判定] Security Auditor（无 asset.update）调用 host-key reset 应返回 403（§12、§42）');
      assert.deepEqual(await allHostKeyRows(ctx.db), snapshot, '[判定] 被拒绝的 reset 不应改变 ssh_host_keys');
      assert.equal(hostKeyAuditBy(await auditEvents(ctx.db), topo.auditor.id).length, 0, '[判定] 被拒绝的 reset 不应产生 HOST_KEY_* 事件');
    });
  });

  // Positive control for the two SEC-11 negatives above: the reset route is reachable and effective for Asset Admin.
  it('[SEC-11] 正向对照：Asset Admin 调用 host-key reset 返回 200 并写 HOST_KEY_* 审计', async () => {
    await withContext(async (ctx) => {
      const topo = await seedDemoTopology(ctx, `EJ-SECRET-${randomKeyHex()}`);
      const assetId = topo.prodWeb01.id;
      await driveHostKeyToChanged(ctx, assetId, topo.alice);

      const res = await api(ctx, 'POST', `/api/admin/assets/${assetId}/host-key/reset`, { cookie: topo.assetAdmin.cookie, body: {} });
      assert.equal(res.status, 200, '[判定] Asset Admin（asset.update）调用 host-key reset 应返回 200（§41、§42）');

      const events = hostKeyAuditBy(await auditEvents(ctx.db), topo.assetAdmin.id);
      assert.equal(events.length, 1, '[判定] Asset Admin reset 应写入一条 HOST_KEY_* 审计事件（§57）');
      assert.equal(events[0].result, 'success', '[判定] reset 审计事件的 result 应为 success');
      assert.equal(events[0].resourceId, assetId, 'observation: the reset audit event references the asset id');
      assert.equal(events[0].action, 'HOST_KEY_RESET', 'observation: reset is audited as HOST_KEY_CHANGED (no dedicated reset action)');
      assert.ok(
        (await hostKeyRows(ctx.db, assetId)).every((row) => row.status !== 'changed'),
        '[判定] Asset Admin reset 后资产应解除 changed 阻断状态（§42 管理员手动重新确认路径）',
      );
    });
  });

  // -----------------------------------------------------------
  // Task 9.3: observation of the reset → TOFU path (L9, EXT-008)
  // -----------------------------------------------------------

  // Observation test: not a numbered Property and contains no [判定] assertions. It records the status quo of
  // the Asset Admin host-key reset so that tasks 4.6 (EXT-008 checklist key `reset_then_tofu`) and 14.2 can
  // judge whether §42 "必须 Asset Admin 手动重新确认" is met; static review 4.2 judged HK-015 partial on this
  // basis. resetHostKeyForAsset() deletes every ssh_host_keys row of the asset and audits HOST_KEY_CHANGED
  // without any fingerprint (src/assets/asset-service.ts:649-672); the next connection's processHostKeyTOFU()
  // finds no row and auto-trusts whatever key it is shown as verified_by = 'system-tofu'
  // (src/durable/SSHSessionDO.ts:914-942), including the rogue key that caused 'changed'. The admin therefore
  // never sees or confirms a specific fingerprint. The assertions describe current behaviour and pass with it.
  it('[SEC-11] reset cannot reopen TOFU; approval is bound to the observed algorithm and fingerprint', async () => {
    await withContext(async (ctx) => {
      const topo = await seedDemoTopology(ctx, 'reset-regression-key');
      const state = await driveHostKeyToChanged(ctx, topo.prodWeb01.id, topo.alice);
      const path = `/api/admin/assets/${topo.prodWeb01.id}/host-key`;
      assert.equal((await api(ctx, 'POST', `${path}/reset`, { cookie: topo.assetAdmin.cookie })).status, 200);
      assert.equal((await hostKeyRows(ctx.db, topo.prodWeb01.id)).length, 1);
      const later = await newHostKeyDo(ctx, topo.prodWeb01.id, { userId: topo.alice.id });
      assert.equal((await presentHostKey(later, state.rogue)).accepted, false);
      const invalid = await api(ctx, 'POST', `${path}/approve`, { cookie: topo.assetAdmin.cookie, body: { algorithm: state.rogue.algorithm, fingerprint: 'SHA256:unobserved' } });
      assert.equal(invalid.status, 400);
      const approved = await api(ctx, 'POST', `${path}/approve`, { cookie: topo.assetAdmin.cookie, body: { algorithm: state.rogue.algorithm, fingerprint: state.rogue.fingerprint } });
      assert.equal(approved.status, 200);
      const fresh = await newHostKeyDo(ctx, topo.prodWeb01.id, { userId: topo.alice.id });
      assert.equal((await presentHostKey(fresh, state.rogue)).accepted, true);
      assert.equal((await hostKeyRows(ctx.db, topo.prodWeb01.id))[0].verified_by, topo.assetAdmin.id);
    });
  });
});
