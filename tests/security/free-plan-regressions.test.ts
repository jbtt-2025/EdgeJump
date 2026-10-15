import test from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2Sync } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { api, createContext, insertUser, seedDemoTopology, seedSessionMetadata } from '../compliance-helpers.ts';
import { verifyPassword, hashPassword } from '../../src/crypto/password.ts';
import { hashUserPassword } from '../../src/auth/password-service.ts';
import { cleanupExpiredRecordings, CLEANUP_OBJECT_BUDGET } from '../../src/sessions/cleanup-service.ts';
import { getSessionRecording } from '../../src/sessions/session-service.ts';
import { RateLimitDO } from '../../src/durable/RateLimitDO.ts';
import { SSHSessionDO } from '../../src/durable/SSHSessionDO.ts';

test('portable PBKDF2 preserves native hashes, pepper and legacy parameters under the managed native cap', async (t) => {
  const password = '兼容-password-42!';
  const pepper = 'test-secret-pepper';
  const salt = '00112233445566778899aabbccddeeff';
  const expected = Buffer.from(pbkdf2Sync(password + pepper, Buffer.from(salt, 'hex'), 600_000, 32, 'sha256')).toString('hex');
  const native = t.mock.method(crypto.subtle, 'deriveBits', () => { throw new DOMException('iteration counts above 100000 are not supported', 'NotSupportedError'); });
  assert.equal(await verifyPassword(password, pepper, expected, salt, 600_000), true);
  assert.equal(await verifyPassword('wrong', pepper, expected, salt, 600_000), false);
  const legacy = Buffer.from(pbkdf2Sync(password + pepper, Buffer.from(salt, 'hex'), 100_000, 32, 'sha256')).toString('hex');
  assert.equal(await verifyPassword(password, pepper, legacy, salt, 100_000), true);
  const generated = await hashPassword(password, pepper);
  assert.equal(generated.iterations, 600_000);
  assert.equal(generated.hash, Buffer.from(pbkdf2Sync(password + pepper, Buffer.from(generated.salt, 'hex'), 600_000, 32, 'sha256')).toString('hex'));
  assert.equal(native.mock.callCount(), 0);
  await assert.rejects(verifyPassword(password, pepper, expected, salt, -1));
});

test('KDF service failure returns 503 and refunds only its reservations, preserving real failure history', async () => {
  const ctx = await createContext();
  try {
    const user = await insertUser(ctx.db, { username: 'kdf-user' });
    const keys = ['ip:203.0.113.25', `user:${user.username}`];
    for (const key of keys) for (let i = 0; i < 4; i++) {
      await ctx.env.RATE_LIMIT.get(ctx.env.RATE_LIMIT.idFromName(key)).fetch('https://ratelimit.internal/attempt', { method: 'POST', body: JSON.stringify({ key }) });
    }
    ctx.env.PASSWORD_KDF = { idFromName: (name: string) => name, get: () => ({ fetch: async () => Response.json({ error: 'sensitive internal error' }, { status: 503 }) }) } as unknown as DurableObjectNamespace;
    const response = await api(ctx, 'POST', '/api/auth/login', { headers: { 'CF-Connecting-IP': '203.0.113.25' }, body: { username: user.username, password: 'valid-length-password' } });
    assert.equal(response.status, 503);
    assert.ok(!JSON.stringify(response.json).includes('sensitive internal error'));
    for (const key of keys) {
      const check = await ctx.env.RATE_LIMIT.get(ctx.env.RATE_LIMIT.idFromName(key)).fetch(`https://ratelimit.internal/check?key=${encodeURIComponent(key)}`);
      assert.equal((await check.json<any>()).totalFailedInWindow, 4);
    }
    assert.equal((await ctx.db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action = 'LOGIN_FAILED' OR action = 'LOGIN_LOCKED'").first<any>()).count, 0);
    assert.equal((await ctx.db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action = 'AUTH_SERVICE_UNAVAILABLE'").first<any>()).count, 1);
    ctx.env.PASSWORD_KDF = undefined as any;
    await assert.rejects(hashUserPassword(user.id, 'password', ctx.env), /Password service unavailable/);
  } finally { await ctx.cleanup(); }
});

test('reservation refunds distinguish attempts recorded in the same millisecond and survive a restart', async () => {
  const stored = new Map<string, unknown>();
  const state = { storage: { get: async (key: string) => stored.get(key), put: async (key: string, value: unknown) => stored.set(key, structuredClone(value)), delete: async (key: string) => stored.delete(key) } } as unknown as DurableObjectState;
  let limiter = new RateLimitDO(state);
  const attempt = async () => (await (await limiter.fetch(new Request('https://internal/attempt', { method: 'POST', body: JSON.stringify({ key: 'user:test' }) }))).json<any>()).reservationId;
  const [first, second] = await Promise.all([attempt(), attempt()]);
  assert.notEqual(first, second);
  limiter = new RateLimitDO(state);
  for (let i = 0; i < 2; i++) await limiter.fetch(new Request('https://internal/refund', { method: 'POST', body: JSON.stringify({ key: 'user:test', reservationId: second }) }));
  assert.equal((await limiter.check('user:test')).totalFailedInWindow, 1);
});

test('large recording cleanup stays below the Free request budget and resumes with persisted cursors', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'test-private-key');
    const sessionId = `sess_${crypto.randomUUID()}`;
    await seedSessionMetadata(ctx.db, { sessionId, userId: topo.alice.id, assetId: topo.prodWeb01.id, accountId: topo.deploy.id });
    await ctx.db.prepare("INSERT INTO system_settings (key, value, updated_at) VALUES ('recording_retention_days', '1', 0) ON CONFLICT(key) DO UPDATE SET value = '1'").run();
    const prefix = `recordings/test/${sessionId}`;
    await ctx.db.prepare("UPDATE ssh_sessions SET status = 'closed', ended_at = 1, recording_status = 'completed', recording_path = ? WHERE id = ?").bind(prefix, sessionId).run();
    const objects = new Set([`${prefix}/manifest.json`, ...Array.from({ length: 85 }, (_, i) => `${prefix}/chunk-${String(i + 1).padStart(6, '0')}.jsonl.gz`)]);
    const deleted: string[] = [];
    let operations = 0;
    let manifestReads = 0;
    ctx.env.RECORDINGS = {
      async get() { operations++; manifestReads++; return { json: async () => ({ chunkCount: 85 }) }; },
      async delete(key: string) { operations++; deleted.push(key); objects.delete(key); },
    } as unknown as R2Bucket;
    let result = await cleanupExpiredRecordings(ctx.env);
    assert.equal(result.storageOperations, CLEANUP_OBJECT_BUDGET);
    assert.equal(operations, CLEANUP_OBJECT_BUDGET);
    assert.equal(result.cleanedCount, 0);
    assert.equal(result.budgetExhausted, true);
    assert.ok(objects.has(`${prefix}/manifest.json`));
    assert.equal((await ctx.db.prepare('SELECT next_chunk FROM recording_cleanup_jobs WHERE session_id = ?').bind(sessionId).first<any>()).next_chunk, 40);
    assert.equal(await getSessionRecording(sessionId, ctx.env), null);
    assert.equal((await ctx.db.prepare('SELECT recording_status FROM ssh_sessions WHERE id = ?').bind(sessionId).first<any>()).recording_status, 'completed');
    for (let i = 0; i < 2; i++) {
      operations = 0;
      result = await cleanupExpiredRecordings(ctx.env);
      assert.ok(operations <= CLEANUP_OBJECT_BUDGET);
      assert.equal(result.storageOperations, operations);
    }
    assert.equal(result.cleanedCount, 1);
    assert.equal(manifestReads, 1);
    assert.equal(objects.size, 0);
    assert.equal(new Set(deleted).size, deleted.length);
    assert.equal((await ctx.db.prepare('SELECT recording_status, recording_path FROM ssh_sessions WHERE id = ?').bind(sessionId).first<any>()).recording_status, 'expired');
    assert.equal(await ctx.db.prepare('SELECT session_id FROM recording_cleanup_jobs WHERE session_id = ?').bind(sessionId).first(), null);
  } finally { await ctx.cleanup(); }
});

test('S3 cleanup leaves a retry cursor after one failed request instead of hidden SDK retries', async (t) => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'test-private-key');
    const sessionId = `sess_${crypto.randomUUID()}`;
    await seedSessionMetadata(ctx.db, { sessionId, userId: topo.alice.id, assetId: topo.prodWeb01.id, accountId: topo.deploy.id });
    await ctx.db.prepare("INSERT INTO system_settings (key, value, updated_at) VALUES ('recording_retention_days', '1', 0) ON CONFLICT(key) DO UPDATE SET value = '1'").run();
    await ctx.db.prepare("UPDATE ssh_sessions SET status = 'closed', ended_at = 1, recording_status = 'completed', recording_path = 'recordings/failed' WHERE id = ?").bind(sessionId).run();
    Object.assign(ctx.env, { S3_ENDPOINT: 'https://storage.test', S3_BUCKET: 'test', S3_ACCESS_KEY_ID: 'test-id', S3_SECRET_ACCESS_KEY: 'test-secret' });
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('unavailable', { status: 503 }));
    const result = await cleanupExpiredRecordings(ctx.env);
    assert.equal(fetch.mock.callCount(), 1);
    assert.equal(result.storageOperations, 1);
    assert.equal(result.cleanedCount, 0);
    const job = await ctx.db.prepare('SELECT next_chunk, lease_until FROM recording_cleanup_jobs WHERE session_id = ?').bind(sessionId).first<any>();
    assert.equal(job.next_chunk, 1);
    assert.ok(job.lease_until > Date.now());
    fetch.mock.restore();
  } finally { await ctx.cleanup(); }
});

test('overlapping cleanup has one owner and a failed slice resumes after its last successful deletion', async () => {
  const ctx = await createContext();
  let releaseManifest: () => void = () => {};
  try {
    const topo = await seedDemoTopology(ctx, 'test-private-key');
    const sessionId = `sess_${crypto.randomUUID()}`;
    await seedSessionMetadata(ctx.db, { sessionId, userId: topo.alice.id, assetId: topo.prodWeb01.id, accountId: topo.deploy.id });
    await ctx.db.prepare("INSERT INTO system_settings (key, value, updated_at) VALUES ('recording_retention_days', '1', 0)").run();
    await ctx.db.prepare("UPDATE ssh_sessions SET status = 'closed', ended_at = 1, recording_status = 'completed', recording_path = 'recordings/retry' WHERE id = ?").bind(sessionId).run();
    let notifyGet: () => void = () => {};
    const started = new Promise<void>((resolve) => { notifyGet = resolve; });
    const gate = new Promise<void>((resolve) => { releaseManifest = resolve; });
    let failLastChunk = true;
    const deleted: string[] = [];
    ctx.env.RECORDINGS = {
      async get() { notifyGet(); await gate; return { json: async () => ({ chunkCount: 3 }) }; },
      async delete(key: string) { if (failLastChunk && key.includes('000003')) throw new Error('Temporary provider error'); deleted.push(key); },
    } as unknown as R2Bucket;
    const first = cleanupExpiredRecordings(ctx.env);
    await started;
    const overlap = await cleanupExpiredRecordings(ctx.env);
    assert.equal(overlap.storageOperations, 0);
    releaseManifest();
    assert.equal((await first).cleanedCount, 0);
    assert.equal((await ctx.db.prepare('SELECT next_chunk FROM recording_cleanup_jobs WHERE session_id = ?').bind(sessionId).first<any>()).next_chunk, 3);
    assert.equal((await ctx.db.prepare('SELECT recording_path FROM ssh_sessions WHERE id = ?').bind(sessionId).first<any>()).recording_path, 'recordings/retry');
    failLastChunk = false;
    await ctx.db.prepare('UPDATE recording_cleanup_jobs SET lease_until = 0 WHERE session_id = ?').bind(sessionId).run();
    const resumed = await cleanupExpiredRecordings(ctx.env);
    assert.equal(resumed.cleanedCount, 1);
    assert.equal(resumed.storageOperations, 2);
    assert.equal(new Set(deleted).size, 4);
    assert.equal(deleted.length, 4);
  } finally { releaseManifest(); await ctx.cleanup(); }
});

test('frequent activity preserves the idle deadline without creating a timer for every output packet', (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 1_000 });
  const session = new SSHSessionDO() as any;
  const closes: string[] = [];
  session.idleTimeoutMs = 100;
  session.handleSessionClose = async (_status: string, reason: string) => { closes.push(reason); };
  session.resetIdleTimer();
  const timer = session.idleTimer;
  t.mock.timers.tick(90);
  for (let i = 0; i < 1_000; i++) session.resetIdleTimer();
  assert.equal(session.idleTimer, timer);
  t.mock.timers.tick(10);
  assert.deepEqual(closes, []);
  t.mock.timers.tick(89);
  assert.deepEqual(closes, []);
  t.mock.timers.tick(1);
  assert.deepEqual(closes, ['idle_timeout']);
});
