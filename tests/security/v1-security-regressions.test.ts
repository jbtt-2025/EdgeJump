import test from 'node:test';
import assert from 'node:assert/strict';
import { api, createContext, insertUser, issueCookie, seedDemoTopology, seedSessionMetadata } from '../compliance-helpers.ts';
import { resetUserPassword } from '../../src/users/user-service.ts';
import { hashToken } from '../../src/crypto/token.ts';
import { generateTotpCode } from '../../src/crypto/totp.ts';
import { getSessionCredential } from '../../src/credentials/credential-service.ts';
import { setCustomDnsResolver } from '../../src/backend/security.ts';
import { createSshFixture, eventually } from '../ssh-fixture.ts';
import { SSHSessionDO } from '../../src/durable/SSHSessionDO.ts';
import { SessionRecorder, computeChunkHash, computeRollingHash, decompressGzip } from '../../src/durable/recording.ts';
import { cleanupExpiredRecordings } from '../../src/sessions/cleanup-service.ts';

test('MFA settings report policy and require password plus TOTP before an eligible user disables MFA', async () => {
  const ctx = await createContext();
  try {
    const user = await insertUser(ctx.db, { username: 'mfa-settings-user' });
    const admin = await insertUser(ctx.db, { username: 'mfa-settings-admin', roles: ['Super Admin'] });
    const password = 'Mfa-settings-test-password-42!';
    await resetUserPassword(user.id, password, user.id, ctx.env);
    await ctx.db.prepare('UPDATE users SET mfa_enabled = 0 WHERE id = ?').bind(user.id).run();
    const cookie = await issueCookie(ctx.db, user.id);
    const adminCookie = await issueCookie(ctx.db, admin.id);
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie })).json.user.mfaRequired, false);
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie: adminCookie })).json.user.mfaRequired, true);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa/disable', { cookie: adminCookie, body: {} })).status, 403);

    const setup = await api(ctx, 'POST', '/api/auth/mfa/setup', { cookie });
    assert.equal(setup.status, 200);
    const code = await generateTotpCode(setup.json.secret);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa/confirm', { cookie, body: { code } })).status, 200);
    assert.equal((await api(ctx, 'PATCH', '/api/admin/settings', { cookie: adminCookie, body: { key: 'require_mfa_for_all', value: 'true' } })).status, 200);
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie })).json.user.mfaRequired, true);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa/disable', { cookie, body: { password, code } })).status, 403);
    assert.equal((await api(ctx, 'PATCH', '/api/admin/settings', { cookie: adminCookie, body: { key: 'require_mfa_for_all', value: 'false' } })).status, 200);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa/disable', { cookie, body: { password: 'wrong-password', code } })).status, 403);
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie })).json.user.mfaEnabled, true);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa/disable', { cookie, body: { password, code } })).status, 200);
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie })).json.user.mfaEnabled, false);
    const row = await ctx.db.prepare('SELECT totp_secret_ciphertext, totp_secret_nonce FROM users WHERE id = ?').bind(user.id).first<any>();
    assert.equal(row.totp_secret_ciphertext, null);
    assert.equal(row.totp_secret_nonce, null);
    assert.equal((await ctx.db.prepare('SELECT COUNT(*) AS count FROM mfa_recovery_codes WHERE user_id = ?').bind(user.id).first<any>()).count, 0);
    assert.equal((await ctx.db.prepare("SELECT actor_user_id FROM audit_events WHERE action = 'MFA_DISABLED'").first<any>()).actor_user_id, user.id);
  } finally { await ctx.cleanup(); }
});

test('MFA challenge is IP-bound, expires, and is consumed once under concurrent completion', async () => {
  const ctx = await createContext();
  try {
    const user = await insertUser(ctx.db, { username: 'mfa-user' });
    await resetUserPassword(user.id, 'A-valid-test-password', user.id, ctx.env);
    await ctx.db.prepare('UPDATE users SET mfa_enabled = 0 WHERE id = ?').bind(user.id).run();
    const cookie = await issueCookie(ctx.db, user.id);
    const setup = await api(ctx, 'POST', '/api/auth/mfa/setup', { cookie });
    assert.equal(setup.status, 200);
    const code = await generateTotpCode(setup.json.secret);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa/confirm', { cookie, body: { code } })).status, 200);
    const first = await api(ctx, 'POST', '/api/auth/login', { body: { username: user.username, password: 'A-valid-test-password' } });
    assert.equal(first.json.mfaRequired, true);
    assert.equal(first.headers.get('set-cookie'), null);
    const challengeToken = first.json.challengeToken;
    const stored = await ctx.db.prepare('SELECT * FROM auth_mfa_challenges WHERE token_hash = ?').bind(await hashToken(challengeToken)).first<any>();
    assert.ok(stored);
    assert.ok(!JSON.stringify(stored).includes(challengeToken));
    const body = { challengeToken, totpCode: code };
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa', { headers: { 'CF-Connecting-IP': '203.0.113.99' }, body })).status, 401);
    const concurrent = await Promise.all([api(ctx, 'POST', '/api/auth/mfa', { body }), api(ctx, 'POST', '/api/auth/mfa', { body })]);
    assert.equal(concurrent.filter((response) => response.status === 200).length, 1);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa', { body })).status, 401);
    const expired = await api(ctx, 'POST', '/api/auth/login', { body: { username: user.username, password: 'A-valid-test-password' } });
    await ctx.db.prepare('UPDATE auth_mfa_challenges SET expires_at = 0 WHERE token_hash = ?').bind(await hashToken(expired.json.challengeToken)).run();
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa', { body: { challengeToken: expired.json.challengeToken, totpCode: code } })).status, 401);
  } finally { await ctx.cleanup(); }
});

test('DO restart fails the old TCP session without starting a new recorder or overwriting stored chunks', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'test-private-key');
    const config = { sessionId: `sess_${crypto.randomUUID()}`, userId: topo.alice.id, assetId: topo.prodWeb01.id, accountId: topo.deploy.id,
      host: '8.8.8.8', port: 22, username: 'deploy', createdAt: Date.now() };
    await seedSessionMetadata(ctx.db, config);
    await ctx.db.prepare("UPDATE ssh_sessions SET status = 'active' WHERE id = ?").bind(config.sessionId).run();
    const stored = new Map<string, unknown>([['config', config], ['connectionStarted', true]]);
    const instance = ctx.track(new SSHSessionDO({ storage: {
      async get(key: string) { return stored.get(key); },
      async put(key: string, value: unknown) { stored.set(key, value); },
      async deleteAll() { stored.clear(); },
    } } as unknown as DurableObjectState, ctx.env));
    const response = await instance.fetch(new Request('https://session.internal/status'));
    assert.equal((await response.json<any>()).status, 'failed');
    assert.equal(instance.getRecorder(), null);
    const row = await ctx.db.prepare('SELECT status, disconnect_reason FROM ssh_sessions WHERE id = ?').bind(config.sessionId).first<any>();
    assert.equal(row.disconnect_reason, 'runtime_restarted');
    assert.deepEqual(ctx.network.attempts, []);
  } finally { await ctx.cleanup(); }
});

test('overlapping size-triggered flushes and close preserve every event and the complete hash chain', async () => {
  const objects = new Map<string, Uint8Array>();
  const recorder = new SessionRecorder('concurrent-recording', {
    async put(key: string, data: Uint8Array | string) { await new Promise((resolve) => setImmediate(resolve)); objects.set(key, typeof data === 'string' ? new TextEncoder().encode(data) : data); },
    async get() { return null; }, async delete() {},
  });
  const writes = [recorder.recordEvent('stdout', 'A'.repeat(600 * 1024)), recorder.recordEvent('stdout', 'B'.repeat(600 * 1024))];
  const manifest = await recorder.close('closed');
  await Promise.all(writes);
  assert.equal(manifest.chunkCount, 3);
  let rolling: string | null = null;
  const sequences: number[] = [];
  for (const descriptor of manifest.chunks!) {
    const bytes = objects.get(descriptor.path)!;
    rolling = await computeRollingHash(rolling, await computeChunkHash(bytes));
    assert.equal(descriptor.rollingHash, rolling);
    const events = new TextDecoder().decode(await decompressGzip(bytes)).trim().split('\n').map((line) => JSON.parse(line));
    sequences.push(...events.map((event) => event.seq));
  }
  assert.deepEqual(sequences, [1, 2, 3]);
  assert.equal(manifest.finalHash, rolling);
});

test('immutable recording deletion fails visibly and preserves D1 recording metadata', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'test-private-key');
    const sessionId = `sess_${crypto.randomUUID()}`;
    await seedSessionMetadata(ctx.db, { sessionId, userId: topo.alice.id, assetId: topo.prodWeb01.id, accountId: topo.deploy.id });
    await ctx.db.prepare("INSERT INTO system_settings (key, value, updated_at) VALUES ('recording_retention_days', '1', 0) ON CONFLICT(key) DO UPDATE SET value = '1'").run();
    await ctx.db.prepare("UPDATE ssh_sessions SET status = 'closed', ended_at = 1, recording_status = 'completed', recording_path = 'recordings/locked' WHERE id = ?").bind(sessionId).run();
    ctx.env.RECORDINGS = { async get() { return { async json() { return { chunkCount: 1 }; } }; }, async delete() { throw new Error('Bucket Lock'); } } as unknown as R2Bucket;
    const result = await cleanupExpiredRecordings(ctx.env, 'manual', { actorUserId: topo.admin.id, actorUsername: 'admin' });
    assert.equal(result.cleanedCount, 0);
    const row = await ctx.db.prepare('SELECT recording_status, recording_path FROM ssh_sessions WHERE id = ?').bind(sessionId).first<any>();
    assert.equal(row.recording_status, 'completed');
    assert.equal(row.recording_path, 'recordings/locked');
    const failure = await ctx.db.prepare("SELECT actor_user_id, result FROM audit_events WHERE action = 'RECORDING_CLEANUP_FAILED'").first<any>();
    assert.equal(failure.actor_user_id, topo.admin.id);
    assert.equal(failure.result, 'failure');
  } finally { await ctx.cleanup(); }
});

test('login lockout normalizes usernames across source IPs and audits the fifth failure', async () => {
  const ctx = await createContext();
  try {
    const variants = ['No-Such-User', ' no-such-user ', 'NO-SUCH-USER', 'no-such-user', ' No-Such-User '];
    for (const [index, username] of variants.entries()) assert.equal((await api(ctx, 'POST', '/api/auth/login', {
      headers: { 'CF-Connecting-IP': `203.0.113.${index + 1}` }, body: { username, password: 'wrong-password' },
    })).status, 401);
    const locks = await ctx.db.prepare("SELECT metadata_json FROM audit_events WHERE action = 'LOGIN_LOCKED'").all<any>();
    assert.equal(locks.results.length, 1);
    assert.ok(locks.results[0].metadata_json.includes('attempt_limit_reached'));
    assert.equal((await api(ctx, 'POST', '/api/auth/login', { headers: { 'CF-Connecting-IP': '203.0.113.80' },
      body: { username: ' no-such-user ', password: 'wrong-password' } })).status, 429);
  } finally { await ctx.cleanup(); }
});

test('rewrap keeps the payload AAD version and uses only the current KEK at session authentication', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'test-private-key-content');
    ctx.env.CREDENTIAL_KEK_V2 = 'ab'.repeat(32);
    const before = await ctx.db.prepare('SELECT * FROM credentials WHERE id = ?').bind(topo.deployKey.id).first<any>();
    const response = await api(ctx, 'POST', `/api/admin/credentials/${topo.deployKey.id}/rewrap`, { cookie: topo.admin.cookie, body: { version: 'v2' } });
    assert.equal(response.status, 200);
    const after = await ctx.db.prepare('SELECT * FROM credentials WHERE id = ?').bind(topo.deployKey.id).first<any>();
    assert.equal(after.credential_ciphertext, before.credential_ciphertext);
    assert.notEqual(after.encrypted_dek, before.encrypted_dek);
    assert.equal(after.credential_key_version, 'v1');
    delete ctx.env.CREDENTIAL_KEK_V1;
    assert.equal((await getSessionCredential(topo.deployKey.id, ctx.env)).plaintext, 'test-private-key-content');
    ctx.env.CREDENTIAL_KEK_V2 = 'cd'.repeat(32);
    await assert.rejects(getSessionCredential(topo.deployKey.id, ctx.env));
  } finally { await ctx.cleanup(); }
});

test('DNS rebinding and mixed public/private answers cannot reach the TCP connector', async () => {
  const fx = await createSshFixture();
  try {
    const { ctx, topo } = fx;
    setCustomDnsResolver(async (_host, type) => type === 'A' ? ['8.8.8.8'] : []);
    assert.equal((await api(ctx, 'PATCH', `/api/admin/assets/${topo.prodWeb01.id}`, { cookie: topo.admin.cookie, body: { hostname: 'ssh.example.test' } })).status, 200);
    const created = await api(ctx, 'POST', '/api/sessions', { cookie: topo.alice.cookie, body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id } });
    setCustomDnsResolver(async (_host, type) => type === 'A' ? ['8.8.8.8', '127.0.0.1'] : []);
    assert.equal((await api(ctx, 'GET', created.json.wsUrl, { cookie: topo.alice.cookie, headers: { Upgrade: 'websocket' } })).status, 101);
    await eventually(async () => (await ctx.db.prepare('SELECT status FROM ssh_sessions WHERE id = ?').bind(created.json.sessionId).first<any>())?.status === 'failed', 'rebind rejection');
    assert.deepEqual(fx.connections, []);
  } finally { setCustomDnsResolver(); await fx.close(); }
});
