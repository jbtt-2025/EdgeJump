// Unit & Integration Tests for Demo Mode Restrictions and Recording Retention Lifecycle Cleanup

import test from 'node:test';
import assert from 'node:assert/strict';
import { createTestDatabase } from './mock-d1.ts';
import { createPasswordKdfNamespace } from './password-kdf-fixture.ts';
import { handleApiRequest } from '../src/api/router.ts';
import { cleanupExpiredRecordings } from '../src/sessions/cleanup-service.ts';
import { createUser } from '../src/users/user-service.ts';
import { COOKIE_NAME } from '../src/auth/auth-service.ts';
import { hashToken } from '../src/crypto/token.ts';
import { R2RecordingStorage, S3RecordingStorage, type RecordingStorage } from '../src/storage/recording-storage.ts';

async function setupTestContext(deployType: 'production' | 'demo' = 'demo') {
  const db = await createTestDatabase();
  const env: any = {
    DB: db,
    DEPLOY_TYPE: deployType,
    AUTH_PEPPER: 'test-pepper',
    PASSWORD_KDF: createPasswordKdfNamespace('test-pepper'),
    CREDENTIAL_KEK_V1: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
  };

  // 1. Create super admin
  const admin = await createUser(
    {
      username: 'admin',
      password: 'AdminPassword123!',
      displayName: 'Super Administrator',
      roles: ['Super Admin'],
    },
    'system',
    env
  );

  await db.prepare('UPDATE users SET mfa_enabled = 1 WHERE id = ?').bind(admin.id).run();
  // 2. Create regular user
  const developer = await createUser(
    {
      username: 'developer01',
      password: 'DevPassword123!',
      displayName: 'Dev User',
      roles: ['User'],
    },
    admin.id,
    env
  );

  // 3. Create active session for admin
  const adminToken = 'admin-test-token-32-chars-length!!';
  const tokenHash = await hashToken(adminToken);
  const now = Date.now();
  await db
    .prepare(
      'INSERT INTO auth_sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, ip) VALUES (?, ?, ?, ?, ?, ?, ?)'
    )
    .bind('sess_admin', admin.id, tokenHash, now, now, now + 3600000, '127.0.0.1')
    .run();

  return { env, db, admin, developer, adminToken };
}

test('demo mode: blocks modifying admin password while allowing regular user password reset', async () => {
  const { env, admin, developer, adminToken } = await setupTestContext('demo');

  // Attempt to reset admin password in demo mode -> 403
  const resetAdminReq = new Request(`https://bastion.test/api/admin/users/${admin.id}/reset-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://bastion.test',
      Cookie: `${COOKIE_NAME}=${adminToken}; __Host-edgejump_csrf=${'a'.repeat(64)}`,
      'X-CSRF-Token': 'a'.repeat(64),
    },
    body: JSON.stringify({ password: 'NewAdminPassword999!' }),
  });
  const resetAdminRes = await handleApiRequest(resetAdminReq, env);
  assert.equal(resetAdminRes.status, 403);
  const errBody = await resetAdminRes.json<any>();
  assert.match(errBody.error, /演示模式下禁止修改管理员密码/);

  // Attempt to disable admin in demo mode -> 403
  const disableAdminReq = new Request(`https://bastion.test/api/admin/users/${admin.id}/disable`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://bastion.test',
      Cookie: `${COOKIE_NAME}=${adminToken}; __Host-edgejump_csrf=${'a'.repeat(64)}`,
      'X-CSRF-Token': 'a'.repeat(64),
    },
  });
  const disableAdminRes = await handleApiRequest(disableAdminReq, env);
  assert.equal(disableAdminRes.status, 403);
  const disableErr = await disableAdminRes.json<any>();
  assert.match(disableErr.error, /演示模式下禁止禁用管理员账号/);

  // Attempt to reset regular user password in demo mode -> 200 OK
  const resetDevReq = new Request(`https://bastion.test/api/admin/users/${developer.id}/reset-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://bastion.test',
      Cookie: `${COOKIE_NAME}=${adminToken}; __Host-edgejump_csrf=${'a'.repeat(64)}`,
      'X-CSRF-Token': 'a'.repeat(64),
    },
    body: JSON.stringify({ password: 'NewDevPassword999!' }),
  });
  const resetDevRes = await handleApiRequest(resetDevReq, env);
  assert.equal(resetDevRes.status, 200);
});

test('demo mode: blocks modifying recording_retention_days while allowing other settings', async () => {
  const { env, adminToken } = await setupTestContext('demo');

  // Attempt to update recording_retention_days in demo mode -> 403
  const updateRetentionReq = new Request('https://bastion.test/api/admin/settings', {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://bastion.test',
      Cookie: `${COOKIE_NAME}=${adminToken}; __Host-edgejump_csrf=${'a'.repeat(64)}`,
      'X-CSRF-Token': 'a'.repeat(64),
    },
    body: JSON.stringify({ key: 'recording_retention_days', value: '30' }),
  });
  const updateRetentionRes = await handleApiRequest(updateRetentionReq, env);
  assert.equal(updateRetentionRes.status, 403);
  const retErr = await updateRetentionRes.json<any>();
  assert.match(retErr.error, /演示模式下禁止修改录像保留时间/);

  // Attempt to update session_idle_timeout in demo mode -> 200 OK
  const updateTimeoutReq = new Request('https://bastion.test/api/admin/settings', {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://bastion.test',
      Cookie: `${COOKIE_NAME}=${adminToken}; __Host-edgejump_csrf=${'a'.repeat(64)}`,
      'X-CSRF-Token': 'a'.repeat(64),
    },
    body: JSON.stringify({ key: 'session_idle_timeout', value: '900' }),
  });
  const updateTimeoutRes = await handleApiRequest(updateTimeoutReq, env);
  assert.equal(updateTimeoutRes.status, 200);
});

test('production mode: allows modifying admin password and recording_retention_days', async () => {
  const { env, admin, adminToken } = await setupTestContext('production');

  // 1. Update recording_retention_days in production mode -> 200 OK
  const updateRetentionReq = new Request('https://bastion.test/api/admin/settings', {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://bastion.test',
      Cookie: `${COOKIE_NAME}=${adminToken}; __Host-edgejump_csrf=${'a'.repeat(64)}`,
      'X-CSRF-Token': 'a'.repeat(64),
    },
    body: JSON.stringify({ key: 'recording_retention_days', value: '14' }),
  });
  const updateRetentionRes = await handleApiRequest(updateRetentionReq, env);
  assert.equal(updateRetentionRes.status, 200);

  // 2. Reset admin password in production mode -> 200 OK
  const resetAdminReq = new Request(`https://bastion.test/api/admin/users/${admin.id}/reset-password`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://bastion.test',
      Cookie: `${COOKIE_NAME}=${adminToken}; __Host-edgejump_csrf=${'a'.repeat(64)}`,
      'X-CSRF-Token': 'a'.repeat(64),
    },
    body: JSON.stringify({ password: 'NewAdminPassword999!' }),
  });
  const resetAdminRes = await handleApiRequest(resetAdminReq, env);
  assert.equal(resetAdminRes.status, 200);
});

test('lifecycle cleanup: purges expired session recordings from storage and updates D1 status', async () => {
  const { env, db } = await setupTestContext('production');

  await db.prepare("INSERT INTO system_settings (key, value, updated_at) VALUES ('recording_retention_days', '7', 0) ON CONFLICT(key) DO UPDATE SET value = '7'").run();
  // Create mock storage tracker
  const storedObjects = new Map<string, any>();
  const mockStorage: RecordingStorage = {
    async put(key: string, value: any) {
      storedObjects.set(key, value);
    },
    async get(key: string) {
      if (!storedObjects.has(key)) return null;
      const val = storedObjects.get(key);
      return {
        json: async () => (typeof val === 'string' ? JSON.parse(val) : val),
        text: async () => String(val),
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    },
    async delete(key: string) {
      storedObjects.delete(key);
    },
  };

  // Seed storage for expired session (10 days old)
  const expiredSessionId = 'sess_expired_10d';
  const expiredPrefix = `recordings/2026/09/29/${expiredSessionId}`;
  storedObjects.set(`${expiredPrefix}/manifest.json`, JSON.stringify({ chunkCount: 2 }));
  storedObjects.set(`${expiredPrefix}/chunk-000001.jsonl.gz`, 'chunk1-data');
  storedObjects.set(`${expiredPrefix}/chunk-000002.jsonl.gz`, 'chunk2-data');

  // Seed storage for unexpired session (1 day old)
  const unexpiredSessionId = 'sess_unexpired_1d';
  const unexpiredPrefix = `recordings/2026/10/08/${unexpiredSessionId}`;
  storedObjects.set(`${unexpiredPrefix}/manifest.json`, JSON.stringify({ chunkCount: 1 }));
  storedObjects.set(`${unexpiredPrefix}/chunk-000001.jsonl.gz`, 'unexpired-chunk');

  const now = Date.now();
  const tenDaysAgo = now - 10 * 86400 * 1000;
  const oneDayAgo = now - 1 * 86400 * 1000;

  // Insert both sessions into D1
  await db
    .prepare(
      `INSERT INTO ssh_sessions (id, user_id, username_snapshot, asset_id, asset_name_snapshot, account_id, account_name_snapshot, source_ip, status, started_at, ended_at, recording_status, recording_path, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      expiredSessionId,
      'usr_1',
      'developer01',
      'ast_1',
      'prod-server',
      'acc_1',
      'root',
      '127.0.0.1',
      'closed',
      tenDaysAgo - 1800000,
      tenDaysAgo,
      'completed',
      expiredPrefix,
      tenDaysAgo - 1800000
    )
    .run();

  await db
    .prepare(
      `INSERT INTO ssh_sessions (id, user_id, username_snapshot, asset_id, asset_name_snapshot, account_id, account_name_snapshot, source_ip, status, started_at, ended_at, recording_status, recording_path, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      unexpiredSessionId,
      'usr_1',
      'developer01',
      'ast_1',
      'prod-server',
      'acc_1',
      'root',
      '127.0.0.1',
      'closed',
      oneDayAgo - 1800000,
      oneDayAgo,
      'completed',
      unexpiredPrefix,
      oneDayAgo - 1800000
    )
    .run();

  // Attach mock storage as R2Bucket
  env.RECORDINGS = {
    put: (k: string, v: any) => mockStorage.put(k, v),
    get: (k: string) => mockStorage.get(k),
    delete: (k: string) => mockStorage.delete(k),
  } as any;

  // Run cleanup with default 7 days retention
  const cleanupRes = await cleanupExpiredRecordings(env, 'test');
  assert.equal(cleanupRes.cleanedCount, 1);
  assert.deepEqual(cleanupRes.expiredSessionIds, [expiredSessionId]);

  // Check expired files deleted from storage
  assert.equal(storedObjects.has(`${expiredPrefix}/manifest.json`), false);
  assert.equal(storedObjects.has(`${expiredPrefix}/chunk-000001.jsonl.gz`), false);
  assert.equal(storedObjects.has(`${expiredPrefix}/chunk-000002.jsonl.gz`), false);

  // Check unexpired files remain in storage
  assert.equal(storedObjects.has(`${unexpiredPrefix}/manifest.json`), true);
  assert.equal(storedObjects.has(`${unexpiredPrefix}/chunk-000001.jsonl.gz`), true);

  // Check D1 expired session status changed to 'expired' and recording_path is null
  const expiredRow = await db
    .prepare('SELECT recording_status, recording_path FROM ssh_sessions WHERE id = ?')
    .bind(expiredSessionId)
    .first<any>();
  assert.equal(expiredRow.recording_status, 'expired');
  assert.equal(expiredRow.recording_path, null);

  // Check D1 unexpired session status remains 'completed'
  const unexpiredRow = await db
    .prepare('SELECT recording_status, recording_path FROM ssh_sessions WHERE id = ?')
    .bind(unexpiredSessionId)
    .first<any>();
  assert.equal(unexpiredRow.recording_status, 'completed');
  assert.equal(unexpiredRow.recording_path, unexpiredPrefix);
});
