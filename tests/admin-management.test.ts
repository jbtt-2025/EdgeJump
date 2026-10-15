import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import { createTestDatabase } from './mock-d1.ts';
import {
  createUser,
  listUsers,
  updateUser,
  disableUser,
  enableUser,
  resetUserPassword,
  createGroup,
  listGroups,
  updateGroup,
  deleteGroup,
  listRoles,
} from '../src/users/user-service.ts';
import {
  getHostKeyForAsset,
  resetHostKeyForAsset,
  createAsset,
} from '../src/assets/asset-service.ts';
import {
  getSetting,
  getAllSettings,
  updateSetting,
} from '../src/settings/settings-service.ts';
import {
  getSessionDetail,
  getSessionCommands,
} from '../src/sessions/session-service.ts';
import type { Env } from '../src/types.ts';
import { createPasswordKdfNamespace } from './password-kdf-fixture.ts';

describe('Admin Management & Lifecycle (Sections 5, 13, 39, 41, 60, 70)', () => {
  let db: any;
  let env: Env;

  beforeEach(async () => {
    db = await createTestDatabase();
    env = {
      DB: db,
      SSH_SESSIONS: {
        idFromName: (name: string) => ({ toString: () => name }),
        get: () => ({
          fetch: async (request: Request) => { const body = await request.json() as any; await db.prepare("UPDATE ssh_sessions SET status = 'terminated', terminated_by = ? WHERE id = 'ssh-sess-1'").bind(body.actorId).run(); return Response.json({ success: true }); },
        }),
      } as any,
      RATE_LIMIT: {} as any,
      RECORDINGS: {} as any,
      KV_CACHE: {} as any,
      AUTH_PEPPER: 'test-admin-pepper',
      PASSWORD_KDF: createPasswordKdfNamespace('test-admin-pepper'),
      CREDENTIAL_KEK_V1: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    };
  });

  it('creates and lists users without exposing password hash or secrets', async () => {
    const user = await createUser(
      {
        username: 'alice',
        password: 'Password123!',
        displayName: 'Alice Developer',
        email: 'alice@example.com',
        roles: ['User'],
      },
      'admin-1',
      env
    );

    assert.strictEqual(user.username, 'alice');
    assert.strictEqual(user.displayName, 'Alice Developer');
    assert.strictEqual(user.status, 'active');

    const users = await listUsers(env.DB);
    const found = users.find((u) => u.username === 'alice');
    assert.ok(found);
    assert.strictEqual(found.displayName, 'Alice Developer');
    // Ensure no secret or password fields exist on UserSummary
    assert.strictEqual((found as any).password_hash, undefined);
    assert.strictEqual((found as any).password_salt, undefined);
  });

  it('updates user attributes and handles roles', async () => {
    const user = await createUser(
      { username: 'bob', password: 'Password123!', displayName: 'Bob' },
      'admin-1',
      env
    );

    await updateUser(
      user.id,
      { displayName: 'Bob Senior', email: 'bob@example.com', roles: ['Asset Admin'] },
      'admin-1',
      env.DB
    );

    const users = await listUsers(env.DB);
    const found = users.find((u) => u.id === user.id);
    assert.ok(found);
    assert.strictEqual(found.displayName, 'Bob Senior');
    assert.strictEqual(found.email, 'bob@example.com');
    assert.ok(found.roles.includes('Asset Admin'));
  });

  it('disables user, revoking login sessions and active SSH sessions per Section 60', async () => {
    const user = await createUser(
      { username: 'charlie', password: 'Password123!' },
      'admin-1',
      env
    );

    // Seed an active auth_session
    const tokenHash = 'fake-token-hash-charlie';
    await env.DB.prepare(
      'INSERT INTO auth_sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, ip) VALUES (?, ?, ?, ?, ?, ?, ?)'
    )
      .bind('sess-1', user.id, tokenHash, Date.now(), Date.now(), Date.now() + 3600000, '127.0.0.1')
      .run();

    // Seed an active SSH session
    await env.DB.prepare(
      `INSERT INTO ssh_sessions (
        id, user_id, username_snapshot, asset_id, asset_name_snapshot,
        account_id, account_name_snapshot, source_ip, started_at, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`
    )
      .bind('ssh-sess-1', user.id, 'charlie', 'asset-1', 'prod-web', 'acc-1', 'root', '127.0.0.1', Date.now(), Date.now())
      .run();

    // Disable the user
    await disableUser(user.id, 'admin-1', env);

    // Verify user status is disabled
    const users = await listUsers(env.DB);
    const found = users.find((u) => u.id === user.id);
    assert.strictEqual(found?.status, 'disabled');

    // Verify auth_session is revoked
    const authSess = await env.DB.prepare('SELECT revoked_at FROM auth_sessions WHERE id = ?')
      .bind('sess-1')
      .first<{ revoked_at: number }>();
    assert.ok(authSess?.revoked_at !== null && authSess?.revoked_at !== undefined);

    // Verify active SSH session was terminated
    const sshSess = await env.DB.prepare('SELECT status, disconnect_reason FROM ssh_sessions WHERE id = ?')
      .bind('ssh-sess-1')
      .first<{ status: string; disconnect_reason: string }>();
    assert.strictEqual(sshSess?.status, 'terminated');
  });

  it('resets password and invalidates existing sessions', async () => {
    const user = await createUser(
      { username: 'david', password: 'Password123!' },
      'admin-1',
      env
    );

    await env.DB.prepare(
      'INSERT INTO auth_sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, ip) VALUES (?, ?, ?, ?, ?, ?, ?)'
    )
      .bind('sess-david', user.id, 'hash-david', Date.now(), Date.now(), Date.now() + 3600000, '127.0.0.1')
      .run();

    await resetUserPassword(user.id, 'NewPassword456!', 'admin-1', env);

    const authSess = await env.DB.prepare('SELECT revoked_at FROM auth_sessions WHERE id = ?')
      .bind('sess-david')
      .first<{ revoked_at: number }>();
    assert.ok(authSess?.revoked_at !== null && authSess?.revoked_at !== undefined);
  });

  it('manages user groups and members', async () => {
    const grp = await createGroup({ name: 'DevOps', description: 'Operations Team' }, 'admin-1', env.DB);
    assert.strictEqual(grp.name, 'DevOps');

    let groups = await listGroups(env.DB);
    assert.strictEqual(groups.length, 1);
    assert.strictEqual(groups[0].memberCount, 0);

    const user = await createUser({ username: 'eve', password: 'Password123!' }, 'admin-1', env);

    await updateGroup(grp.id, { description: 'DevOps and SRE', members: [user.id] }, 'admin-1', env.DB);

    groups = await listGroups(env.DB);
    assert.strictEqual(groups[0].description, 'DevOps and SRE');
    assert.strictEqual(groups[0].memberCount, 1);

    await deleteGroup(grp.id, 'admin-1', env.DB);
    groups = await listGroups(env.DB);
    assert.strictEqual(groups.length, 0);
  });

  it('manages host key verification and admin reset (Sections 39, 41)', async () => {
    const asset = await createAsset(
      { name: 'db-host', hostname: '93.184.216.34', port: 22 },
      'admin-1',
      env.DB
    );

    // Simulate TOFU host key record in ssh_host_keys
    await env.DB.prepare(
      `INSERT INTO ssh_host_keys (id, asset_id, algorithm, fingerprint, public_key, status, created_at, verified_at)
       VALUES (?, ?, 'ssh-ed25519', 'SHA256:abc123456789', 'AAAAE2VjZHNh...', 'verified', ?, ?)`
    )
      .bind('hk-1', asset.id, Date.now(), Date.now())
      .run();

    const hostKey = await getHostKeyForAsset(asset.id, env.DB);
    assert.ok(hostKey);
    assert.strictEqual(hostKey.algorithm, 'ssh-ed25519');
    assert.strictEqual(hostKey.fingerprint, 'SHA256:abc123456789');

    // Admin resets host key
    await resetHostKeyForAsset(asset.id, 'admin-1', env.DB);
    const hostKeyAfter = await getHostKeyForAsset(asset.id, env.DB);
    assert.strictEqual(hostKeyAfter?.status, 'unverified');
    assert.strictEqual(hostKeyAfter?.fingerprint, hostKey.fingerprint);
  });

  it('manages system settings (Sections 45, 60)', async () => {
    const initialIdle = await getSetting('session_idle_timeout', env.DB);
    assert.strictEqual(initialIdle, '1800'); // default 30 min

    await updateSetting('session_idle_timeout', '3600', 'admin-1', env.DB);
    const updatedIdle = await getSetting('session_idle_timeout', env.DB);
    assert.strictEqual(updatedIdle, '3600');

    const all = await getAllSettings(env.DB);
    assert.strictEqual(all['session_idle_timeout'], '3600');
    assert.strictEqual(all['session_max_duration'], '28800');
  });

  it('queries session details and heuristic command audit records', async () => {
    const now = Date.now();
    await env.DB.prepare(
      `INSERT INTO ssh_sessions (
        id, user_id, username_snapshot, asset_id, asset_name_snapshot,
        account_id, account_name_snapshot, source_ip, started_at, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`
    )
      .bind('sess-detail-1', 'usr-1', 'alice', 'asset-1', 'web-01', 'acc-1', 'root', '127.0.0.1', now, now)
      .run();

    await env.DB.prepare(
      `INSERT INTO session_commands (id, session_id, timestamp, command, source, redacted, created_at)
       VALUES (?, ?, ?, ?, 'heuristic', 0, ?)`
    )
      .bind('cmd-1', 'sess-detail-1', now + 100, 'ls -la', now + 100)
      .run();

    const detail = await getSessionDetail('sess-detail-1', env.DB);
    assert.ok(detail);
    assert.strictEqual(detail.username_snapshot, 'alice');

    const cmds = await getSessionCommands('sess-detail-1', env.DB);
    assert.strictEqual(cmds.length, 1);
    assert.strictEqual(cmds[0].command, 'ls -la');
    assert.strictEqual(cmds[0].redacted, false);
  });
});
