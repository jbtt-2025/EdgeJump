import test from 'node:test';
import assert from 'node:assert/strict';
import { api, captureConsole, createContext, insertUser, issueCookie, seedDemoTopology } from '../compliance-helpers.ts';
import { checkUserAssetAccountAccess } from '../../src/authorization/authorization-service.ts';
import { createAsset } from '../../src/assets/asset-service.ts';
import { decryptCredential } from '../../src/crypto/envelope.ts';

test('demo protects shared administrator profiles and roles across visitor sessions while ordinary users remain editable', async () => {
  const ctx = await createContext({ deployType: 'demo' });
  try {
    const topo = await seedDemoTopology(ctx, 'demo-protection-test-secret');
    const secondCookie = await issueCookie(ctx.db, topo.admin.id);
    for (const target of [topo.admin, topo.assetAdmin]) {
      for (const body of [{ roles: [] }, { roles: ['User'] }, { groups: [] }, { displayName: 'changed', email: 'other@example.test' }]) {
        const result = await api(ctx, 'PATCH', `/api/admin/users/${target.id}`, { cookie: secondCookie, body });
        assert.equal(result.status, 403);
        assert.match(result.json.error, /管理员账号受保护/);
      }
    }
    const me = await api(ctx, 'GET', '/api/me', { cookie: topo.admin.cookie });
    assert.ok(me.json.permissions.includes('*'));
    const users = await api(ctx, 'GET', '/api/admin/users', { cookie: secondCookie });
    assert.equal(users.json.find((user: any) => user.id === topo.admin.id).demoProtected, true);
    assert.equal(users.json.find((user: any) => user.id === topo.bob.id).demoProtected, false);
    const roleBefore = (await api(ctx, 'GET', '/api/admin/roles', { cookie: secondCookie })).json;
    assert.equal((await api(ctx, 'PATCH', '/api/admin/roles/role_security_auditor', { cookie: secondCookie, body: { canTerminate: true } })).status, 403);
    assert.deepEqual((await api(ctx, 'GET', '/api/admin/roles', { cookie: secondCookie })).json, roleBefore);
    assert.equal((await api(ctx, 'POST', `/api/admin/users/${topo.admin.id}/enable`, { cookie: secondCookie })).status, 403);
    const groupPath = `/api/admin/groups/${topo.developers.id}`;
    assert.equal((await api(ctx, 'PATCH', groupPath, { cookie: secondCookie, body: { members: [topo.alice.id, topo.admin.id] } })).status, 403);
    await ctx.db.prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)').bind(topo.developers.id, topo.admin.id, Date.now()).run();
    assert.equal((await api(ctx, 'PATCH', groupPath, { cookie: secondCookie, body: { members: [] } })).status, 403);
    assert.equal((await api(ctx, 'DELETE', groupPath, { cookie: secondCookie })).status, 403);
    assert.equal((await api(ctx, 'PATCH', groupPath, { cookie: secondCookie, body: { members: [topo.admin.id] } })).status, 200);
    assert.equal((await api(ctx, 'PATCH', `/api/admin/users/${topo.bob.id}`, { cookie: secondCookie, body: { roles: ['Security Auditor'] } })).status, 200);
  } finally { await ctx.cleanup(); }
});

test('production administrators can still edit user roles and the auditor termination permission', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'production-role-test-secret');
    assert.equal((await api(ctx, 'PATCH', `/api/admin/users/${topo.assetAdmin.id}`, { cookie: topo.admin.cookie, body: { roles: ['User'] } })).status, 200);
    assert.equal((await api(ctx, 'PATCH', '/api/admin/roles/role_security_auditor', { cookie: topo.admin.cookie, body: { canTerminate: true } })).status, 200);
    assert.equal((await checkUserAssetAccountAccess(topo.assetAdmin.id, topo.prodDb01.id, topo.dba.id, 'connect', ctx.db)).authorized, false);
  } finally { await ctx.cleanup(); }
});

test('both built-in administrator roles see and connect to all machines without rules, with target and host-key checks intact', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'admin-default-access-secret');
    const empty = await createAsset({ name: 'no-account-yet', hostname: '9.9.9.9' }, topo.admin.id, ctx.db);
    await ctx.db.prepare('DELETE FROM authorization_rules').run();
    for (const administrator of [topo.admin, topo.assetAdmin]) {
      const visible = await api(ctx, 'GET', '/api/assets', { cookie: administrator.cookie });
      assert.deepEqual(new Set(visible.json.map((asset: any) => asset.id)), new Set([topo.prodWeb01.id, topo.prodDb01.id, empty.id]));
      assert.deepEqual(new Set(visible.json.find((asset: any) => asset.id === topo.prodWeb01.id).accounts.map((account: any) => account.username)), new Set(['deploy', 'root']));
      assert.ok(visible.json.find((asset: any) => asset.id === topo.prodWeb01.id).groups.some((group: any) => group.id === topo.web.id));
      assert.equal((await api(ctx, 'POST', '/api/sessions', { cookie: administrator.cookie, body: { assetId: topo.prodDb01.id, accountId: topo.dba.id } })).status, 201);
      assert.equal((await checkUserAssetAccountAccess(administrator.id, topo.prodWeb01.id, topo.dba.id, 'connect', ctx.db)).authorized, false);
      assert.equal((await checkUserAssetAccountAccess(administrator.id, topo.prodDb01.id, topo.dba.id, 'port_forward', ctx.db)).authorized, false);
    }
    for (const user of [topo.alice, topo.auditor]) assert.deepEqual((await api(ctx, 'GET', '/api/assets', { cookie: user.cookie })).json, []);
    await ctx.db.prepare('DELETE FROM user_roles WHERE user_id = ?').bind(topo.admin.id).run();
    assert.deepEqual((await api(ctx, 'GET', '/api/assets', { cookie: topo.admin.cookie })).json, [], 'the username admin alone grants no access');
    await ctx.db.prepare('UPDATE asset_accounts SET enabled = 0 WHERE id = ?').bind(topo.dba.id).run();
    assert.equal((await checkUserAssetAccountAccess(topo.assetAdmin.id, topo.prodDb01.id, topo.dba.id, 'connect', ctx.db)).authorized, false);
    await ctx.db.prepare('UPDATE asset_accounts SET enabled = 1 WHERE id = ?').bind(topo.dba.id).run();
    await ctx.db.prepare("UPDATE assets SET host_key_policy = 'approval_required' WHERE id = ?").bind(topo.prodDb01.id).run();
    assert.equal((await api(ctx, 'POST', '/api/sessions', { cookie: topo.assetAdmin.cookie, body: { assetId: topo.prodDb01.id, accountId: topo.dba.id } })).status, 403);
    await ctx.db.prepare('UPDATE assets SET enabled = 0 WHERE id = ?').bind(topo.prodDb01.id).run();
    assert.equal((await checkUserAssetAccountAccess(topo.assetAdmin.id, topo.prodDb01.id, topo.dba.id, 'connect', ctx.db)).authorized, false);
    await ctx.db.prepare("UPDATE users SET status = 'disabled' WHERE id = ?").bind(topo.assetAdmin.id).run();
    assert.equal((await checkUserAssetAccountAccess(topo.assetAdmin.id, topo.prodWeb01.id, topo.root.id, 'connect', ctx.db)).authorized, false);
  } finally { await ctx.cleanup(); }
});

test('machine creation can reuse an account and create encrypted credentials in the same audited transaction', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'source-credential-secret');
    const secret = 'inline-machine-credential-secret';
    const response = await api(ctx, 'POST', '/api/admin/assets', { cookie: topo.admin.cookie, body: {
      name: 'new-machine', hostname: '9.9.9.9', groupIds: [topo.web.id], accounts: [
        { sourceAccountId: topo.deploy.id }, { username: 'root', credentialId: topo.rootPassword.id },
        { username: 'ops', credential: { type: 'password', secret } },
      ],
    } });
    assert.equal(response.status, 201, response.text);
    assert.equal(response.json.accounts.length, 3);
    const [reused, , fresh] = response.json.accounts;
    assert.notEqual(reused.id, topo.deploy.id);
    assert.equal(reused.credentialId, topo.deployKey.id);
    assert.equal(reused.assetId, response.json.id);
    assert.equal((await ctx.db.prepare('SELECT asset_id FROM asset_accounts WHERE id = ?').bind(topo.deploy.id).first<any>()).asset_id, topo.prodWeb01.id);
    const stored = await ctx.db.prepare('SELECT * FROM credentials WHERE id = ?').bind(fresh.credentialId).first<any>();
    assert.equal(stored.name, 'new-machine / ops');
    assert.equal(await decryptCredential(stored, stored.id, ctx.kek), secret);
    const audits = await ctx.db.prepare('SELECT action, metadata_json FROM audit_events WHERE resource_id IN (?, ?, ?, ?, ?)')
      .bind(response.json.id, ...response.json.accounts.map((account: any) => account.id), stored.id).all<any>();
    assert.deepEqual(audits.results.map((row) => row.action).sort(), ['ACCOUNT_CREATED', 'ACCOUNT_CREATED', 'ACCOUNT_CREATED', 'ASSET_CREATED', 'CREDENTIAL_CREATED']);
    assert.ok(!response.text.includes(secret) && !response.text.includes('ciphertext'));
    assert.ok(!JSON.stringify(audits.results).includes(secret));
    assert.equal((await checkUserAssetAccountAccess(topo.alice.id, response.json.id, reused.id, 'connect', ctx.db)).authorized, false, 'copying an account does not copy its authorization');
    assert.equal((await api(ctx, 'GET', '/api/admin/accounts', { cookie: topo.admin.cookie })).json.length, 6);
    assert.equal((await api(ctx, 'GET', '/api/admin/accounts', { cookie: topo.alice.cookie })).status, 403);
  } finally { await ctx.cleanup(); }
});

test('linked creation validates permissions and rolls back all data and audits on a database failure', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'rollback-source-secret');
    const counts = async () => Promise.all(['assets', 'asset_accounts', 'credentials', 'audit_events'].map(async (table) =>
      (await ctx.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<any>()).count));
    const before = await counts();
    const accounts = [{ username: 'ops', credential: { type: 'password', secret: 'rollback-only-secret' } }];
    const logs = captureConsole();
    const duplicates = await api(ctx, 'POST', '/api/admin/assets', { cookie: topo.admin.cookie, body: { name: 'invalid', hostname: '9.9.9.9', accounts: [...accounts, ...accounts] } });
    assert.equal(duplicates.status, 400);
    assert.deepEqual(await counts(), before);
    await ctx.db.exec("CREATE TRIGGER fail_account BEFORE INSERT ON asset_accounts WHEN NEW.username = 'ops' BEGIN SELECT RAISE(ABORT, 'forced account write failure'); END");
    const failed = await api(ctx, 'POST', '/api/admin/assets', { cookie: topo.admin.cookie, body: { name: 'rolled-back', hostname: '9.9.9.9', accounts } });
    assert.ok(failed.status >= 400);
    assert.deepEqual(await counts(), before);
    const failedAccount = await api(ctx, 'POST', `/api/admin/assets/${topo.prodWeb01.id}/accounts`, { cookie: topo.admin.cookie, body: accounts[0] });
    assert.ok(failedAccount.status >= 400);
    assert.deepEqual(await counts(), before);
    assert.ok(!logs.lines.join('\n').includes('rollback-only-secret'));
    const limited = await insertUser(ctx.db, { username: 'machine-only', roles: [] });
    await ctx.db.prepare("INSERT INTO roles (id, name, created_at) VALUES ('role_machine_only', 'Machine Only', ?)").bind(Date.now()).run();
    await ctx.db.prepare("INSERT INTO role_permissions (role_id, permission_id) SELECT 'role_machine_only', id FROM permissions WHERE code = 'asset.create'").run();
    await ctx.db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, 'role_machine_only')").bind(limited.id).run();
    const cookie = await issueCookie(ctx.db, limited.id);
    assert.equal((await api(ctx, 'POST', '/api/admin/assets', { cookie, body: { name: 'forbidden', hostname: '9.9.9.9', accounts: [{ sourceAccountId: topo.root.id }] } })).status, 403);
    assert.equal((await api(ctx, 'POST', '/api/admin/assets', { cookie, body: { name: 'asset-only', hostname: '9.9.9.9' } })).status, 201);
  } finally { await ctx.cleanup(); }
});

test('an account can create a private-key credential inline and a duplicate creates no orphan credential', async () => {
  const ctx = await createContext();
  try {
    const topo = await seedDemoTopology(ctx, 'inline-account-source-secret');
    const body = { username: 'service', credential: { name: 'service-key', type: 'private_key', secret: 'test-private-key-write-only' } };
    const created = await api(ctx, 'POST', `/api/admin/assets/${topo.prodDb01.id}/accounts`, { cookie: topo.assetAdmin.cookie, body });
    assert.equal(created.status, 201, created.text);
    assert.equal(created.json.credentialType, 'private_key');
    assert.ok(!created.text.includes(body.credential.secret));
    const count = (await ctx.db.prepare('SELECT COUNT(*) AS count FROM credentials').first<any>()).count;
    const duplicate = await api(ctx, 'POST', `/api/admin/assets/${topo.prodDb01.id}/accounts`, { cookie: topo.assetAdmin.cookie, body });
    assert.equal(duplicate.status, 400);
    assert.match(duplicate.json.error, /同名/);
    assert.equal((await ctx.db.prepare('SELECT COUNT(*) AS count FROM credentials').first<any>()).count, count);
  } finally { await ctx.cleanup(); }
});
