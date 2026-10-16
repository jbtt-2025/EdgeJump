import test from 'node:test';
import assert from 'node:assert/strict';
import { api, createContext, insertUser, issueCookie } from '../compliance-helpers.ts';
import { login, setupMfa, confirmMfa, validateSession } from '../../src/auth/auth-service.ts';
import { resetUserPassword } from '../../src/users/user-service.ts';
import { generateTotpCode } from '../../src/crypto/totp.ts';

const password = 'Demo-auth-test-password-42!';

test('demo administrators bypass enrollment and the global MFA policy while retaining management permissions', async () => {
  const ctx = await createContext({ deployType: 'demo' });
  try {
    const administrator = await insertUser(ctx.db, { username: 'demo-admin', roles: ['Super Admin'] });
    await ctx.db.prepare('UPDATE users SET mfa_enabled = 0 WHERE id = ?').bind(administrator.id).run();
    await ctx.db.prepare("UPDATE system_settings SET value = 'true' WHERE key = 'require_mfa_for_all'").run();
    await resetUserPassword(administrator.id, '1', administrator.id, ctx.env);
    const response = await api(ctx, 'POST', '/api/auth/login', { body: { username: administrator.username, password: '1' } });
    assert.equal(response.status, 200);
    assert.equal(response.json.mfaRequired, false);
    assert.equal(response.json.mfaSetupRequired, false);
    assert.ok(response.json.permissions.includes('*'));
    const cookie = response.headers.get('Set-Cookie')!.split(';')[0];
    const me = await api(ctx, 'GET', '/api/me', { cookie });
    assert.equal(me.json.user.mfaEnabled, false);
    assert.equal(me.json.user.mfaPending, false);
    assert.equal(me.json.user.mfaRequired, false);
    assert.ok(me.json.permissions.includes('*'));
    assert.equal((await api(ctx, 'GET', '/api/admin/users', { cookie })).status, 200);
    for (const path of ['/api/auth/mfa/setup', '/api/auth/mfa/confirm', '/api/auth/mfa/disable']) {
      const denied = await api(ctx, 'POST', path, { cookie, body: { code: '000000' } });
      assert.equal(denied.status, 403);
      assert.match(denied.json.error, /演示模式.*不开放 MFA/);
    }
    assert.equal((await ctx.db.prepare('SELECT COUNT(*) AS count FROM mfa_recovery_codes').first<any>()).count, 0);
    await assert.rejects(setupMfa(administrator.id, ctx.env), /disabled in demo mode/);
    await assert.rejects(confirmMfa(administrator.id, '000000', ctx.env), /disabled in demo mode/);

    ctx.env.DEPLOY_TYPE = 'production';
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie })).status, 401);
    const production = await api(ctx, 'POST', '/api/auth/login', { body: { username: administrator.username, password: '1' } });
    assert.equal(production.json.mfaSetupRequired, true);
    assert.deepEqual(production.json.permissions, []);
  } finally { await ctx.cleanup(); }
});

test('demo password login bypasses existing TOTP without changing its secret or treating it as MFA verification', async () => {
  const ctx = await createContext();
  try {
    const administrator = await insertUser(ctx.db, { username: 'existing-mfa-admin', roles: ['Super Admin'] });
    await ctx.db.prepare('UPDATE users SET mfa_enabled = 0 WHERE id = ?').bind(administrator.id).run();
    await resetUserPassword(administrator.id, password, administrator.id, ctx.env);
    const setup = await setupMfa(administrator.id, ctx.env);
    assert.equal(await confirmMfa(administrator.id, await generateTotpCode(setup.secret), ctx.env), true);
    const before = await ctx.db.prepare('SELECT mfa_enabled, totp_secret_ciphertext, totp_secret_nonce FROM users WHERE id = ?').bind(administrator.id).first<any>();
    const production = await login({ username: administrator.username, password, clientIp: '127.0.0.1' }, ctx.env);
    assert.equal(production.mfaRequired, true);
    if (!production.mfaRequired) throw new Error('Expected a production MFA challenge');

    ctx.env.DEPLOY_TYPE = 'demo';
    const demo = await login({ username: administrator.username, password, clientIp: '127.0.0.1' }, ctx.env);
    assert.equal(demo.mfaRequired, false);
    if (demo.mfaRequired) throw new Error('Demo must permit password-only login');
    assert.equal(demo.mfaSetupRequired, false);
    assert.ok(demo.permissions.includes('*'));
    await assert.rejects(login({ username: administrator.username, password: 'wrong', mfaChallenge: production.challengeToken, clientIp: '127.0.0.1' }, ctx.env), /Invalid username or password/);
    assert.equal((await api(ctx, 'POST', '/api/auth/mfa', { body: { challengeToken: production.challengeToken, totpCode: await generateTotpCode(setup.secret) } })).status, 403);
    const after = await ctx.db.prepare('SELECT mfa_enabled, totp_secret_ciphertext, totp_secret_nonce FROM users WHERE id = ?').bind(administrator.id).first<any>();
    assert.deepEqual(after, before);
    const audit = await ctx.db.prepare("SELECT metadata_json FROM audit_events WHERE action = 'LOGIN_SUCCESS' ORDER BY timestamp DESC LIMIT 1").first<any>();
    assert.equal(JSON.parse(audit.metadata_json).mfaUsed, false);
    assert.equal(JSON.parse(audit.metadata_json).deployType, 'demo');

    ctx.env.DEPLOY_TYPE = 'production';
    assert.equal(await validateSession(demo.sessionToken, ctx.db), null);
    assert.equal((await login({ username: administrator.username, password, clientIp: '127.0.0.1' }, ctx.env)).mfaRequired, true);
  } finally { await ctx.cleanup(); }
});

test('existing enrollment-pending sessions work in demo and retain the original restriction in production', async () => {
  const ctx = await createContext();
  try {
    const administrator = await insertUser(ctx.db, { username: 'pending-admin', roles: ['Super Admin'] });
    await ctx.db.prepare('UPDATE users SET mfa_enabled = 0 WHERE id = ?').bind(administrator.id).run();
    const cookie = await issueCookie(ctx.db, administrator.id);
    await ctx.db.prepare('UPDATE auth_sessions SET mfa_pending = 1 WHERE user_id = ?').bind(administrator.id).run();
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie })).json.user.mfaPending, true);
    ctx.env.DEPLOY_TYPE = 'demo';
    const demo = await api(ctx, 'GET', '/api/me', { cookie });
    assert.equal(demo.json.user.mfaPending, false);
    assert.ok(demo.json.permissions.includes('*'));
    assert.equal((await api(ctx, 'GET', '/api/admin/users', { cookie })).status, 200);
    ctx.env.DEPLOY_TYPE = 'production';
    assert.equal((await api(ctx, 'GET', '/api/me', { cookie })).json.user.mfaPending, true);
    assert.equal((await api(ctx, 'GET', '/api/admin/users', { cookie })).status, 403);
  } finally { await ctx.cleanup(); }
});
