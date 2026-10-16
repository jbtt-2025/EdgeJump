import test from 'node:test';
import assert from 'node:assert/strict';
import { api, captureConsole, createContext, insertUser, TEST_BOOTSTRAP_TOKEN } from '../compliance-helpers.ts';
import { createUser, resetUserPassword } from '../../src/users/user-service.ts';

const validInput = { bootstrapToken: TEST_BOOTSTRAP_TOKEN, username: 'admin', password: 'Bootstrap-password-42!' };

test('bootstrap returns specific validation errors and creates no user for rejected input', async () => {
  const ctx = await createContext();
  try {
    for (const [body, code, status, message] of [
      [{ ...validInput, bootstrapToken: 'wrong-token' }, 'BOOTSTRAP_TOKEN_INVALID', 403, /初始化令牌/],
      [{ ...validInput, username: ' ' }, 'BOOTSTRAP_USERNAME_REQUIRED', 400, /用户名/],
      [{ ...validInput, username: 123 }, 'BOOTSTRAP_USERNAME_REQUIRED', 400, /用户名/],
      [{ ...validInput, username: 'ab', deployType: 'demo' }, 'BOOTSTRAP_USERNAME_TOO_SHORT', 400, /3 个字符/],
      [{ ...validInput, password: '' }, 'BOOTSTRAP_PASSWORD_REQUIRED', 400, /密码/],
      [{ ...validInput, password: 123 }, 'BOOTSTRAP_PASSWORD_REQUIRED', 400, /密码/],
      [{ ...validInput, password: '1234567' }, 'BOOTSTRAP_PASSWORD_TOO_SHORT', 400, /8 个字符/],
      [{ ...validInput, displayName: {} }, 'BOOTSTRAP_INVALID_REQUEST', 400, /格式/],
      [null, 'BOOTSTRAP_INVALID_REQUEST', 400, /格式/],
      [[], 'BOOTSTRAP_INVALID_REQUEST', 400, /格式/],
      ['{invalid-json', 'BOOTSTRAP_INVALID_REQUEST', 400, /格式/],
    ] as const) {
      const response = await api(ctx, 'POST', '/api/auth/bootstrap', { body });
      assert.equal(response.status, status);
      assert.equal(response.json.code, code);
      assert.match(response.json.error, message);
      assert.equal(response.headers.get('X-Request-ID'), response.json.requestId);
      assert.ok(response.headers.get('Cache-Control')?.includes('no-store'));
    }
    assert.equal((await ctx.db.prepare('SELECT COUNT(*) AS count FROM users').first<any>()).count, 0);
    const audits = await ctx.db.prepare("SELECT metadata_json FROM audit_events WHERE action = 'BOOTSTRAP_FAILED'").all<any>();
    assert.equal(audits.results.length, 1);
    assert.ok(!JSON.stringify(audits.results).includes('wrong-token'));
  } finally { await ctx.cleanup(); }
});

test('an unconfigured bootstrap token reports a deployment configuration error', async () => {
  const ctx = await createContext({ bootstrapToken: null });
  try {
    const logs = captureConsole();
    const response = await api(ctx, 'POST', '/api/auth/bootstrap', { body: validInput });
    assert.equal(response.status, 503);
    assert.equal(response.json.code, 'BOOTSTRAP_TOKEN_NOT_CONFIGURED');
    assert.match(response.json.error, /Worker Secrets/);
    assert.ok(logs.lines.some((line) => line.includes(response.json.requestId) && line.includes(response.json.code)));
    assert.ok(!logs.lines.join('\n').includes(TEST_BOOTSTRAP_TOKEN));
  } finally { await ctx.cleanup(); }
});

test('a missing D1 migration has an actionable message and matching sanitized log entry', async () => {
  const ctx = await createContext();
  try {
    await ctx.db.exec('DROP TABLE system_settings');
    const logs = captureConsole();
    for (const [method, path] of [['GET', '/api/auth/bootstrap/status'], ['POST', '/api/auth/bootstrap']] as const) {
      const response = await api(ctx, method, path, method === 'POST' ? { body: validInput } : {});
      assert.equal(response.status, 503);
      assert.equal(response.json.code, 'BOOTSTRAP_SCHEMA_MISSING');
      assert.match(response.json.error, /D1 数据库迁移/);
      assert.ok(logs.lines.some((line) => line.includes(response.json.requestId) && line.includes(response.json.code)));
      assert.ok(!response.text.includes('no such table'));
    }
    assert.ok(!logs.lines.join('\n').includes(validInput.password));
  } finally { await ctx.cleanup(); }
});

test('bootstrap status failures expose the operation without reflecting exception text', async (t) => {
  const ctx = await createContext();
  try {
    const sentinel = 'private-database-exception-with-secret';
    const logs = captureConsole();
    t.mock.method(ctx.db, 'prepare', () => { throw new Error(sentinel); });
    const response = await api(ctx, 'GET', '/api/auth/bootstrap/status');
    assert.equal(response.status, 503);
    assert.equal(response.json.code, 'BOOTSTRAP_STATUS_UNAVAILABLE');
    assert.match(response.json.error, /D1 数据库绑定/);
    assert.ok(!response.text.includes(sentinel));
    assert.ok(!logs.lines.join('\n').includes(sentinel));
  } finally { await ctx.cleanup(); }
});

test('bootstrap password service failure returns 503 without creating an administrator', async () => {
  const ctx = await createContext();
  try {
    const logs = captureConsole();
    ctx.env.PASSWORD_KDF = {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async () => Response.json({ error: 'private-kdf-exception' }, { status: 503 }) }),
    } as unknown as DurableObjectNamespace;
    const response = await api(ctx, 'POST', '/api/auth/bootstrap', { body: validInput });
    assert.equal(response.status, 503);
    assert.equal(response.json.code, 'BOOTSTRAP_PASSWORD_SERVICE_UNAVAILABLE');
    assert.match(response.json.error, /PASSWORD_KDF/);
    assert.ok(!response.text.includes('private-kdf-exception'));
    assert.ok(!logs.lines.join('\n').includes(validInput.password));
    assert.equal((await ctx.db.prepare('SELECT COUNT(*) AS count FROM users').first<any>()).count, 0);
  } finally { await ctx.cleanup(); }
});

test('bootstrap write errors are server failures and keep bound values out of the response and logs', async (t) => {
  const ctx = await createContext();
  try {
    const logs = captureConsole();
    const sentinel = `D1 write failed with ${validInput.password} and ${TEST_BOOTSTRAP_TOKEN}`;
    const prepare = ctx.db.prepare.bind(ctx.db);
    const mock = t.mock.method(ctx.db, 'prepare', (sql: string) => {
      if (sql.includes('INSERT INTO users')) throw new Error(sentinel);
      return prepare(sql);
    });
    const response = await api(ctx, 'POST', '/api/auth/bootstrap', { body: validInput });
    mock.mock.restore();
    assert.equal(response.status, 500);
    assert.equal(response.json.code, 'BOOTSTRAP_SAVE_FAILED');
    assert.match(response.json.error, /管理员配置保存失败/);
    assert.ok(!response.text.includes(validInput.password));
    assert.ok(!logs.lines.join('\n').includes(validInput.password));
    assert.ok(!logs.lines.join('\n').includes(TEST_BOOTSTRAP_TOKEN));
    assert.equal((await ctx.db.prepare('SELECT COUNT(*) AS count FROM users').first<any>()).count, 0);
  } finally { await ctx.cleanup(); }
});

test('an audit failure after administrator creation directs the user to login and keeps bootstrap closed', async (t) => {
  const ctx = await createContext();
  try {
    captureConsole();
    const prepare = ctx.db.prepare.bind(ctx.db);
    const mock = t.mock.method(ctx.db, 'prepare', (sql: string) => {
      if (sql.includes('INSERT INTO audit_events')) throw new Error('D1_ERROR: no such table: audit_events');
      return prepare(sql);
    });
    const response = await api(ctx, 'POST', '/api/auth/bootstrap', { body: validInput });
    mock.mock.restore();
    assert.equal(response.status, 500);
    assert.equal(response.json.code, 'BOOTSTRAP_AUDIT_FAILED');
    assert.match(response.json.error, /管理员已创建/);
    assert.equal((await api(ctx, 'GET', '/api/auth/bootstrap/status')).json.bootstrapNeeded, false);
    const again = await api(ctx, 'POST', '/api/auth/bootstrap', { body: validInput });
    assert.equal(again.status, 403);
    assert.equal(again.json.code, 'BOOTSTRAP_COMPLETED');
    assert.equal((await api(ctx, 'POST', '/api/auth/login', { body: validInput })).status, 200);
  } finally { await ctx.cleanup(); }
});

test('demo accepts short bootstrap and user credentials, hashes passwords and preserves one-time setup', async () => {
  const ctx = await createContext({ deployType: 'demo' });
  try {
    for (const body of [{ ...validInput, username: ' ' }, { ...validInput, password: '' }]) {
      assert.equal((await api(ctx, 'POST', '/api/auth/bootstrap', { body })).status, 400);
    }
    const response = await api(ctx, 'POST', '/api/auth/bootstrap', { body: { ...validInput, username: 'a', password: '1' } });
    assert.equal(response.status, 201);
    assert.equal(response.json.user.username, 'a');
    const administratorId = response.json.user.id;
    const row = await ctx.db.prepare('SELECT password_hash, password_params FROM users WHERE id = ?').bind(administratorId).first<any>();
    assert.match(row.password_hash, /^[a-f0-9]{64}$/);
    assert.equal(JSON.parse(row.password_params).iterations, 600_000);
    assert.equal((await api(ctx, 'POST', '/api/auth/login', { body: { username: 'a', password: '1' } })).status, 200);
    assert.equal((await api(ctx, 'POST', '/api/auth/bootstrap', { body: validInput })).json.code, 'BOOTSTRAP_COMPLETED');

    const user = await createUser({ username: 'b', password: '2' }, administratorId, ctx.env);
    assert.equal((await api(ctx, 'POST', '/api/auth/login', { body: { username: 'b', password: '2' } })).status, 200);
    await resetUserPassword(user.id, '3', administratorId, ctx.env);
    assert.equal((await api(ctx, 'POST', '/api/auth/login', { body: { username: 'b', password: '3' } })).status, 200);
    await assert.rejects(createUser({ username: '', password: '2' }, administratorId, ctx.env), /Username is required/);
    await assert.rejects(createUser({ username: 'c', password: '' }, administratorId, ctx.env), /Password is required/);
    await assert.rejects(resetUserPassword(user.id, '', administratorId, ctx.env), /Password is required/);
  } finally { await ctx.cleanup(); }
});

test('production user creation and reset preserve the password policy and existing short usernames', async () => {
  const ctx = await createContext();
  try {
    const administrator = await insertUser(ctx.db, { username: 'admin', roles: ['Super Admin'] });
    await assert.rejects(createUser({ username: 'u', password: '1' }, administrator.id, ctx.env), /at least 8/);
    const user = await createUser({ username: 'u', password: validInput.password }, administrator.id, ctx.env);
    await assert.rejects(resetUserPassword(user.id, '1', administrator.id, ctx.env), /at least 8/);
    assert.equal((await api(ctx, 'POST', '/api/auth/login', { body: { username: 'u', password: validInput.password } })).status, 200);
  } finally { await ctx.cleanup(); }
});
