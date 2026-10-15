import { startSshServer, CLIENT_PRIVATE_KEY, eventually } from './ssh-fixture.ts';
import { seedSessionMetadata } from './compliance-helpers.ts';
// Regression flow for the V1 review: real Worker APIs, MFA, encrypted SSH,
// read-only monitoring, termination, replay, and the complete management audit chain.
// Tests run sequentially and keep the original finding IDs for traceability.

import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import type { SSHSessionInitConfig } from '../src/durable/SSHSessionDO.ts';
import type { ApiOptions, ApiResult, ComplianceContext } from './compliance-helpers.ts';
import { SSHSessionDO } from '../src/durable/SSHSessionDO.ts';
import { generateTotpCode } from '../src/crypto/totp.ts';
import { COOKIE_NAME } from '../src/auth/auth-service.ts';
import { deleteAssetAccount, updateAssetAccount } from '../src/assets/asset-service.ts';
import { computeHostKeyFingerprint, getHostKeyAlgorithm } from '../src/ssh/host-key.ts';
import { concat, encodeString } from '../src/ssh/utils.ts';
import { bytesToHex, hexToBytes } from '../src/crypto/utils.ts';
import {
  TEST_BOOTSTRAP_TOKEN,
  api,
  captureConsole,
  createContext,
  decodeTicket,
  flushAsync,
  grantPermission,
} from './compliance-helpers.ts';

// -------------------------------------------------------------
// Constants
// -------------------------------------------------------------

const STEP_TIMEOUT_MS = 60_000;
const DO_BASE_URL = 'https://ssh-session.do.internal';

/** AGENTS.md §57, in document order. */
const SECTION_57_EVENTS = [
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGOUT',
  'USER_CREATED',
  'USER_UPDATED',
  'USER_DISABLED',
  'USER_ENABLED',
  'GROUP_CREATED',
  'GROUP_UPDATED',
  'GROUP_DELETED',
  'ASSET_CREATED',
  'ASSET_UPDATED',
  'ASSET_DELETED',
  'ACCOUNT_CREATED',
  'ACCOUNT_UPDATED',
  'ACCOUNT_DELETED',
  'CREDENTIAL_CREATED',
  'CREDENTIAL_REPLACED',
  'CREDENTIAL_DELETED',
  'AUTHORIZATION_CREATED',
  'AUTHORIZATION_UPDATED',
  'AUTHORIZATION_DELETED',
  'HOST_KEY_TRUSTED',
  'HOST_KEY_CHANGED',
  'SESSION_CREATED',
  'SESSION_CONNECTED',
  'SESSION_FAILED',
  'SESSION_CLOSED',
  'SESSION_TERMINATED',
  'SETTING_CHANGED',
] as const;

type Section57Event = (typeof SECTION_57_EVENTS)[number];

/** Fields the DO reads from its /init body to connect and authenticate (src/durable/SSHSessionDO.ts SSHSessionInitConfig). */
const INIT_REQUIRED_FIELDS = ['sessionId', 'userId', 'assetId', 'accountId', 'host', 'port', 'username'] as const;

/** Field set a credential API response may contain (§18, §71). */
const CREDENTIAL_SAFE_FIELDS = new Set(['id', 'name', 'type', 'keyVersion', 'createdAt', 'updatedAt']);

function stepOptions(_finding?: string): { timeout: number } {
  return { timeout: STEP_TIMEOUT_MS };
}

function randomHex(bytes: number): string {
  return bytesToHex(new Uint8Array(randomBytes(bytes)));
}

function randomSecret(label: string): string {
  return `EJ-SECRET-${label}-${randomHex(24)}`;
}

function randomPassword(label: string): string {
  return `EJ-PW-${label}-${randomHex(12)}`;
}

// -------------------------------------------------------------
// Shared flow state
// -------------------------------------------------------------

interface RouteUser {
  id: string;
  username: string;
  password: string;
  cookie: string | null;
}

interface Named {
  id: string;
  name: string;
}

interface FlowAsset extends Named {
  hostname: string;
  port: number;
}

interface FlowAccount {
  id: string;
  assetId: string;
  username: string;
  credentialId: string;
}

interface FlowSession {
  sessionId: string;
  ticket: string;
  wsUrl: string;
  expiresAt: number;
}

interface FlowState {
  admin?: RouteUser;
  alice?: RouteUser;
  bob?: RouteUser;
  auditor?: RouteUser;
  developers?: Named;
  production?: Named;
  web?: Named & { parentId: string | null };
  prodWeb01?: FlowAsset;
  prodDb01?: FlowAsset;
  deployKey?: Named;
  rootPassword?: Named;
  deploy?: FlowAccount;
  root?: FlowAccount;
  dba?: FlowAccount;
  rule?: Named;
  session?: FlowSession;
  auditActions?: string[];
  /** Every response body delivered to a browser during the flow (FUN-15 leak scan). */
  browserTexts: string[];
  secrets: { deployKey: string; rootPassword: string; tempCredential: string; tempCredentialReplaced: string };
}

const state: FlowState = {
  browserTexts: [],
  secrets: {
    deployKey: CLIENT_PRIVATE_KEY,
    rootPassword: randomSecret('root-password'),
    tempCredential: randomSecret('temp-credential'),
    tempCredentialReplaced: randomSecret('temp-credential-replaced'),
  },
};

let context: ComplianceContext | null = null;
let sshServer: Awaited<ReturnType<typeof startSshServer>> | null = null;

function ctx(): ComplianceContext {
  assert.ok(context, 'fixture: compliance context must be created in before()');
  return context;
}

function need<T>(value: T | null | undefined, what: string): T {
  assert.ok(value !== undefined && value !== null, `fixture: 前置步骤未完成：${what}`);
  return value as T;
}

/** Route call through src/worker.ts; the response body is recorded as browser-visible text. */
async function call(method: string, path: string, opts: ApiOptions = {}): Promise<ApiResult> {
  const res = await api(ctx(), method, path, opts);
  if (res.status === 101 && path.includes('/ws')) await eventually(async () => (await sessionRow(state.session!.sessionId))?.status === 'active', 'demo SSH active');
  state.browserTexts.push(res.text);
  return res;
}

function sessionCookieFrom(res: ApiResult): string | null {
  const raw = res.headers.get('set-cookie');
  if (!raw) return null;
  const first = raw.split(';')[0].trim();
  return first.startsWith(`${COOKIE_NAME}=`) && first.length > COOKIE_NAME.length + 1 ? first : null;
}

async function loginViaRoute(user: RouteUser): Promise<ApiResult> {
  const res = await call('POST', '/api/auth/login', { body: { username: user.username, password: user.password } });
  user.cookie = res.status === 200 ? sessionCookieFrom(res) : null;
  if (res.json?.mfaSetupRequired && user.cookie) {
    const setup = await call('POST', '/api/auth/mfa/setup', { cookie: user.cookie });
    assert.equal(setup.status, 200);
    const confirm = await call('POST', '/api/auth/mfa/confirm', { cookie: user.cookie, body: { code: await generateTotpCode(setup.json.secret) } });
    assert.equal(confirm.status, 200);
  }
  return res;
}

async function createUserViaRoute(username: string, displayName: string, role: string): Promise<RouteUser> {
  const admin = need(state.admin?.cookie, 'Super Admin 登录');
  const password = randomPassword(username);
  const res = await call('POST', '/api/admin/users', {
    cookie: admin,
    body: { username, password, displayName, roles: [role] },
  });
  assert.equal(res.status, 201, `fixture: POST /api/admin/users (${username}) 应返回 201`);
  return { id: String(res.json?.id), username, password, cookie: null };
}

function doIdOf(sessionId: string): string {
  return ctx().sessions.idFromName(sessionId).toString();
}

async function sessionRow(sessionId: string): Promise<Record<string, unknown> | null> {
  return ctx()
    .db.prepare('SELECT * FROM ssh_sessions WHERE id = ?')
    .bind(sessionId)
    .first<Record<string, unknown>>();
}

async function auditRows(filter: { action?: string; resourceId?: string } = {}): Promise<
  Array<{ action: string; actor_user_id: string | null; resource_id: string | null; metadata_json: string | null }>
> {
  const { results } = await ctx()
    .db.prepare('SELECT action, actor_user_id, resource_id, metadata_json FROM audit_events ORDER BY timestamp, rowid')
    .all<{ action: string; actor_user_id: string | null; resource_id: string | null; metadata_json: string | null }>();
  return (results ?? []).filter(
    (row) =>
      (filter.action === undefined || row.action === filter.action) &&
      (filter.resourceId === undefined || row.resource_id === filter.resourceId),
  );
}

async function waitFor(predicate: () => Promise<boolean>, what: string, rounds: number = 200): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    if (await predicate()) return;
    await flushAsync(1);
  }
  assert.fail(`fixture: 等待超时：${what}`);
}

async function doFetch(
  instance: SSHSessionDO,
  method: string,
  path: string,
  init: { body?: unknown; headers?: Record<string, string> } = {},
): Promise<Response> {
  const headers = new Headers(init.headers ?? {});
  let body: string | undefined;
  if (init.body !== undefined) {
    body = JSON.stringify(init.body);
    headers.set('Content-Type', 'application/json');
  }
  headers.set('x-user-id', String((instance as any).config?.userId ?? ''));
  return instance.fetch(new Request(`${DO_BASE_URL}${path}`, { method, headers, body }));
}

/** Native SSHSessionInitConfig (no credential material) for DO-level probes. */
function nativeInitConfig(sessionId: string, user: RouteUser, asset: FlowAsset, account: FlowAccount): SSHSessionInitConfig {
  return {
    sessionId,
    userId: user.id,
    usernameSnapshot: user.username,
    assetId: asset.id,
    assetNameSnapshot: asset.name,
    accountId: account.id,
    accountNameSnapshot: account.username,
    host: asset.hostname,
    port: asset.port,
    username: account.username,
    authMethod: 'publickey',
    sourceIp: '127.0.0.1',
    userAgent: 'compliance-test',
  };
}

async function newProbeDo(config: SSHSessionInitConfig): Promise<{ instance: SSHSessionDO; init: Response }> {
  const instance = ctx().track(new SSHSessionDO(undefined, ctx().env));
  await seedSessionMetadata(ctx().db, config);
  const init = await doFetch(instance, 'POST', '/init', { body: config });
  return { instance, init };
}

interface TofuProbe {
  processHostKeyTOFU(algorithm: string, fingerprint: string, hostKeyBlob: Uint8Array): Promise<void>;
}

/** Synthetic host key blob `string(algorithm) || string(key bytes)` with the implementation's own fingerprinting. */
async function syntheticHostKey(keyHex: string): Promise<{ algorithm: string; fingerprint: string; blob: Uint8Array }> {
  const blob = concat(encodeString('ssh-ed25519'), encodeString(hexToBytes(keyHex)));
  return { algorithm: getHostKeyAlgorithm(blob), fingerprint: await computeHostKeyFingerprint(blob), blob };
}

async function auditActionsViaRoute(): Promise<string[]> {
  if (state.auditActions) return state.auditActions;
  const auditor = need(state.auditor?.cookie, 'auditor 登录');
  const res = await call('GET', '/api/admin/audit?limit=200', { cookie: auditor });
  assert.equal(res.status, 200, 'fixture: GET /api/admin/audit 应返回 200');
  assert.ok(Array.isArray(res.json), 'fixture: 审计日志接口应返回数组');
  state.auditActions = (res.json as Array<{ action: string }>).map((event) => event.action);
  return state.auditActions;
}

after(async () => {
  if (sshServer) await sshServer.close();
  else if (context) await context.cleanup();
  context = null;
});

// -------------------------------------------------------------
// §93 demo flow
// -------------------------------------------------------------

describe('compliance-demo-flow: §93 功能验收演示链路', () => {
  before(async () => {
    context = await createContext();
    sshServer = await startSshServer(context, { storage: false });
  });

  // ---- FUN-01 Super Admin 登录 ----

  it('[FUN-01] 前置：经 BOOTSTRAP_TOKEN 初始化 Super Admin，初始化入口随即永久失效', stepOptions(), async () => {
    const statusBefore = await call('GET', '/api/auth/bootstrap/status');
    assert.equal(statusBefore.status, 200, 'fixture: bootstrap status 应可读');
    assert.equal(statusBefore.json?.bootstrapNeeded, true, 'fixture: 空库应需要初始化');

    const admin: RouteUser = { id: '', username: 'admin', password: randomPassword('admin'), cookie: null };
    const res = await call('POST', '/api/auth/bootstrap', {
      headers: { 'x-bootstrap-token': TEST_BOOTSTRAP_TOKEN },
      body: { username: admin.username, password: admin.password, displayName: 'Super Admin' },
    });
    assert.equal(res.threw, false, '[判定] Bootstrap 处理不应抛出异常');
    assert.equal(res.status, 201, '[判定] 持有 BOOTSTRAP_TOKEN 时应创建 Super Admin（§9）');
    admin.id = String(res.json?.user?.id);
    state.admin = admin;

    const statusAfter = await call('GET', '/api/auth/bootstrap/status');
    assert.equal(statusAfter.json?.bootstrapNeeded, false, '[判定] 初始化完成后不再需要初始化（§9）');

    const again = await call('POST', '/api/auth/bootstrap', {
      headers: { 'x-bootstrap-token': TEST_BOOTSTRAP_TOKEN },
      body: { username: 'admin2', password: randomPassword('admin2'), displayName: 'Second Admin' },
    });
    assert.equal(again.status, 403, '[判定] 初始化完成后再次初始化应被拒绝（§9 BOOTSTRAP_TOKEN 永久失效）');
    const admins = await ctx()
      .db.prepare("SELECT COUNT(*) AS count FROM user_roles WHERE role_id = 'role_super_admin'")
      .first<{ count: number }>();
    assert.equal(admins?.count, 1, '[判定] 系统中只应存在一个经 Bootstrap 创建的 Super Admin');
  });

  it('[FUN-01] Super Admin 登录并获得全部管理权限', stepOptions(), async () => {
    const admin = need(state.admin, 'Bootstrap');
    const res = await loginViaRoute(admin);
    assert.equal(res.status, 200, '[判定] Super Admin 应能以用户名与密码登录（§93-1）');
    assert.ok(admin.cookie, '[判定] 登录成功应通过 Set-Cookie 下发会话 Cookie（§7）');

    const me = await call('GET', '/api/me', { cookie: admin.cookie });
    assert.equal(me.status, 200, '[判定] 登录 Cookie 应能访问 /api/me');
    assert.equal(me.json?.user?.username, 'admin', '[判定] /api/me 应返回 Super Admin 本人');
    assert.ok(Array.isArray(me.json?.permissions) && me.json.permissions.includes('*'), '[判定] Super Admin 应拥有 * 权限（§12）');
  });

  // ---- FUN-02 .. FUN-10 管理员布置 ----

  it('[FUN-02] 创建 Developers 用户组', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const res = await call('POST', '/api/admin/groups', {
      cookie: admin,
      body: { name: 'Developers', description: '§93 demo group' },
    });
    assert.equal(res.status, 201, '[判定] POST /api/admin/groups 应创建用户组（§13）');
    state.developers = { id: String(res.json?.id), name: 'Developers' };

    const list = await call('GET', '/api/admin/groups', { cookie: admin });
    assert.equal(list.status, 200, '[判定] 用户组列表应可读');
    assert.ok(
      (list.json as Array<{ id: string; name: string }>).some((g) => g.id === state.developers?.id && g.name === 'Developers'),
      '[判定] 用户组列表应包含 Developers',
    );
  });

  it('[FUN-03] 创建 Alice 与 Bob', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const alice = await createUserViaRoute('alice', 'Alice', 'User');
    const bob = await createUserViaRoute('bob', 'Bob', 'User');
    state.alice = alice;
    state.bob = bob;

    const list = await call('GET', '/api/admin/users', { cookie: admin });
    assert.equal(list.status, 200, '[判定] 用户列表应可读');
    const users = list.json as Array<{ id: string; username: string; status: string; roles: string[] }>;
    for (const created of [alice, bob]) {
      const row = users.find((u) => u.id === created.id);
      assert.ok(row, `[判定] 用户列表应包含 ${created.username}`);
      assert.equal(row.status, 'active', `[判定] ${created.username} 应为 active`);
      assert.deepEqual(row.roles, ['User'], `[判定] ${created.username} 应只具有 User 角色（§12）`);
    }
    assert.ok(!/password_?hash|passwordHash|password_?salt|passwordSalt/i.test(list.text), '[判定] 用户列表不应返回密码哈希或盐（§70）');
  });

  it('[FUN-04] Alice 加入 Developers', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const developers = need(state.developers, '创建 Developers');
    const alice = need(state.alice, '创建 Alice');
    const bob = need(state.bob, '创建 Bob');

    const res = await call('PATCH', `/api/admin/groups/${developers.id}`, { cookie: admin, body: { members: [alice.id] } });
    assert.equal(res.status, 200, '[判定] PATCH /api/admin/groups/:id 应更新组成员（§13）');

    const users = (await call('GET', '/api/admin/users', { cookie: admin })).json as Array<{ id: string; groups: string[] }>;
    assert.deepEqual(users.find((u) => u.id === alice.id)?.groups, ['Developers'], '[判定] Alice 应属于 Developers');
    assert.deepEqual(users.find((u) => u.id === bob.id)?.groups, [], '[判定] Bob 不应属于任何用户组');

    const groups = (await call('GET', '/api/admin/groups', { cookie: admin })).json as Array<{ id: string; memberCount: number }>;
    assert.equal(groups.find((g) => g.id === developers.id)?.memberCount, 1, '[判定] Developers 应恰好有 1 名成员');
  });

  it('[FUN-05] 创建资产组 Production/Web', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const production = await call('POST', '/api/admin/asset-groups', { cookie: admin, body: { name: 'Production' } });
    assert.equal(production.status, 201, '[判定] 应创建资产组 Production（§15）');
    state.production = { id: String(production.json?.id), name: 'Production' };

    const web = await call('POST', '/api/admin/asset-groups', {
      cookie: admin,
      body: { name: 'Web', parentId: state.production.id },
    });
    assert.equal(web.status, 201, '[判定] 应在 Production 下创建子资产组 Web（§15 parent_id）');
    state.web = { id: String(web.json?.id), name: 'Web', parentId: web.json?.parentId ?? null };

    const list = await call('GET', '/api/admin/asset-groups', { cookie: admin });
    const webRow = (list.json as Array<{ id: string; parentId: string | null }>).find((g) => g.id === state.web?.id);
    assert.equal(webRow?.parentId, state.production.id, '[判定] Web 的 parentId 应指向 Production（§15 树结构）');
  });

  it('[FUN-06] 创建资产 prod-web-01（另建未授权资产 prod-db-01）', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const web = need(state.web, '创建 Production/Web');
    const production = need(state.production, '创建 Production');

    const prodWeb01 = await call('POST', '/api/admin/assets', {
      cookie: admin,
      body: { name: 'prod-web-01', hostname: '8.8.8.8', port: 22, platform: 'linux', environment: 'production', groupIds: [web.id] },
    });
    assert.equal(prodWeb01.status, 201, '[判定] 应创建资产 prod-web-01（§14）');
    state.prodWeb01 = { id: String(prodWeb01.json?.id), name: 'prod-web-01', hostname: '8.8.8.8', port: 22 };

    // prod-db-01 is the "other, unauthorized asset" of §93 step 13 (Production group, not Production/Web).
    const prodDb01 = await call('POST', '/api/admin/assets', {
      cookie: admin,
      body: { name: 'prod-db-01', hostname: '1.1.1.1', port: 22, platform: 'linux', environment: 'production', groupIds: [production.id] },
    });
    assert.equal(prodDb01.status, 201, 'fixture: 应创建资产 prod-db-01');
    state.prodDb01 = { id: String(prodDb01.json?.id), name: 'prod-db-01', hostname: '1.1.1.1', port: 22 };

    const list = (await call('GET', '/api/admin/assets', { cookie: admin })).json as Array<{
      id: string;
      hostname: string;
      port: number;
      groupIds: string[];
    }>;
    const row = list.find((a) => a.id === state.prodWeb01?.id);
    assert.equal(row?.hostname, '8.8.8.8', '[判定] prod-web-01 的 hostname 应被保存');
    assert.equal(row?.port, 22, '[判定] prod-web-01 的端口应被保存');
    assert.deepEqual(row?.groupIds, [web.id], '[判定] prod-web-01 应属于 Production/Web');
  });

  it('[FUN-07] 创建凭证 prod-deploy-key 且响应不含凭证内容', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const res = await call('POST', '/api/admin/credentials', {
      cookie: admin,
      body: { name: 'prod-deploy-key', type: 'private_key', secret: state.secrets.deployKey },
    });
    assert.equal(res.status, 201, '[判定] 应创建 private_key 凭证 prod-deploy-key（§17）');
    state.deployKey = { id: String(res.json?.id), name: 'prod-deploy-key' };
    const extraFields = Object.keys(res.json ?? {}).filter((key) => !CREDENTIAL_SAFE_FIELDS.has(key));
    assert.deepEqual(extraFields, [], '[判定] 凭证创建响应只应包含元数据字段（§18、§71）');
    assert.ok(!res.text.includes(state.secrets.deployKey), '[判定] 凭证创建响应不应包含凭证明文（§18）');

    // Shared password credential for root@prod-web-01 and dba@prod-db-01 (§16: one credential, many accounts).
    const rootPassword = await call('POST', '/api/admin/credentials', {
      cookie: admin,
      body: { name: 'prod-root-password', type: 'password', secret: state.secrets.rootPassword },
    });
    assert.equal(rootPassword.status, 201, 'fixture: 应创建 password 凭证 prod-root-password');
    state.rootPassword = { id: String(rootPassword.json?.id), name: 'prod-root-password' };

    const list = await call('GET', '/api/admin/credentials', { cookie: admin });
    assert.equal(list.status, 200, '[判定] 凭证列表应可读');
    const row = (list.json as Array<{ id: string; type: string }>).find((c) => c.id === state.deployKey?.id);
    assert.equal(row?.type, 'private_key', '[判定] 凭证列表应显示类型 private_key');
    assert.ok(!list.text.includes(state.secrets.deployKey), '[判定] 凭证列表不应包含凭证明文（§18）');
  });

  it('[FUN-08] 创建 SSH 账号 deploy', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const prodDb01 = need(state.prodDb01, '创建 prod-db-01');
    const deployKey = need(state.deployKey, '创建 prod-deploy-key');
    const rootPassword = need(state.rootPassword, '创建 prod-root-password');

    const deploy = await call('POST', `/api/admin/assets/${prodWeb01.id}/accounts`, {
      cookie: admin,
      body: { username: 'deploy', credentialId: deployKey.id },
    });
    assert.equal(deploy.status, 201, '[判定] 应在 prod-web-01 上创建 SSH 账号 deploy（§16）');
    state.deploy = { id: String(deploy.json?.id), assetId: prodWeb01.id, username: 'deploy', credentialId: deployKey.id };

    // root@prod-web-01 is not authorized for Developers (§26); dba@prod-db-01 belongs to the unauthorized asset.
    const root = await call('POST', `/api/admin/assets/${prodWeb01.id}/accounts`, {
      cookie: admin,
      body: { username: 'root', credentialId: rootPassword.id },
    });
    assert.equal(root.status, 201, 'fixture: 应在 prod-web-01 上创建 SSH 账号 root');
    state.root = { id: String(root.json?.id), assetId: prodWeb01.id, username: 'root', credentialId: rootPassword.id };

    const dba = await call('POST', `/api/admin/assets/${prodDb01.id}/accounts`, {
      cookie: admin,
      body: { username: 'dba', credentialId: rootPassword.id },
    });
    assert.equal(dba.status, 201, 'fixture: 应在 prod-db-01 上创建 SSH 账号 dba');
    state.dba = { id: String(dba.json?.id), assetId: prodDb01.id, username: 'dba', credentialId: rootPassword.id };
  });

  // The implementation binds the credential when the account is created (POST body credentialId); there is no
  // separate binding route (updateAssetAccount has no route), so FUN-09 is confirmed on the stored binding.
  it('[FUN-09] deploy 账号绑定 prod-deploy-key', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const deploy = need(state.deploy, '创建 deploy');
    const deployKey = need(state.deployKey, '创建 prod-deploy-key');

    const res = await call('GET', `/api/admin/assets/${prodWeb01.id}/accounts`, { cookie: admin });
    assert.equal(res.status, 200, '[判定] 资产账号列表应可读');
    const row = (res.json as Array<{ id: string; credentialId: string; credentialName: string; credentialType: string }>).find(
      (a) => a.id === deploy.id,
    );
    assert.equal(row?.credentialId, deployKey.id, '[判定] deploy 应绑定 prod-deploy-key（§16）');
    assert.equal(row?.credentialName, 'prod-deploy-key', '[判定] 账号列表应显示绑定的凭证名称');
    assert.equal(row?.credentialType, 'private_key', '[判定] 账号列表应显示绑定的凭证类型');
    assert.ok(!res.text.includes(state.secrets.deployKey), '[判定] 账号列表不应包含凭证明文（§18）');
  });

  it('[FUN-10] 创建授权 Developers → Production/Web → deploy → connect', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const developers = need(state.developers, '创建 Developers');
    const web = need(state.web, '创建 Production/Web');
    const deploy = need(state.deploy, '创建 deploy');

    const res = await call('POST', '/api/admin/authorizations', {
      cookie: admin,
      body: {
        name: 'Developers -> Production/Web -> deploy',
        groupIds: [developers.id],
        assetGroupIds: [web.id],
        accountIds: [deploy.id],
        actions: ['connect'],
      },
    });
    assert.equal(res.status, 201, '[判定] 应创建授权规则（§23）');
    state.rule = { id: String(res.json?.id), name: 'Developers -> Production/Web -> deploy' };

    const list = await call('GET', '/api/admin/authorizations', { cookie: admin });
    const rule = (list.json as Array<{
      id: string;
      groupIds: string[];
      assetGroupIds: string[];
      accountIds: string[];
      actions: string[];
      allAccounts: boolean;
    }>).find((r) => r.id === state.rule?.id);
    assert.ok(rule, '[判定] 授权列表应包含新规则');
    assert.deepEqual(rule.groupIds, [developers.id], '[判定] 规则主体应为 Developers（§24）');
    assert.deepEqual(rule.assetGroupIds, [web.id], '[判定] 规则目标应为 Production/Web（§25）');
    assert.deepEqual(rule.accountIds, [deploy.id], '[判定] 规则账号应为 deploy（§26）');
    assert.deepEqual(rule.actions, ['connect'], '[判定] 规则动作应为 connect（§27）');
    assert.equal(rule.allAccounts, false, '[判定] 规则不应授权全部账号（§26）');
  });

  // ---- FUN-11 .. FUN-15 Alice ----

  it('[FUN-11] Alice 登录', stepOptions(), async () => {
    const alice = need(state.alice, '创建 Alice');
    const res = await loginViaRoute(alice);
    assert.equal(res.status, 200, '[判定] Alice 应能登录（§93-11）');
    assert.ok(alice.cookie, '[判定] 登录成功应下发会话 Cookie');
    const setCookie = res.headers.get('set-cookie') ?? '';
    assert.ok(/HttpOnly/i.test(setCookie), '[判定] 会话 Cookie 应带 HttpOnly（§7）');
    assert.ok(/Secure/i.test(setCookie), '[判定] 会话 Cookie 应带 Secure（§7）');
    assert.ok(/SameSite=Strict/i.test(setCookie), '[判定] 会话 Cookie 应带 SameSite=Strict（§7）');

    const me = await call('GET', '/api/me', { cookie: alice.cookie });
    assert.equal(me.json?.user?.username, 'alice', '[判定] /api/me 应返回 Alice 本人');
  });

  it('[FUN-12] Alice 可以看到 prod-web-01 且只看到被授权的 deploy 账号', stepOptions(), async () => {
    const alice = need(state.alice?.cookie, 'Alice 登录');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const deploy = need(state.deploy, '创建 deploy');

    const res = await call('GET', '/api/assets', { cookie: alice });
    assert.equal(res.status, 200, '[判定] Alice 的可见资产列表应可读');
    const assets = res.json as Array<{ id: string; name: string; accounts: Array<{ id: string; username: string }> }>;
    const visible = assets.find((a) => a.id === prodWeb01.id);
    assert.ok(visible, '[判定] Alice 应能看到 prod-web-01（§30）');
    assert.deepEqual(
      visible.accounts.map((a) => a.id),
      [deploy.id],
      '[判定] Alice 在 prod-web-01 上只应看到被授权的 deploy 账号，不应因资产授权获得 root（§26）',
    );

    const accounts = await call('GET', `/api/assets/${prodWeb01.id}/accounts`, { cookie: alice });
    assert.deepEqual(
      (accounts.json as Array<{ id: string }>).map((a) => a.id),
      [deploy.id],
      '[判定] /api/assets/:id/accounts 只应返回被授权的 deploy 账号',
    );
  });

  it('[FUN-13] Alice 看不到其它未授权资产，未入组的 Bob 看不到任何资产', stepOptions(), async () => {
    const alice = need(state.alice?.cookie, 'Alice 登录');
    const bob = need(state.bob, '创建 Bob');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const prodDb01 = need(state.prodDb01, '创建 prod-db-01');

    // Positive control: the same route returns prod-web-01 for Alice, so an empty result is meaningful.
    const aliceAssets = (await call('GET', '/api/assets', { cookie: alice })).json as Array<{ id: string }>;
    assert.deepEqual(aliceAssets.map((a) => a.id), [prodWeb01.id], '[判定] Alice 只应看到被授权的 prod-web-01（§30）');

    const dbAccounts = await call('GET', `/api/assets/${prodDb01.id}/accounts`, { cookie: alice });
    assert.equal(dbAccounts.status, 200, 'fixture: /api/assets/:id/accounts 应可调用');
    assert.deepEqual(dbAccounts.json, [], '[判定] 未授权资产的账号对 Alice 不可见（§30）');

    const bobLogin = await loginViaRoute(bob);
    assert.equal(bobLogin.status, 200, 'fixture: Bob 应能登录');
    const bobAssets = await call('GET', '/api/assets', { cookie: need(bob.cookie, 'Bob 登录') });
    assert.equal(bobAssets.status, 200, 'fixture: Bob 的可见资产列表应可读');
    assert.deepEqual(bobAssets.json, [], '[判定] 不在 Developers 中的 Bob 不应看到任何资产（§29 Default Deny）');
  });

  it('[FUN-13] 服务器端再次校验：未授权资产或账号无法创建会话', stepOptions(), async () => {
    const alice = need(state.alice?.cookie, 'Alice 登录');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const prodDb01 = need(state.prodDb01, '创建 prod-db-01');
    const root = need(state.root, '创建 root');
    const dba = need(state.dba, '创建 dba');

    const sessionsBefore = await ctx().db.prepare('SELECT COUNT(*) AS count FROM ssh_sessions').first<{ count: number }>();
    const otherAsset = await call('POST', '/api/sessions', { cookie: alice, body: { assetId: prodDb01.id, accountId: dba.id } });
    assert.equal(otherAsset.status, 403, '[判定] Alice 不应能连接未授权资产 prod-db-01（§30、§31）');
    const otherAccount = await call('POST', '/api/sessions', { cookie: alice, body: { assetId: prodWeb01.id, accountId: root.id } });
    assert.equal(otherAccount.status, 403, '[判定] Alice 不应能以未授权账号 root 连接 prod-web-01（§26）');
    const afterCount = await ctx().db.prepare('SELECT COUNT(*) AS count FROM ssh_sessions').first<{ count: number }>();
    assert.equal(afterCount?.count, sessionsBefore?.count, '[判定] 被拒绝的连接请求不应创建会话记录');
  });

  it('[FUN-14] Alice 创建会话获得短时票据与 WebSocket 地址', stepOptions(), async () => {
    const alice = need(state.alice, 'Alice 登录');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const deploy = need(state.deploy, '创建 deploy');

    const requestedAt = Date.now();
    const res = await call('POST', '/api/sessions', {
      cookie: need(alice.cookie, 'Alice 登录'),
      body: { assetId: prodWeb01.id, accountId: deploy.id },
    });
    assert.equal(res.status, 201, '[判定] 被授权的 Alice 应能创建会话（§31）');
    const session: FlowSession = {
      sessionId: String(res.json?.sessionId),
      ticket: String(res.json?.ticket),
      wsUrl: String(res.json?.wsUrl),
      expiresAt: Number(res.json?.expiresAt),
    };
    state.session = session;
    const responded = Date.now();
    assert.ok(session.ticket.length > 0, '[判定] 会话创建应返回票据（§32）');
    assert.ok(session.wsUrl.startsWith(`/api/sessions/${session.sessionId}/ws`), '[判定] 会话创建应返回 WebSocket 地址（§32）');
    assert.ok(
      session.expiresAt > requestedAt && session.expiresAt <= responded + 60_000,
      '[判定] 票据有效期不应超过 60 秒（§32）',
    );

    const row = need(await sessionRow(session.sessionId), 'ssh_sessions 记录');
    assert.equal(row.user_id, alice.id, '[判定] 会话记录应归属 Alice（§43）');
    assert.equal(row.username_snapshot, 'alice', '[判定] 会话记录应保存用户名快照（§43）');
    assert.equal(row.asset_name_snapshot, 'prod-web-01', '[判定] 会话记录应保存资产名快照（§43）');
    assert.equal(row.account_name_snapshot, 'deploy', '[判定] 会话记录应保存账号名快照（§43）');

    const initCalls = ctx().sessions.calls.filter((c) => c.id === doIdOf(session.sessionId) && c.path === '/init');
    assert.equal(initCalls.length, 1, '[判定] createSession 应向该会话的 SSHSessionDO 发送一次 /init（§33）');
  });

  it('[FUN-14] Web Terminal 以票据完成 WebSocket 升级', stepOptions('fun14-ws'), async () => {
    const alice = need(state.alice?.cookie, 'Alice 登录');
    const session = need(state.session, 'Alice 创建会话');
    const res = await call('GET', session.wsUrl, { cookie: alice, headers: { Upgrade: 'websocket' } });
    assert.equal(res.threw, false, '[判定] WebSocket 升级处理不应抛出异常');
    assert.equal(res.status, 101, '[判定] 会话票据经 /api/sessions/:id/ws 应完成 WebSocket 升级（§31、§35）');
  });

  // Contract observation L6: the body createSession() sends to the DO vs the fields SSHSessionDO reads.
  it('[FUN-14] 契约观察：Worker→DO /init 请求体包含 DO 建立 SSH 连接所需字段（L6）', stepOptions('fun14-l6'), async () => {
    const session = need(state.session, 'Alice 创建会话');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const initCall = need(
      ctx().sessions.calls.find((c) => c.id === doIdOf(session.sessionId) && c.method === 'POST' && c.path === '/init'),
      'createSession 发往 DO 的 /init 请求',
    );
    const body = initCall.body as Record<string, unknown> | null;
    assert.ok(body && typeof body === 'object', 'fixture: /init 请求体应为 JSON 对象');

    const missing = INIT_REQUIRED_FIELDS.filter((key) => body[key] === undefined || body[key] === null || body[key] === '');
    assert.deepEqual(missing, [], '[判定] /init 请求体缺少 SSHSessionInitConfig 所需字段（L6）');
    assert.equal(body.host, prodWeb01.hostname, '[判定] /init 的 host 应等于 D1 中资产的 hostname');
    assert.equal(body.port, prodWeb01.port, '[判定] /init 的 port 应等于 D1 中资产的端口');
    assert.equal(body.username, 'deploy', '[判定] /init 的 username 应为目标 SSH 账号 deploy');
    assert.equal(body.authMethod, undefined, '[判定] private_key 凭证应以 authMethod = publickey 交给 DO');
    assert.equal(body.privateKey, undefined, '[判定] private_key 凭证应以 privateKey 字段交给 DO（值不回显）');
  });

  // Contract observation L7: createSession() already inserted the ssh_sessions row; the DO /init inserts it again.
  it('[FUN-14] 契约观察：DO /init 不与 createSession 已写入的 ssh_sessions 行冲突（L7）', stepOptions('fun14-l7'), async () => {
    const alice = need(state.alice, 'Alice 登录');
    const session = need(state.session, 'Alice 创建会话');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const deploy = need(state.deploy, '创建 deploy');

    // Positive control: a DO initialised with native fields and a fresh session id succeeds, so a failure below is
    // attributable to the pre-existing row rather than to the /init body.
    const control = await newProbeDo(nativeInitConfig(`sess_${randomUUID()}`, alice, prodWeb01, deploy));
    assert.equal(control.init.status, 200, 'fixture: 正向对照：全新会话 ID 的 DO /init 应成功');

    // Same native fields, but the session id createSession() has already written (isolates L7 from L6).
    const instance = ctx().sessions.instances.get(doIdOf(session.sessionId));
    assert.ok(instance, 'createSession must initialize its real session DO');
    const actual = await instance.fetch(new Request('https://session.internal/status'));
    assert.equal(actual.status, 200);
    assert.equal((await actual.json<{ sessionId: string }>()).sessionId, session.sessionId);
    const { results } = await ctx()
      .db.prepare('SELECT COUNT(*) AS count FROM ssh_sessions WHERE id = ?')
      .bind(session.sessionId)
      .all<{ count: number }>();
    assert.equal(results?.[0]?.count, 1, '[判定] 同一会话只应有一条 ssh_sessions 记录');
  });

  it('[FUN-15] 浏览器可见的响应与票据不含私钥或凭证密文', stepOptions(), async () => {
    const session = need(state.session, 'Alice 创建会话');
    const deployKey = need(state.deployKey, '创建 prod-deploy-key');
    const rootPassword = need(state.rootPassword, '创建 prod-root-password');

    const payload = decodeTicket(session.ticket);
    assert.ok(payload, 'fixture: 票据载荷应可解码');
    const payloadKeys = Object.keys(payload).sort();
    const allowed = new Set(['sessionId', 'userId', 'assetId', 'accountId', 'exp', 'nonce', 'ip']);
    assert.deepEqual(payloadKeys.filter((k) => !allowed.has(k)), [], '[判定] 票据载荷只应包含会话绑定字段（§32）');

    const { results: rows } = await ctx()
      .db.prepare(
        'SELECT credential_ciphertext, credential_nonce, encrypted_dek, dek_nonce FROM credentials WHERE id IN (?, ?)'
      )
      .bind(deployKey.id, rootPassword.id)
      .all<Record<string, string>>();
    const needles = [state.secrets.deployKey, state.secrets.rootPassword];
    for (const row of rows ?? []) for (const value of Object.values(row)) if (value) needles.push(value);
    assert.equal(needles.length, 10, 'fixture: 两条凭证各 4 个密文列与 2 个明文');

    const texts = [...state.browserTexts, JSON.stringify(payload)];
    const hits = needles.map((needle, index) => (texts.some((t) => t.includes(needle)) ? index : -1)).filter((i) => i >= 0);
    assert.deepEqual(hits, [], '[判定] 浏览器可见的响应或票据中出现凭证明文或密文（下标 0-1 为明文，其余为密文列）（§92-1）');
  });

  // ---- FUN-18 .. FUN-23 Auditor ----

  it('[FUN-18] 前置：经路由创建 Security Auditor 用户 auditor 并登录', stepOptions(), async () => {
    state.auditor = await createUserViaRoute('auditor', 'Security Auditor', 'Security Auditor');
    const res = await loginViaRoute(state.auditor);
    assert.equal(res.status, 200, 'fixture: auditor 应能登录');
    const me = await call('GET', '/api/me', { cookie: need(state.auditor.cookie, 'auditor 登录') });
    const permissions = (me.json?.permissions ?? []) as string[];
    assert.ok(permissions.includes('session.view_all'), '[判定] Security Auditor 应具备 session.view_all（§12）');
    assert.ok(permissions.includes('session.monitor'), '[判定] Security Auditor 应具备 session.monitor（§12）');
    assert.ok(permissions.includes('audit.read'), '[判定] Security Auditor 应具备 audit.read（§12）');
  });

  it('[FUN-18] Auditor 能看到 Alice 的在线会话', stepOptions(), async () => {
    const auditor = need(state.auditor?.cookie, 'auditor 登录');
    const alice = need(state.alice, 'Alice 登录');
    const session = need(state.session, 'Alice 创建会话');

    const res = await call('GET', '/api/admin/sessions?type=online', { cookie: auditor });
    assert.equal(res.status, 200, '[判定] Auditor 应能读取在线会话列表（§47）');
    const online = (res.json as Array<Record<string, unknown>>).find((s) => s.id === session.sessionId);
    assert.ok(online, '[判定] 在线会话列表应包含 Alice 的会话（§47）');
    assert.equal(online.username, 'alice', '[判定] 在线会话应显示用户（§47）');
    assert.equal(online.assetName, 'prod-web-01', '[判定] 在线会话应显示资产（§47）');
    assert.equal(online.accountName, 'deploy', '[判定] 在线会话应显示 SSH 账号（§47）');
    assert.equal(typeof online.sourceIp, 'string', '[判定] 在线会话应显示来源 IP（§47）');
    assert.equal(typeof online.startedAt, 'number', '[判定] 在线会话应显示开始时间（§47）');

    // Negative with the positive control above: a plain User cannot read the admin session list.
    const asAlice = await call('GET', '/api/admin/sessions?type=online', { cookie: need(alice.cookie, 'Alice 登录') });
    assert.equal(asAlice.status, 403, '[判定] 普通用户不应能读取在线会话列表（§11 session.view_all）');
  });

  it('[FUN-19] Auditor 打开 Live Monitor（WebSocket 升级，实时输出不在此判定）', stepOptions('fun19-monitor'), async () => {
    const auditor = need(state.auditor?.cookie, 'auditor 登录');
    const session = need(state.session, 'Alice 创建会话');
    const res = await call('GET', `/api/admin/sessions/${session.sessionId}/monitor`, {
      cookie: auditor,
      headers: { Upgrade: 'websocket' },
    });
    assert.equal(res.threw, false, '[判定] 监控升级处理不应抛出异常');
    assert.equal(res.status, 101, '[判定] Auditor 应能以只读方式升级到会话监控 WebSocket（§48）');
  });

  it('[FUN-20] 前置：Security Auditor 默认不具备 session.terminate', stepOptions(), async () => {
    const auditor = need(state.auditor?.cookie, 'auditor 登录');
    const session = need(state.session, 'Alice 创建会话');
    const res = await call('POST', `/api/admin/sessions/${session.sessionId}/terminate`, { cookie: auditor });
    assert.equal(res.status, 403, '[判定] Security Auditor 默认不应能终止会话（§12 session.terminate 单独配置）');
    const row = need(await sessionRow(session.sessionId), 'ssh_sessions 记录');
    assert.notEqual(row.status, 'terminated', '[判定] 被拒绝的终止请求不应改变会话状态');
  });

  it('[FUN-20] Auditor 获授 session.terminate 后强制终止 Alice 的会话', stepOptions(), async () => {
    const auditorUser = need(state.auditor, 'auditor 登录');
    const auditor = need(auditorUser.cookie, 'auditor 登录');
    const session = need(state.session, 'Alice 创建会话');

    // 无角色管理 API，需数据库配置: there is no role / permission management route, so session.terminate is granted
    // to the auditor through a per-user custom role written directly to D1 (§12 "单独配置").
    assert.equal((await call('PATCH', '/api/admin/roles/role_security_auditor', { cookie: state.admin!.cookie, body: { canTerminate: true } })).status, 200);

    const res = await call('POST', `/api/admin/sessions/${session.sessionId}/terminate`, { cookie: auditor });
    assert.equal(res.status, 200, '[判定] 具备 session.terminate 的 Auditor 应能强制终止会话（§49）');

    const row = need(await sessionRow(session.sessionId), 'ssh_sessions 记录');
    assert.equal(row.status, 'terminated', '[判定] 被终止会话的状态应为 terminated（§44、§49）');
    assert.equal(typeof row.ended_at, 'number', '[判定] 被终止会话应记录结束时间（§43）');

    const doId = doIdOf(session.sessionId);
    assert.ok(
      ctx().sessions.calls.some((c) => c.id === doId && c.method === 'POST' && c.path === '/terminate'),
      '[判定] Worker 应通知该会话的 SSHSessionDO 执行 terminate（§49）',
    );
    assert.equal(ctx().sessions.instances.get(doId)?.getStatus(), 'terminated', '[判定] SSHSessionDO 的状态应为 terminated（§49）');

    const terminated = await auditRows({ action: 'SESSION_TERMINATED', resourceId: session.sessionId });
    assert.ok(
      terminated.some((e) => e.actor_user_id === auditorUser.id),
      '[判定] 应写入以 Auditor 为 actor 的 SESSION_TERMINATED 审计事件（§49）',
    );
  });

  it('[FUN-20] 终止记录归属执行终止的 Auditor（terminated_by 与审计 actor）', stepOptions('fun20-terminated-by'), async () => {
    const auditorUser = need(state.auditor, 'auditor 登录');
    const alice = need(state.alice, 'Alice 登录');
    const session = need(state.session, 'Alice 创建会话');

    const row = need(await sessionRow(session.sessionId), 'ssh_sessions 记录');
    assert.equal(row.terminated_by, auditorUser.id, '[判定] ssh_sessions.terminated_by 应记录执行终止的 Auditor（§43、§49）');
    const terminated = await auditRows({ action: 'SESSION_TERMINATED', resourceId: session.sessionId });
    assert.ok(
      terminated.every((e) => e.actor_user_id !== alice.id),
      '[判定] SESSION_TERMINATED 不应把会话用户 Alice 记为终止者（§49 actor）',
    );
  });

  it('[FUN-22] Historical Session 出现已终止会话记录', stepOptions(), async () => {
    const auditor = need(state.auditor?.cookie, 'auditor 登录');
    const session = need(state.session, 'Alice 创建会话');

    const res = await call('GET', '/api/admin/sessions?type=historical', { cookie: auditor });
    assert.equal(res.status, 200, '[判定] Auditor 应能读取历史会话列表（§74 Historical Sessions）');
    const historical = (res.json as Array<Record<string, unknown>>).find((s) => s.id === session.sessionId);
    assert.ok(historical, '[判定] 历史会话列表应包含 Alice 已终止的会话');
    assert.equal(historical.status, 'terminated', '[判定] 历史会话应显示结果 terminated');
    assert.equal(historical.username, 'alice', '[判定] 历史会话应保留用户名快照（§43）');
    assert.equal(historical.assetName, 'prod-web-01', '[判定] 历史会话应保留资产名快照（§43）');
    assert.equal(historical.accountName, 'deploy', '[判定] 历史会话应保留账号名快照（§43）');
    assert.equal(typeof historical.endedAt, 'number', '[判定] 历史会话应显示结束时间');

    const detail = await call('GET', `/api/admin/sessions/${session.sessionId}`, { cookie: auditor });
    assert.equal(detail.status, 200, '[判定] 会话详情接口应返回该会话（§73）');
    assert.equal(detail.json?.id, session.sessionId, '[判定] 会话详情应指向该会话');

    const online = (await call('GET', '/api/admin/sessions?type=online', { cookie: auditor })).json as Array<{ id: string }>;
    assert.ok(!online.some((s) => s.id === session.sessionId), '[判定] 已终止会话不应再出现在在线会话列表中');
  });

  it('[FUN-23] 未配置录像存储时录像接口安全降级（真实回放不在此判定）', stepOptions(), async () => {
    const auditor = need(state.auditor?.cookie, 'auditor 登录');
    const session = need(state.session, 'Alice 创建会话');
    assert.equal(ctx().env.RECORDINGS, undefined, 'fixture: 本上下文未配置 R2 录像存储');

    const res = await call('GET', `/api/admin/sessions/${session.sessionId}/recording`, { cookie: auditor });
    assert.equal(res.threw, false, '[判定] 录像接口不应抛出异常');
    assert.equal(res.status, 404, '[判定] 未配置录像存储时录像接口应返回 404 而不是 500（§4 R2 可选）');
  });

  // ---- FUN-24 审计链 ----

  it('[FUN-24] 前置：经路由补充执行 §57 所列的其余管理与会话操作', stepOptions(), async () => {
    const admin = need(state.admin?.cookie, 'Super Admin 登录');
    const alice = need(state.alice, 'Alice 登录');
    const bob = need(state.bob, 'Bob 登录');
    const prodWeb01 = need(state.prodWeb01, '创建 prod-web-01');
    const deploy = need(state.deploy, '创建 deploy');

    // LOGIN_FAILED
    const failedLogin = await call('POST', '/api/auth/login', { body: { username: bob.username, password: randomPassword('wrong') } });
    assert.equal(failedLogin.status, 401, 'fixture: 错误密码登录应返回 401');

    // USER_UPDATED / USER_DISABLED / USER_ENABLED
    assert.equal((await call('PATCH', `/api/admin/users/${bob.id}`, { cookie: admin, body: { displayName: 'Bob B.' } })).status, 200, 'fixture: PATCH user');
    assert.equal((await call('POST', `/api/admin/users/${bob.id}/disable`, { cookie: admin })).status, 200, 'fixture: disable user');
    assert.equal((await call('POST', `/api/admin/users/${bob.id}/enable`, { cookie: admin })).status, 200, 'fixture: enable user');

    // GROUP_DELETED
    const tempGroup = await call('POST', '/api/admin/groups', { cookie: admin, body: { name: 'Audit-Temp-Group' } });
    assert.equal(tempGroup.status, 201, 'fixture: create temp group');
    assert.equal((await call('DELETE', `/api/admin/groups/${tempGroup.json?.id}`, { cookie: admin })).status, 200, 'fixture: delete temp group');

    // Temporary asset / credential / account / rule for the UPDATED and DELETED events.
    const tempAsset = await call('POST', '/api/admin/assets', {
      cookie: admin,
      body: { name: 'audit-temp-01', hostname: '9.9.9.9', port: 22, platform: 'linux', environment: 'staging' },
    });
    assert.equal(tempAsset.status, 201, 'fixture: create temp asset');
    const tempAssetId = String(tempAsset.json?.id);
    const tempCred = await call('POST', '/api/admin/credentials', {
      cookie: admin,
      body: { name: 'audit-temp-credential', type: 'password', secret: state.secrets.tempCredential },
    });
    assert.equal(tempCred.status, 201, 'fixture: create temp credential');
    const tempCredId = String(tempCred.json?.id);
    const tempAccount = await call('POST', `/api/admin/assets/${tempAssetId}/accounts`, {
      cookie: admin,
      body: { username: 'ops', credentialId: tempCredId },
    });
    assert.equal(tempAccount.status, 201, 'fixture: create temp account');
    const tempAccountId = String(tempAccount.json?.id);
    const tempRule = await call('POST', '/api/admin/authorizations', {
      cookie: admin,
      body: { name: 'audit-temp-rule', userIds: [bob.id], assetIds: [tempAssetId], accountIds: [tempAccountId], actions: ['connect'] },
    });
    assert.equal(tempRule.status, 201, 'fixture: create temp rule');
    const tempRuleId = String(tempRule.json?.id);

    // AUTHORIZATION_UPDATED / AUTHORIZATION_DELETED
    assert.equal((await call('PATCH', `/api/admin/authorizations/${tempRuleId}`, { cookie: admin, body: { enabled: false } })).status, 200, 'fixture: PATCH rule');
    assert.equal((await call('DELETE', `/api/admin/authorizations/${tempRuleId}`, { cookie: admin })).status, 200, 'fixture: DELETE rule');

    // ACCOUNT_UPDATED / ACCOUNT_DELETED: no route exists, so the service functions are called directly.
    assert.equal((await call('PATCH', `/api/admin/assets/${tempAssetId}/accounts/${tempAccountId}`, { cookie: admin, body: { enabled: false } })).status, 200);
    assert.equal((await call('DELETE', `/api/admin/assets/${tempAssetId}/accounts/${tempAccountId}`, { cookie: admin })).status, 200);

    // ASSET_UPDATED / ASSET_DELETED
    assert.equal((await call('PATCH', `/api/admin/assets/${tempAssetId}`, { cookie: admin, body: { description: 'updated' } })).status, 200, 'fixture: PATCH asset');
    assert.equal((await call('DELETE', `/api/admin/assets/${tempAssetId}`, { cookie: admin })).status, 200, 'fixture: DELETE asset');

    // CREDENTIAL_REPLACED / CREDENTIAL_DELETED
    assert.equal(
      (await call('PUT', `/api/admin/credentials/${tempCredId}`, { cookie: admin, body: { secret: state.secrets.tempCredentialReplaced } })).status,
      200,
      'fixture: PUT credential',
    );
    assert.equal((await call('DELETE', `/api/admin/credentials/${tempCredId}`, { cookie: admin })).status, 200, 'fixture: DELETE credential');

    // SETTING_CHANGED (value equals the default, so behaviour is unchanged)
    assert.equal(
      (await call('PATCH', '/api/admin/settings', {
        cookie: admin,
        body: { key: 'terminate_sessions_on_permission_revocation', value: 'false' },
      })).status,
      200,
      'fixture: PATCH setting',
    );

    // HOST_KEY_TRUSTED / HOST_KEY_CHANGED: first connection to prod-web-01 and a later fingerprint change, presented
    // to an SSHSessionDO the way the handshake does after signature verification (a real handshake needs a real server).
    const hkProbe = await newProbeDo(nativeInitConfig(`sess_${randomUUID()}`, alice, prodWeb01, deploy));
    assert.equal(hkProbe.init.status, 200, 'fixture: host key probe DO /init');
    await ctx().db.prepare('DELETE FROM ssh_host_keys WHERE asset_id = ?').bind(prodWeb01.id).run();
    const firstKey = await syntheticHostKey('a1'.repeat(32));
    const changedKey = await syntheticHostKey('b2'.repeat(32));
    const tofu = hkProbe.instance as unknown as TofuProbe;
    await tofu.processHostKeyTOFU(firstKey.algorithm, firstKey.fingerprint, firstKey.blob);
    await assert.rejects(
      tofu.processHostKeyTOFU(changedKey.algorithm, changedKey.fingerprint, changedKey.blob),
      'fixture: a changed fingerprint must be blocked',
    );

    // SESSION_CLOSED / SESSION_FAILED: a DO-level connect whose TCP connect is refused by the network block.
    const { setCustomSocketConnector } = await import('../src/durable/SSHSessionDO.ts');
    setCustomSocketConnector(() => { ctx().network.attempts.push({ kind: 'socket', target: `${prodWeb01.hostname}:${prodWeb01.port}` }); throw new Error('simulated connection failure'); });
    const connSessionId = `sess_${randomUUID()}`;
    const connProbe = await newProbeDo(nativeInitConfig(connSessionId, alice, prodWeb01, deploy));
    assert.equal(connProbe.init.status, 200, 'fixture: connection probe DO /init');
    const ticketRes = await doFetch(connProbe.instance, 'POST', '/ticket');
    const { ticket } = (await ticketRes.json()) as { ticket: string };
    const consoleCapture = captureConsole();
    try {
      const upgrade = await doFetch(connProbe.instance, 'GET', `/connect?ticket=${encodeURIComponent(ticket)}`, {
        headers: { Upgrade: 'websocket' },
      });
      assert.equal(upgrade.status, 101, 'fixture: DO /connect upgrade');
      await waitFor(
        async () => (await auditRows({ resourceId: connSessionId })).some((e) => e.action !== 'SESSION_CREATED'),
        'DO 连接失败后的会话结束审计',
      );
    } finally {
      consoleCapture.restore();
    }
    assert.equal(connProbe.instance.getStatus(), 'failed', 'fixture: the refused connection must end the session as failed');
    assert.ok(
      ctx().network.attempts.some((a) => a.kind === 'socket' && a.target === `${prodWeb01.hostname}:${prodWeb01.port}`),
      'fixture: the DO must have attempted the TCP connect (blocked by the network block)',
    );

    const ownSession = await newProbeDo(nativeInitConfig(`sess_${randomUUID()}`, alice, prodWeb01, deploy));
    await doFetch(ownSession.instance, 'POST', '/terminate', { body: { clientClosed: true } });

    // LOGOUT (last, so Alice's cookie is no longer needed)
    const logout = await call('POST', '/api/auth/logout', { cookie: need(alice.cookie, 'Alice 登录') });
    assert.equal(logout.status, 200, 'fixture: logout');
    alice.cookie = null;
  });

  it('[FUN-24] 正向对照：Security Auditor 经审计日志接口读取操作链路', stepOptions(), async () => {
    const total = await ctx().db.prepare('SELECT COUNT(*) AS count FROM audit_events').first<{ count: number }>();
    assert.ok((total?.count ?? 0) <= 200, 'fixture: 审计事件总数应在接口单页上限 200 以内');
    state.auditActions = undefined;
    const actions = await auditActionsViaRoute();
    assert.equal(actions.length, total?.count, '[判定] 审计日志接口应返回全部审计事件');
    assert.ok(actions.includes('LOGIN_SUCCESS'), '[判定] 审计日志应包含登录事件');

    const auditText = state.browserTexts[state.browserTexts.length - 1];
    const needles = Object.values(state.secrets);
    const hits = needles.map((needle, index) => (auditText.includes(needle) ? index : -1)).filter((i) => i >= 0);
    assert.deepEqual(hits, [], '[判定] 审计日志接口响应中出现凭证明文（§58）');
  });

  for (const action of SECTION_57_EVENTS) {
    it(`[FUN-24] 审计链包含 ${action}`, { timeout: STEP_TIMEOUT_MS }, async () => {
      const actions = await auditActionsViaRoute();
      assert.ok(actions.includes(action), `[判定] 审计日志中缺少 §57 事件 ${action}`);
    });
  }
});
