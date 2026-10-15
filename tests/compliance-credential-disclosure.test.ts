import { seedSessionMetadata } from './compliance-helpers.ts';
// Supplementary verification tests for the v1-compliance-review spec.
// Topic: credential disclosure — SEC-01, SEC-02, SEC-03, SEC-04, SEC-17 (Property 1) and the
// §22 plaintext-lifecycle observation used by the CRED items.
//
// Design reference: .kiro/specs/v1-compliance-review/design.md C6.3, C6.5 (compliance-credential-disclosure),
// C6.7, C6.8.
// - Task 6.1 (this skeleton): shared in-file scenario helpers, positive controls, and the
//   non-verdict observation of where credential plaintext travels.
// - Task 6.2: the Property 1 tests ([SEC-01]/[SEC-02]/[SEC-03]/[SEC-04]/[SEC-17]) in the "Property 1" describe
//   block at the end of this file. Every iteration runs one fresh scenario (runProperty1Flow) and each test
//   checks its own surface of that scenario.
//
// Rules followed here (C6.7 / C6.8):
// - The implementation is only observed through src/worker.ts (via api()), exported service functions and
//   the real Durable Object classes behind the mock namespaces created by createContext().
// - No network, no real Cloudflare resources; the KEK is random per context, the pepper is a test constant.
// - Assertion messages never echo plaintext values; diagnostics only name locations (route, JSON path,
//   table.column, call path), never values.

import { afterEach, describe, it } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import type { CredentialType } from '../src/types.ts';
import type { SSHSessionInitConfig } from '../src/durable/SSHSessionDO.ts';
import { getSessionCredential } from '../src/credentials/credential-service.ts';
import { SSHSessionDO } from '../src/durable/SSHSessionDO.ts';
import {
  PROPERTY_RUNS,
  api,
  captureConsole,
  createContext,
  createRng,
  decodeTicket,
  flushAsync,
  forAll,
  scanDatabase,
  seedDemoTopology,
  seedFromEnv,
} from './compliance-helpers.ts';
import type {
  ApiOptions,
  ApiResult,
  ComplianceContext,
  DemoTopology,
  MockDoCall,
  Rng,
  SeededAccount,
} from './compliance-helpers.ts';

// -------------------------------------------------------------
// In-file constants
// -------------------------------------------------------------

/** Fields a credential API response may contain (AGENTS.md §18, §71). Used by [SEC-02] in task 6.2. */
const CREDENTIAL_SUMMARY_FIELDS: readonly string[] = ['id', 'name', 'type', 'keyVersion', 'createdAt', 'updatedAt'];

/** Credential row columns holding envelope material that must never reach a browser (§71). */
const CREDENTIAL_MATERIAL_COLUMNS = ['credential_ciphertext', 'credential_nonce', 'encrypted_dek', 'dek_nonce'] as const;

const CREDENTIAL_TYPES: readonly CredentialType[] = ['password', 'private_key'];

// -------------------------------------------------------------
// Randomness and secrets
// -------------------------------------------------------------

function fnv1a(text: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** Per-test reproducible RNG derived from EJ_COMPLIANCE_SEED (or the default seed) and a label. */
function testRng(label: string): Rng {
  return createRng((seedFromEnv() ^ fnv1a(label)) >>> 0);
}

/** Unique, obviously fake credential plaintext `EJ-SECRET-<hex>` (32 hex characters). */
function makeSecret(rng: Rng): string {
  return `EJ-SECRET-${rng.hex(16)}`;
}

function pickCredentialType(rng: Rng): CredentialType {
  return rng.pick(CREDENTIAL_TYPES);
}

// -------------------------------------------------------------
// Scenario lifecycle (one isolated context + §93 topology per scenario)
// -------------------------------------------------------------

interface Scenario {
  ctx: ComplianceContext;
  topo: DemoTopology;
}

// Safety net: every context opened in this file is cleaned up after each test even if a test forgets.
const openContexts = new Set<ComplianceContext>();

afterEach(async () => {
  for (const ctx of openContexts) await ctx.cleanup();
  openContexts.clear();
});

/** Creates a fresh context and seeds the §93 topology; `deploySecret` is the prod-deploy-key plaintext. */
async function openScenario(deploySecret: string): Promise<Scenario> {
  const ctx = await createContext();
  openContexts.add(ctx);
  const topo = await seedDemoTopology(ctx, deploySecret);
  return { ctx, topo };
}

async function closeScenario(scenario: Scenario): Promise<void> {
  openContexts.delete(scenario.ctx);
  await scenario.ctx.cleanup();
}

/** Runs `fn` inside a fresh scenario and always cleans it up (DO timers, network block, console). */
async function withScenario<T>(deploySecret: string, fn: (scenario: Scenario) => Promise<T>): Promise<T> {
  const scenario = await openScenario(deploySecret);
  try {
    return await fn(scenario);
  } finally {
    await closeScenario(scenario);
  }
}

// -------------------------------------------------------------
// Flow log: every response and ticket the "browser" received
// -------------------------------------------------------------

interface FlowLog {
  /**
   * Every API response, labelled with a route template (no IDs, no values) and an optional context
   * (actor / phase) used only in location descriptions.
   */
  responses: Array<{ label: string; context?: string; result: ApiResult }>;
  /** Every session ticket handed to the browser. */
  tickets: string[];
  /** Messages an SSHSessionDO sent to the browser end of the terminal WebSocket (task 6.2 probes). */
  terminalMessages: string[];
}

function newFlowLog(): FlowLog {
  return { responses: [], tickets: [], terminalMessages: [] };
}

/** api() wrapper that records the response under a route-template label. */
async function callApi(
  scenario: Scenario,
  log: FlowLog,
  label: string,
  method: string,
  path: string,
  opts: ApiOptions = {},
  context?: string,
): Promise<ApiResult> {
  const result = await api(scenario.ctx, method, path, opts);
  log.responses.push({ label, context, result });
  return result;
}

async function createCredentialViaRoute(
  scenario: Scenario,
  log: FlowLog,
  input: { name: string; type: CredentialType; secret: string },
): Promise<ApiResult> {
  return callApi(scenario, log, 'POST /api/admin/credentials', 'POST', '/api/admin/credentials', {
    cookie: scenario.topo.admin.cookie,
    body: input,
  });
}

async function replaceCredentialViaRoute(
  scenario: Scenario,
  log: FlowLog,
  credentialId: string,
  secret: string,
): Promise<ApiResult> {
  return callApi(scenario, log, 'PUT /api/admin/credentials/:id', 'PUT', `/api/admin/credentials/${encodeURIComponent(credentialId)}`, {
    cookie: scenario.topo.admin.cookie,
    body: { secret },
  });
}

/**
 * POST /api/sessions as Alice for prod-web-01 / `accountId` (default: deploy), using the implementation's
 * camelCase body (L19).
 */
async function createAliceSession(
  scenario: Scenario,
  log: FlowLog,
  accountId: string = scenario.topo.deploy.id,
): Promise<ApiResult> {
  const result = await callApi(scenario, log, 'POST /api/sessions', 'POST', '/api/sessions', {
    cookie: scenario.topo.alice.cookie,
    body: { assetId: scenario.topo.prodWeb01.id, accountId },
  });
  if (result.status === 201 && typeof result.json?.ticket === 'string') log.tickets.push(result.json.ticket);
  return result;
}

async function terminateSessionAsAdmin(scenario: Scenario, log: FlowLog, sessionId: string): Promise<ApiResult> {
  return callApi(
    scenario,
    log,
    'POST /api/admin/sessions/:id/terminate',
    'POST',
    `/api/admin/sessions/${encodeURIComponent(sessionId)}/terminate`,
    { cookie: scenario.topo.admin.cookie },
  );
}

/** The `/init` calls the Worker sent to the DO addressed by idFromName(sessionId) (session-service.ts). */
function initCallsFor(ctx: ComplianceContext, sessionId: string): MockDoCall[] {
  const doId = ctx.sessions.idFromName(sessionId).toString();
  return ctx.sessions.calls.filter((call) => call.method === 'POST' && call.path === '/init' && call.id === doId);
}

/** Envelope material of one credential row by column (values stay in memory; never printed). */
async function readCredentialMaterialColumns(
  db: D1Database,
  credentialId: string,
): Promise<Array<{ column: string; value: string }>> {
  const row = await db
    .prepare(`SELECT ${CREDENTIAL_MATERIAL_COLUMNS.join(', ')} FROM credentials WHERE id = ?`)
    .bind(credentialId)
    .first<Record<string, unknown>>();
  if (!row) return [];
  const out: Array<{ column: string; value: string }> = [];
  for (const column of CREDENTIAL_MATERIAL_COLUMNS) {
    const value = row[column];
    if (typeof value === 'string' && value !== '') out.push({ column, value });
  }
  return out;
}

/** Envelope material values of one credential row (values stay in memory; never printed). */
async function readCredentialMaterial(db: D1Database, credentialId: string): Promise<string[]> {
  return (await readCredentialMaterialColumns(db, credentialId)).map((entry) => entry.value);
}

// -------------------------------------------------------------
// Exposure locator: names WHERE a needle appears, never the needle itself
// -------------------------------------------------------------

/** JSON paths (`$.a.b[0]`) of string leaves containing `needle`. */
function locateNeedle(value: unknown, needle: string, path: string = '$', out: string[] = []): string[] {
  if (typeof value === 'string') {
    if (value.includes(needle)) out.push(path);
  } else if (Array.isArray(value)) {
    value.forEach((item, index) => locateNeedle(item, needle, `${path}[${index}]`, out));
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) locateNeedle(item, needle, `${path}.${key}`, out);
  }
  return out;
}

function locateInDoCalls(prefix: string, calls: MockDoCall[], needle: string, out: string[]): void {
  for (const call of calls) {
    for (const jsonPath of locateNeedle(call.body, needle)) out.push(`${prefix} ${call.method} ${call.path} 请求体 ${jsonPath}`);
    if (call.url.includes(needle)) out.push(`${prefix} ${call.method} ${call.path} URL`);
    for (const [header, value] of Object.entries(call.headers)) {
      if (value.includes(needle)) out.push(`${prefix} ${call.method} ${call.path} 请求头 ${header}`);
    }
  }
}

/**
 * Lists every observable surface containing `needle`: browser-facing API responses (and decoded ticket
 * payloads), Worker→DO calls, every D1 table/column, captured console lines and blocked network attempts.
 * Entries are location descriptions only.
 */
/**
 * Browser-visible surfaces only (used by [SEC-01]): API response bodies and headers, decoded ticket payloads
 * and terminal WebSocket messages. Worker→DO calls are Worker-internal and deliberately not included.
 */
function locateInBrowserSurfaces(log: FlowLog, needle: string, out: string[] = []): string[] {
  for (const { label, context, result } of log.responses) {
    const where = `API 响应 ${label}${context ? `（${context}）` : ''}`;
    if (result.text.includes(needle)) {
      const jsonPaths = result.json !== null ? locateNeedle(result.json, needle) : [];
      out.push(`${where} ${jsonPaths.length > 0 ? jsonPaths.join(',') : '(原始文本)'}`);
    }
    result.headers.forEach((value, key) => {
      if (value.includes(needle)) out.push(`${where} 响应头 ${key}`);
    });
  }
  for (const ticket of log.tickets) {
    const payload = decodeTicket(ticket);
    for (const jsonPath of locateNeedle(payload, needle)) out.push(`票据载荷 ${jsonPath}`);
    if (payload === null && ticket.includes(needle)) out.push('票据原文');
  }
  log.terminalMessages.forEach((message, index) => {
    if (message.includes(needle)) out.push(`终端 WebSocket 消息 #${index}`);
  });
  return out;
}

async function locateExposures(
  scenario: Scenario,
  log: FlowLog,
  consoleLines: readonly string[],
  needle: string,
): Promise<string[]> {
  const out: string[] = [];

  locateInBrowserSurfaces(log, needle, out);

  locateInDoCalls('Worker→SSHSessionDO', scenario.ctx.sessions.calls, needle, out);
  locateInDoCalls('Worker→RateLimitDO', scenario.ctx.rateLimit.calls, needle, out);

  for (const hit of await scanDatabase(scenario.ctx.db, [needle])) out.push(`D1 ${hit.table}.${hit.column}`);

  const consoleHits = consoleLines.filter((line) => line.includes(needle)).length;
  if (consoleHits > 0) out.push(`console 输出 ${consoleHits} 行`);

  for (const attempt of scenario.ctx.network.attempts) {
    if (attempt.target.includes(needle)) out.push(`网络尝试 ${attempt.kind}`);
  }
  return out;
}

// -------------------------------------------------------------
// Full lifecycle used by the observation (6.1) and Property 1 (6.2)
// -------------------------------------------------------------

interface LifecycleSecrets {
  /** Plaintext of a new credential created through POST /api/admin/credentials. */
  created: string;
  createdType: CredentialType;
  /** Plaintext that replaces prod-deploy-key through PUT /api/admin/credentials/:id (used by the session). */
  replaced: string;
}

interface LifecycleResult {
  createdCredentialId: string;
  sessionId: string;
  ticket: string;
}

interface LifecycleOptions {
  /**
   * Credential replaced through PUT and the account Alice opens the session with.
   * Defaults to prod-deploy-key / deploy (§93 topology).
   */
  target?: { credentialId: string; accountId: string };
  /** Runs after POST /api/sessions succeeded and before the administrator terminates the session. */
  afterSession?: (state: LifecycleResult) => Promise<void>;
}

/**
 * 创建 → 替换 → 建会话 → 终止, entirely through routes:
 *   admin POST /api/admin/credentials (secrets.created)
 *   admin PUT  /api/admin/credentials/:target (secrets.replaced; default target prod-deploy-key)
 *   alice POST /api/sessions (prod-web-01 / target account, so the DO receives secrets.replaced)
 *   [options.afterSession]
 *   admin POST /api/admin/sessions/:id/terminate
 * Precondition failures throw with a message that never contains a plaintext value.
 */
async function runCredentialLifecycle(
  scenario: Scenario,
  log: FlowLog,
  secrets: LifecycleSecrets,
  options: LifecycleOptions = {},
): Promise<LifecycleResult> {
  const target = options.target ?? { credentialId: scenario.topo.deployKey.id, accountId: scenario.topo.deploy.id };

  const created = await createCredentialViaRoute(scenario, log, {
    name: 'compliance-created-credential',
    type: secrets.createdType,
    secret: secrets.created,
  });
  assert.equal(created.status, 201, '前置失败：管理员创建凭证未返回 201');
  const createdCredentialId: unknown = created.json?.id;
  assert.ok(typeof createdCredentialId === 'string' && createdCredentialId !== '', '前置失败：创建凭证响应缺少 id');

  const replaced = await replaceCredentialViaRoute(scenario, log, target.credentialId, secrets.replaced);
  assert.equal(replaced.status, 200, '前置失败：管理员替换凭证未返回 200');

  const session = await createAliceSession(scenario, log, target.accountId);
  assert.equal(session.status, 201, '前置失败：Alice 创建会话未返回 201');
  const sessionId: unknown = session.json?.sessionId;
  const ticket: unknown = session.json?.ticket;
  assert.ok(typeof sessionId === 'string' && sessionId !== '', '前置失败：会话响应缺少 sessionId');
  assert.ok(typeof ticket === 'string' && ticket !== '', '前置失败：会话响应缺少 ticket');

  if (options.afterSession) await options.afterSession({ createdCredentialId, sessionId, ticket });

  const terminated = await terminateSessionAsAdmin(scenario, log, sessionId);
  assert.equal(terminated.status, 200, '前置失败：管理员终止会话未返回 200');

  return { createdCredentialId, sessionId, ticket };
}

// -------------------------------------------------------------
// Task 6.1: positive controls (D9) — the paths the negative scans rely on are actually open
// -------------------------------------------------------------

describe('凭证不外泄：正向对照', () => {
  it('[SEC-01] 正向对照：管理员经路由创建凭证成功（201）', { timeout: 30_000 }, async () => {
    const rng = testRng('6.1:create-credential');
    await withScenario(makeSecret(rng), async (scenario) => {
      const log = newFlowLog();
      const type = pickCredentialType(rng);
      const created = await createCredentialViaRoute(scenario, log, {
        name: 'compliance-positive-control',
        type,
        secret: makeSecret(rng),
      });
      assert.equal(created.status, 201, '正向对照失败：POST /api/admin/credentials 未返回 201');
      assert.ok(typeof created.json?.id === 'string' && created.json.id.startsWith('cred_'), '正向对照失败：响应缺少凭证 id');
      assert.equal(created.json?.name, 'compliance-positive-control', '正向对照失败：响应中的凭证名称不符');
      assert.equal(created.json?.type, type, '正向对照失败：响应中的凭证类型不符');

      const row = await scenario.ctx.db
        .prepare('SELECT id, type FROM credentials WHERE id = ?')
        .bind(created.json.id)
        .first<{ id: string; type: string }>();
      assert.ok(row !== null, '正向对照失败：D1 credentials 表没有新建的凭证行');
      assert.equal(row.type, type, '正向对照失败：D1 中的凭证类型不符');
      assert.equal((await readCredentialMaterial(scenario.ctx.db, created.json.id)).length, 4, '正向对照失败：D1 凭证行缺少信封加密字段');

      const listed = await callApi(scenario, log, 'GET /api/admin/credentials', 'GET', '/api/admin/credentials', {
        cookie: scenario.topo.admin.cookie,
      });
      assert.equal(listed.status, 200, '正向对照失败：GET /api/admin/credentials 未返回 200');
      assert.ok(
        Array.isArray(listed.json) && listed.json.some((item: { id?: unknown }) => item?.id === created.json.id),
        '正向对照失败：凭证列表中没有新建的凭证',
      );
    });
  });

  it('[SEC-01] 正向对照：Alice 经 POST /api/sessions 创建会话得到 201', { timeout: 30_000 }, async () => {
    const rng = testRng('6.1:alice-session');
    await withScenario(makeSecret(rng), async (scenario) => {
      const log = newFlowLog();
      const session = await createAliceSession(scenario, log);
      assert.equal(session.status, 201, '正向对照失败：Alice 创建会话未返回 201');
      assert.ok(typeof session.json?.sessionId === 'string' && session.json.sessionId.startsWith('sess_'), '正向对照失败：响应缺少 sessionId');
      assert.ok(typeof session.json?.ticket === 'string' && session.json.ticket !== '', '正向对照失败：响应缺少 ticket');
      assert.equal(typeof session.json?.wsUrl, 'string', '正向对照失败：响应缺少 wsUrl');

      const payload = decodeTicket(session.json.ticket);
      assert.ok(payload !== null, '正向对照失败：票据载荷无法解码');
      assert.equal(payload.sessionId, session.json.sessionId, '正向对照失败：票据载荷未绑定 sessionId');

      const row = await scenario.ctx.db
        .prepare('SELECT user_id, asset_id, account_id FROM ssh_sessions WHERE id = ?')
        .bind(session.json.sessionId)
        .first<{ user_id: string; asset_id: string; account_id: string }>();
      assert.ok(row !== null, '正向对照失败：D1 ssh_sessions 没有会话记录');
      assert.equal(row.user_id, scenario.topo.alice.id, '正向对照失败：会话记录的 user_id 不是 Alice');
      assert.equal(row.asset_id, scenario.topo.prodWeb01.id, '正向对照失败：会话记录的 asset_id 不符');
      assert.equal(row.account_id, scenario.topo.deploy.id, '正向对照失败：会话记录的 account_id 不符');
    });
  });

  it('[SEC-01] 正向对照：模拟命名空间收到 /init 且不携带凭证明文', { timeout: 30_000 }, async () => {
    const rng = testRng('6.1:init-call');
    const deploySecret = makeSecret(rng);
    await withScenario(deploySecret, async (scenario) => {
      const log = newFlowLog();
      const session = await createAliceSession(scenario, log);
      assert.equal(session.status, 201, '正向对照失败：Alice 创建会话未返回 201');
      const sessionId: string = session.json.sessionId;

      const inits = initCallsFor(scenario.ctx, sessionId);
      assert.equal(inits.length, 1, '正向对照失败：模拟命名空间未恰好收到一次该会话的 /init');
      assert.ok(
        scenario.ctx.sessions.instances.has(scenario.ctx.sessions.idFromName(sessionId).toString()),
        '正向对照失败：/init 未到达真实 SSHSessionDO 实例',
      );

      const body = inits[0].body as {
        sessionId?: unknown;
        assetId?: string; host?: string; port?: number; accountId?: string;
        account?: { id?: unknown };
        credential?: { type?: unknown; plaintext?: unknown };
      } | null;
      assert.ok(body !== null && typeof body === 'object', '正向对照失败：/init 请求体不是 JSON 对象');
      assert.equal(body.sessionId, sessionId, '正向对照失败：/init 请求体的 sessionId 不符');
      assert.equal(body.assetId, scenario.topo.prodWeb01.id, '正向对照失败：/init 请求体的资产 id 不符');
      assert.equal(body.host, scenario.topo.prodWeb01.hostname, '正向对照失败：/init 目标主机不是 D1 资产记录');
      assert.equal(body.port, scenario.topo.prodWeb01.port, '正向对照失败：/init 目标端口不是 D1 资产记录');
      assert.equal(body.accountId, scenario.topo.deploy.id, '正向对照失败：/init 请求体的账号 id 不符');
      assert.equal(body.credential, undefined);
      // Confirms decryption works, so the leak scans of Property 1 search for a value that really flows.
      // Compared with ===, so a mismatch never prints the value.
      assert.ok((await getSessionCredential(scenario.topo.deployKey.id, scenario.ctx.env)).plaintext === deploySecret);
    });
  });
});

// -------------------------------------------------------------
// Task 6.1: observation (no verdict) — where does credential plaintext travel? (§22)
// -------------------------------------------------------------

describe('凭证不外泄：明文去向观察（§22）', () => {
  it('[SEC-01] 观察：凭证明文在"创建 → 替换 → 建会话 → 终止"流程中的出现位置', { timeout: 30_000 }, async (t: TestContext) => {
    const rng = testRng('6.1:observation');
    const seededSecret = makeSecret(rng);
    const secrets: LifecycleSecrets = {
      created: makeSecret(rng),
      createdType: pickCredentialType(rng),
      replaced: makeSecret(rng),
    };

    await withScenario(seededSecret, async (scenario) => {
      const log = newFlowLog();
      const captured = captureConsole();
      try {
        await runCredentialLifecycle(scenario, log, secrets);
      } finally {
        captured.restore();
      }

      const observed: Array<{ label: string; needle: string }> = [
        { label: '会话使用的凭证（PUT 替换后的 prod-deploy-key）', needle: secrets.replaced },
        { label: '被替换前的 prod-deploy-key', needle: seededSecret },
        { label: '经 POST /api/admin/credentials 新建、未被会话使用的凭证', needle: secrets.created },
      ];

      for (const { label, needle } of observed) {
        const where = await locateExposures(scenario, log, captured.lines, needle);
        t.diagnostic(`观察 ${label}：${where.length > 0 ? where.join('；') : '未出现在任何可观察位置'}`);
      }

      const sessionCalls = scenario.ctx.sessions.calls.map((call) => `${call.method} ${call.path}`);
      t.diagnostic(`观察 Worker→SSHSessionDO 调用序列：${sessionCalls.join(' → ') || '无'}`);
      t.diagnostic(`观察 被阻断的网络尝试：${scenario.ctx.network.attempts.length} 次`);
    });
  });
});

// -------------------------------------------------------------
// Task 6.2: Property 1 — 凭证明文与密文不外泄
// ([SEC-01], [SEC-02], [SEC-03], [SEC-04], [SEC-17])
//
// Each iteration (runProperty1Flow, fresh context + §93 topology) does, entirely through routes unless noted:
//   1. random case: four `EJ-SECRET-<hex>` plaintexts, the type of the new credential and the type of the
//      credential Alice's session uses (private_key → prod-deploy-key / deploy; password → prod-root-password /
//      root, granted to Alice by the administrator through POST /api/admin/authorizations);
//   2. 创建 → 替换 → 建会话 (runCredentialLifecycle);
//   3. while the session is open: GET sweep (C6.6, administrator and Alice), then the DO connect-failure probes:
//      (a) the SSHSessionDO instance that received the Worker's /init (mock namespace `instances`): /ticket, then
//          /connect?ticket= with `Upgrade: websocket` called directly on the instance — the route path
//          GET /api/sessions/:id/ws cannot reach the DO (L3: idFromString on `sess_<uuid>`; L4: ticket sent as a
//          header, DO reads the query string). Its /init answered 500 (L6/L7) but the DO keeps the config, so the
//          background SSH connect starts, the network block refuses the socket and the DO logs the failure;
//      (b) an SSHSessionDO constructed by the test with the DO-native SSHSessionInitConfig carrying the same
//          plaintext as `password` / `privateKey`, driven the same way (the shape the DO would receive once L6
//          is resolved);
//   4. 终止 (admin POST /api/admin/sessions/:id/terminate), GET sweep again;
//   5. cleanup (terminates every DO), so console lines include the cleanup path.
// Console output is captured from before seeding until after cleanup.
// -------------------------------------------------------------

/** Base URL for direct Durable Object calls (the host is ignored by the DO). */
const DO_BASE_URL = 'https://session.internal';

const REDACTED = '[REDACTED]';

/**
 * Metadata keys AGENTS.md §58 forbids unless redacted (password, private_key, TOTP secret, session cookie,
 * raw authorization header, DEK, KEK) plus plaintext / ciphertext. Test-side list, independent of the
 * implementation's SENSITIVE_KEY_PATTERNS.
 */
const AUDIT_SENSITIVE_KEY_PATTERNS: readonly RegExp[] = [
  /pass/i,
  /secret/i,
  /private.?key/i,
  /plaintext/i,
  /cipher/i,
  /dek/i,
  /kek/i,
  /totp/i,
  /cookie/i,
  /^authorization$/i,
  /auth.*header/i,
];

/** Credential API responses whose field set is restricted to CREDENTIAL_SUMMARY_FIELDS ([SEC-02]). */
const CREDENTIAL_SUMMARY_ROUTES: ReadonlySet<string> = new Set([
  'POST /api/admin/credentials',
  'PUT /api/admin/credentials/:id',
  'GET /api/admin/credentials',
]);

const CREDENTIAL_DETAIL_ROUTE = 'GET /api/admin/credentials/:id';

const PHASE_ACTIVE = '会话进行中';
const PHASE_ENDED = '会话终止后';

type SweepActor = 'admin' | 'alice';
const SWEEP_ACTORS: readonly SweepActor[] = ['admin', 'alice'];

interface Needle {
  /** Location-free description, e.g. "会话使用的凭证明文"; never the value. */
  label: string;
  value: string;
}

interface Property1Case {
  /** prod-deploy-key plaintext at seeding time (replaced later when the session uses deploy). */
  seededDeploySecret: string;
  /** Type of the credential Alice's session uses (decides deploy vs root). */
  sessionCredentialType: CredentialType;
  secrets: LifecycleSecrets;
}

interface DoProbeResult {
  label: string;
  connectStatus: number;
  socketAttempted: boolean;
  failureLogged: boolean;
  finalStatus: string;
  terminalMessageCount: number;
}

interface Property1Observation {
  scenario: Scenario;
  log: FlowLog;
  /** Console lines from before seeding until after cleanup. */
  consoleLines: readonly string[];
  lifecycle: LifecycleResult;
  plaintexts: Needle[];
  /** Envelope material of every credential row, before the replacement and in the final state (deduplicated). */
  material: Needle[];
  credentialIds: string[];
  doProbes: DoProbeResult[];
}

function genProperty1Case(rng: Rng): Property1Case {
  return {
    seededDeploySecret: makeSecret(rng),
    sessionCredentialType: pickCredentialType(rng),
    secrets: { created: makeSecret(rng), createdType: pickCredentialType(rng), replaced: makeSecret(rng) },
  };
}

function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}

/** Concrete GET requests of C6.6 reachable with a cookie (WebSocket routes carry `Upgrade: websocket`). */
function browserGetProbes(
  topo: DemoTopology,
  ids: { sessionId: string; ticket: string; credentialIds: readonly string[] },
): Array<{ route: string; path: string; upgrade?: boolean }> {
  const sid = encodeURIComponent(ids.sessionId);
  const assetIds = [topo.prodWeb01.id, topo.prodDb01.id].map((id) => encodeURIComponent(id));
  return [
    { route: 'GET /api/health', path: '/api/health' },
    { route: 'GET /api/auth/bootstrap/status', path: '/api/auth/bootstrap/status' },
    { route: 'GET /api/me', path: '/api/me' },
    { route: 'GET /api/assets', path: '/api/assets' },
    ...assetIds.map((id) => ({ route: 'GET /api/assets/:id/accounts', path: `/api/assets/${id}/accounts` })),
    {
      route: 'GET /api/sessions/:id/ws',
      path: `/api/sessions/${sid}/ws?ticket=${encodeURIComponent(ids.ticket)}`,
      upgrade: false,
    },
    { route: 'GET /api/admin/users', path: '/api/admin/users' },
    { route: 'GET /api/admin/groups', path: '/api/admin/groups' },
    { route: 'GET /api/admin/roles', path: '/api/admin/roles' },
    { route: 'GET /api/admin/assets', path: '/api/admin/assets' },
    ...assetIds.map((id) => ({ route: 'GET /api/admin/assets/:id/accounts', path: `/api/admin/assets/${id}/accounts` })),
    ...assetIds.map((id) => ({ route: 'GET /api/admin/assets/:id/host-key', path: `/api/admin/assets/${id}/host-key` })),
    { route: 'GET /api/admin/asset-groups', path: '/api/admin/asset-groups' },
    { route: 'GET /api/admin/credentials', path: '/api/admin/credentials' },
    ...ids.credentialIds.map((id) => ({
      route: CREDENTIAL_DETAIL_ROUTE,
      path: `/api/admin/credentials/${encodeURIComponent(id)}`,
    })),
    { route: 'GET /api/admin/authorizations', path: '/api/admin/authorizations' },
    { route: 'GET /api/admin/sessions?type=online', path: '/api/admin/sessions?type=online' },
    { route: 'GET /api/admin/sessions?type=historical', path: '/api/admin/sessions?type=historical' },
    { route: 'GET /api/admin/sessions/:id', path: `/api/admin/sessions/${sid}` },
    { route: 'GET /api/admin/sessions/:id/commands', path: `/api/admin/sessions/${sid}/commands` },
    { route: 'GET /api/admin/sessions/:id/recording', path: `/api/admin/sessions/${sid}/recording` },
    { route: 'GET /api/admin/sessions/:id/monitor', path: `/api/admin/sessions/${sid}/monitor`, upgrade: true },
    { route: 'GET /api/admin/settings', path: '/api/admin/settings' },
    { route: 'GET /api/admin/audit', path: '/api/admin/audit?limit=200' },
  ];
}

async function sweepBrowserGets(
  scenario: Scenario,
  log: FlowLog,
  ids: { sessionId: string; ticket: string; credentialIds: readonly string[] },
  phase: string,
): Promise<void> {
  const probes = browserGetProbes(scenario.topo, ids);
  for (const actor of SWEEP_ACTORS) {
    const cookie = scenario.topo[actor].cookie;
    for (const probe of probes) {
      await callApi(
        scenario,
        log,
        probe.route,
        'GET',
        probe.path,
        { cookie, headers: probe.upgrade ? { Upgrade: 'websocket' } : undefined },
        `${actor}，${phase}`,
      );
    }
  }
}

function findResponse(log: FlowLog, label: string, context: string): ApiResult | undefined {
  return log.responses.find((entry) => entry.label === label && entry.context === context)?.result;
}

/** Positive controls (D9): the sweep really read populated administrator and user views. */
function assertSweepPositiveControls(log: FlowLog, credentialIds: readonly string[], sessionId: string): void {
  for (const phase of [PHASE_ACTIVE, PHASE_ENDED]) {
    const list = findResponse(log, 'GET /api/admin/credentials', `admin，${phase}`);
    assert.equal(list?.status, 200, `前置失败：管理员 GET /api/admin/credentials 未返回 200（${phase}）`);
    const listedIds = Array.isArray(list?.json) ? list.json.map((item: { id?: unknown }) => item?.id) : [];
    assert.ok(
      credentialIds.every((id) => listedIds.includes(id)),
      `前置失败：管理员凭证列表未包含全部凭证（${phase}）`,
    );
    const detail = findResponse(log, 'GET /api/admin/sessions/:id', `admin，${phase}`);
    assert.equal(detail?.status, 200, `前置失败：管理员 GET /api/admin/sessions/:id 未返回 200（${phase}）`);
    assert.equal(detail?.json?.id, sessionId, `前置失败：会话详情不是本次会话（${phase}）`);
    const audit = findResponse(log, 'GET /api/admin/audit', `admin，${phase}`);
    assert.ok(audit?.status === 200 && Array.isArray(audit.json) && audit.json.length > 0, `前置失败：管理员审计日志为空（${phase}）`);
    const assets = findResponse(log, 'GET /api/assets', `alice，${phase}`);
    assert.ok(
      assets?.status === 200 && Array.isArray(assets.json) && assets.json.length > 0,
      `前置失败：Alice 的可见资产为空（${phase}）`,
    );
  }
}

/** Password-typed session credential: the administrator grants Alice prod-web-01 / root through the route. */
async function prepareSessionTarget(
  scenario: Scenario,
  log: FlowLog,
  type: CredentialType,
): Promise<{ credentialId: string; account: SeededAccount }> {
  const { topo } = scenario;
  if (type === 'private_key') return { credentialId: topo.deployKey.id, account: topo.deploy };
  const grant = await callApi(scenario, log, 'POST /api/admin/authorizations', 'POST', '/api/admin/authorizations', {
    cookie: topo.admin.cookie,
    body: {
      name: 'compliance: alice -> prod-web-01 -> root',
      userIds: [topo.alice.id],
      assetIds: [topo.prodWeb01.id],
      accountIds: [topo.root.id],
      actions: ['connect'],
    },
  });
  assert.equal(grant.status, 201, '前置失败：管理员为 Alice 授权 root 账号未返回 201');
  return { credentialId: topo.rootPassword.id, account: topo.root };
}

async function materialNeedles(db: D1Database, credentialId: string, label: string): Promise<Needle[]> {
  return (await readCredentialMaterialColumns(db, credentialId)).map(({ column, value }) => ({
    label: `${label} ${column}`,
    value,
  }));
}

function dedupeNeedles(needles: Needle[]): Needle[] {
  const seen = new Set<string>();
  return needles.filter((needle) => {
    if (seen.has(needle.value)) return false;
    seen.add(needle.value);
    return true;
  });
}

/** DO-native init config for probe (b): the session's plaintext in the field the DO authenticates with. */
function nativeInitConfig(
  topo: DemoTopology,
  account: SeededAccount,
  type: CredentialType,
  plaintext: string,
): SSHSessionInitConfig {
  const base = {
    sessionId: `sess_${randomUUID()}`,
    userId: topo.alice.id,
    usernameSnapshot: topo.alice.username,
    assetId: topo.prodWeb01.id,
    assetNameSnapshot: topo.prodWeb01.name,
    accountId: account.id,
    accountNameSnapshot: account.username,
    host: topo.prodWeb01.hostname,
    port: topo.prodWeb01.port,
    username: account.username,
    sourceIp: '127.0.0.1',
    userAgent: 'compliance-test',
  };
  return type === 'password'
    ? { ...base, authMethod: 'password', password: plaintext }
    : { ...base, authMethod: 'publickey', privateKey: plaintext };
}

/**
 * Drives one SSHSessionDO through /ticket and /connect?ticket= (with `Upgrade: websocket`) directly on the
 * instance, records what the DO sends to the browser end of the terminal WebSocket, and waits until the
 * background SSH connect (refused by the network block) has ended the session.
 */
async function driveConnectFailure(
  ctx: ComplianceContext,
  log: FlowLog,
  instance: SSHSessionDO,
  label: string,
  consoleLines: readonly string[],
): Promise<DoProbeResult> {
  const attemptsBefore = ctx.network.attempts.length;
  const linesBefore = consoleLines.length;
  const messagesBefore = log.terminalMessages.length;

  const ticketRes = await instance.fetch(new Request(`${DO_BASE_URL}/ticket`, { method: 'POST', headers: { 'x-user-id': (instance as any).config.userId } }));
  const issued = (await ticketRes.json()) as { ticket?: unknown };
  assert.ok(typeof issued.ticket === 'string' && issued.ticket !== '', `前置失败：${label} /ticket 未签发票据`);

  const upgrade = await instance.fetch(
    new Request(`${DO_BASE_URL}/connect?ticket=${encodeURIComponent(issued.ticket)}`, {
      method: 'GET',
      headers: { Upgrade: 'websocket', 'x-user-id': (instance as any).config.userId },
    }),
  );
  // Attach synchronously after the upgrade resolves: the DO sends its error line from a later microtask.
  const client = (upgrade as unknown as { webSocket?: { addEventListener?: (type: string, fn: (event: { data: unknown }) => void) => void } })
    .webSocket;
  client?.addEventListener?.('message', (event) => {
    log.terminalMessages.push(typeof event.data === 'string' ? event.data : String(event.data));
  });

  for (let round = 0; round < 20 && instance.getStatus() === 'connecting'; round++) await flushAsync(1);
  await flushAsync();

  return {
    label,
    connectStatus: upgrade.status,
    socketAttempted: ctx.network.attempts.slice(attemptsBefore).some((attempt) => attempt.kind === 'socket'),
    failureLogged: consoleLines.slice(linesBefore).some((line) => line.includes('ssh_connection_failed')),
    finalStatus: instance.getStatus(),
    terminalMessageCount: log.terminalMessages.length - messagesBefore,
  };
}

function assertDoProbePositiveControl(probe: DoProbeResult): void {
  assert.equal(probe.connectStatus, 101, `前置失败：${probe.label} /connect 未完成升级（101）`);
  assert.ok(probe.socketAttempted, `前置失败：${probe.label} 未发起 TCP 连接（连接失败路径未触发）`);
  assert.ok(probe.failureLogged, `前置失败：${probe.label} 未输出连接失败日志（console 捕获或失败路径未生效）`);
  assert.equal(probe.finalStatus, 'failed', `前置失败：${probe.label} 连接失败后会话状态不是 failed`);
  assert.ok(probe.terminalMessageCount > 0, `前置失败：${probe.label} 未向终端 WebSocket 发送连接错误消息`);
}

/** One full Property 1 iteration; the scenario is already cleaned up when this returns (D1 stays readable). */
async function runProperty1Flow(c: Property1Case): Promise<Property1Observation> {
  const captured = captureConsole();
  let scenario: Scenario | null = null;
  try {
    scenario = await openScenario(c.seededDeploySecret);
    const current = scenario;
    const { ctx, topo } = current;
    const log = newFlowLog();

    const target = await prepareSessionTarget(current, log, c.sessionCredentialType);
    const materialBefore = [
      ...(await materialNeedles(ctx.db, topo.deployKey.id, 'prod-deploy-key 替换前')),
      ...(await materialNeedles(ctx.db, topo.rootPassword.id, 'prod-root-password 替换前')),
    ];

    const doProbes: DoProbeResult[] = [];
    const lifecycle = await runCredentialLifecycle(current, log, c.secrets, {
      target: { credentialId: target.credentialId, accountId: target.account.id },
      afterSession: async ({ createdCredentialId, sessionId, ticket }) => {
        // Positive control (D9): the value the scans look for really flows to the DO.
        const inits = initCallsFor(ctx, sessionId);
        assert.equal(inits.length, 1, '前置失败：模拟命名空间未恰好收到一次该会话的 /init');
        const credential = (inits[0].body as { credential?: { type?: unknown; plaintext?: unknown } } | null)?.credential;
        assert.equal(credential, undefined);
        assert.ok((await getSessionCredential(target.credentialId, ctx.env)).plaintext === c.secrets.replaced);

        const credentialIds = [topo.deployKey.id, topo.rootPassword.id, createdCredentialId];
        await sweepBrowserGets(current, log, { sessionId, ticket, credentialIds }, PHASE_ACTIVE);

        const routed = ctx.sessions.instances.get(ctx.sessions.idFromName(sessionId).toString());
        assert.ok(routed !== undefined, '前置失败：模拟命名空间中没有收到 /init 的 SSHSessionDO 实例');
        doProbes.push(await driveConnectFailure(ctx, log, routed, '经 Worker /init 的 SSHSessionDO', captured.lines));

        const native = ctx.track(new SSHSessionDO(undefined, ctx.env));
        const nativeConfig = nativeInitConfig(topo, target.account, c.sessionCredentialType, c.secrets.replaced);
        await seedSessionMetadata(ctx.db, nativeConfig);
        const init = await native.fetch(
          new Request(`${DO_BASE_URL}/init`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(nativeConfig),
          }),
        );
        assert.equal(init.status, 200, '前置失败：DO 原生配置的 SSHSessionDO /init 未返回 200');
        doProbes.push(await driveConnectFailure(ctx, log, native, 'DO 原生配置的 SSHSessionDO', captured.lines));
      },
    });

    const credentialIds = [topo.deployKey.id, topo.rootPassword.id, lifecycle.createdCredentialId];
    await sweepBrowserGets(current, log, { sessionId: lifecycle.sessionId, ticket: lifecycle.ticket, credentialIds }, PHASE_ENDED);
    assertSweepPositiveControls(log, credentialIds, lifecycle.sessionId);

    const materialAfter = [
      ...(await materialNeedles(ctx.db, topo.deployKey.id, 'prod-deploy-key 终态')),
      ...(await materialNeedles(ctx.db, topo.rootPassword.id, 'prod-root-password 终态')),
      ...(await materialNeedles(ctx.db, lifecycle.createdCredentialId, '新建凭证 终态')),
    ];
    assert.equal(materialAfter.length, 12, '前置失败：凭证行缺少信封加密字段');

    const plaintexts: Needle[] = [
      { label: 'prod-deploy-key 初始明文', value: c.seededDeploySecret },
      { label: 'prod-root-password 初始明文', value: topo.secrets.rootPassword },
      { label: '新建凭证明文', value: c.secrets.created },
      { label: '会话使用的凭证明文（PUT 替换后）', value: c.secrets.replaced },
    ];

    await closeScenario(current);
    return {
      scenario: current,
      log,
      consoleLines: captured.lines,
      lifecycle,
      plaintexts,
      material: dedupeNeedles([...materialBefore, ...materialAfter]),
      credentialIds,
      doProbes,
    };
  } finally {
    if (scenario) await closeScenario(scenario);
    captured.restore();
  }
}

function joinFindings(findings: readonly string[]): string {
  const shown = findings.slice(0, 12).join('；');
  return findings.length > 12 ? `${shown}；…共 ${findings.length} 处` : shown;
}

/** JSON paths of keys matching AUDIT_SENSITIVE_KEY_PATTERNS whose value is not "[REDACTED]". */
function locateUnredactedSensitiveKeys(value: unknown, path: string = '$', out: string[] = [], counter = { seen: 0 }): string[] {
  if (Array.isArray(value)) {
    value.forEach((item, index) => locateUnredactedSensitiveKeys(item, `${path}[${index}]`, out, counter));
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      const child = `${path}.${key}`;
      if (AUDIT_SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(key))) {
        counter.seen++;
        if (item !== REDACTED) out.push(child);
      } else {
        locateUnredactedSensitiveKeys(item, child, out, counter);
      }
    }
  }
  return out;
}

const propertyOptions = { timeout: 60_000 };

describe('Property 1: 凭证明文与密文不外泄', () => {
  // Feature: v1-compliance-review, Property 1: 凭证明文与密文不外泄
  it('[SEC-01] 属性：浏览器可见响应、响应头、票据载荷与终端消息不含凭证明文与信封密文', propertyOptions, async (t: TestContext) => {
    let responses = 0;
    let passwordSessions = 0;
    await forAll(genProperty1Case, async (c) => {
      const obs = await runProperty1Flow(c);
      responses += obs.log.responses.length;
      if (c.sessionCredentialType === 'password') passwordSessions++;
      assert.ok(obs.log.tickets.length === 1, '前置失败：浏览器未收到会话票据');
      assert.ok(decodeTicket(obs.log.tickets[0]) !== null, '前置失败：会话票据载荷无法解码');

      const findings: string[] = [];
      for (const needle of [...obs.plaintexts, ...obs.material]) {
        for (const where of locateInBrowserSurfaces(obs.log, needle.value)) findings.push(`${needle.label} → ${where}`);
      }
      assert.ok(findings.length === 0, `[判定] 浏览器可见位置出现凭证明文或信封密文：${joinFindings(findings)}`);
    }, { runs: PROPERTY_RUNS, seed: seedFromEnv() });
    t.diagnostic(`迭代 ${PROPERTY_RUNS} 次，种子 ${seedFromEnv()}；扫描 API 响应 ${responses} 个；会话凭证类型 password ${passwordSessions} 次、private_key ${PROPERTY_RUNS - passwordSessions} 次`);
  });

  // Feature: v1-compliance-review, Property 1: 凭证明文与密文不外泄
  it('[SEC-02] 属性：凭证 API 响应字段 ⊆ 摘要字段，GET /api/admin/credentials/:id 不返回凭证内容', propertyOptions, async (t: TestContext) => {
    const detailStatuses = new Map<string, number>();
    await forAll(genProperty1Case, async (c) => {
      const obs = await runProperty1Flow(c);
      const needles = [...obs.plaintexts, ...obs.material];
      const findings: string[] = [];
      const successCounts = new Map<string, number>();

      for (const { label, context, result } of obs.log.responses) {
        const where = `${label}${context ? `（${context}）` : ''}`;
        const restricted = CREDENTIAL_SUMMARY_ROUTES.has(label) || label === CREDENTIAL_DETAIL_ROUTE;
        if (!restricted) continue;

        if (label === CREDENTIAL_DETAIL_ROUTE) {
          const key = `${context?.split('，')[0] ?? ''} ${result.status}`;
          detailStatuses.set(key, (detailStatuses.get(key) ?? 0) + 1);
          for (const needle of needles) {
            if (result.text.includes(needle.value)) findings.push(`${where} 返回了${needle.label}`);
          }
        }
        if (!isSuccess(result.status)) continue;
        successCounts.set(label, (successCounts.get(label) ?? 0) + 1);

        const records: unknown[] = Array.isArray(result.json) ? result.json : [result.json];
        records.forEach((record, index) => {
          if (record === null || typeof record !== 'object' || Array.isArray(record)) {
            findings.push(`${where} 第 ${index} 项不是 JSON 对象`);
            return;
          }
          for (const field of Object.keys(record)) {
            if (!CREDENTIAL_SUMMARY_FIELDS.includes(field)) findings.push(`${where} 第 ${index} 项含字段 ${field}`);
          }
        });
      }

      // Positive controls (D9): create, replace and list really answered with credential summaries.
      for (const route of CREDENTIAL_SUMMARY_ROUTES) {
        assert.ok((successCounts.get(route) ?? 0) > 0, `前置失败：${route} 没有成功响应可供检查`);
      }
      assert.equal(
        obs.log.responses.filter((entry) => entry.label === CREDENTIAL_DETAIL_ROUTE).length,
        obs.credentialIds.length * SWEEP_ACTORS.length * 2,
        '前置失败：GET /api/admin/credentials/:id 未覆盖全部凭证、身份与阶段',
      );
      assert.ok(findings.length === 0, `[判定] 凭证 API 响应超出摘要字段或返回凭证内容：${joinFindings(findings)}`);
    }, { runs: PROPERTY_RUNS, seed: seedFromEnv() });
    const statuses = [...detailStatuses.entries()].map(([key, count]) => `${key} ×${count}`).join('，');
    t.diagnostic(`GET /api/admin/credentials/:id 响应状态（身份 状态 ×次数）：${statuses}`);
  });

  // Feature: v1-compliance-review, Property 1: 凭证明文与密文不外泄
  it('[SEC-03] 属性：D1 全表全列不含凭证明文', propertyOptions, async () => {
    await forAll(genProperty1Case, async (c) => {
      const obs = await runProperty1Flow(c);
      const db = obs.scenario.ctx.db;

      // Positive control (D9): the scanner does find known envelope material in credentials.*.
      // The new credential is never replaced, so its final-state ciphertext must still be in credentials.*.
      const ciphertext = obs.material.find((needle) => needle.label === '新建凭证 终态 credential_ciphertext');
      assert.ok(ciphertext !== undefined, '前置失败：没有可用于扫描器自检的凭证密文');
      const selfCheck = await scanDatabase(db, [ciphertext.value]);
      assert.ok(
        selfCheck.some((hit) => hit.table === 'credentials' && hit.column === 'credential_ciphertext'),
        '前置失败：D1 扫描未能定位已知的凭证密文列（扫描器失效）',
      );

      const hits = await scanDatabase(db, obs.plaintexts.map((needle) => needle.value));
      const findings = hits.map((hit) => `D1 ${hit.table}.${hit.column}（${obs.plaintexts[hit.needleIndex].label}）`);
      assert.ok(findings.length === 0, `[判定] D1 中出现凭证明文：${joinFindings(findings)}`);
    }, { runs: PROPERTY_RUNS, seed: seedFromEnv() });
  });

  // Feature: v1-compliance-review, Property 1: 凭证明文与密文不外泄
  it('[SEC-04] 属性：console 输出（含 DO 连接失败路径）不含凭证明文', propertyOptions, async (t: TestContext) => {
    let lines = 0;
    let probes = 0;
    await forAll(genProperty1Case, async (c) => {
      const obs = await runProperty1Flow(c);
      assert.equal(obs.doProbes.length, 2, '前置失败：DO 连接失败探针未全部执行');
      for (const probe of obs.doProbes) assertDoProbePositiveControl(probe);
      lines += obs.consoleLines.length;
      probes += obs.doProbes.length;

      const findings: string[] = [];
      for (const needle of obs.plaintexts) {
        const count = obs.consoleLines.filter((line) => line.includes(needle.value)).length;
        if (count > 0) findings.push(`console 输出 ${count} 行含${needle.label}`);
      }
      assert.ok(findings.length === 0, `[判定] Worker / DO 日志中出现凭证明文：${joinFindings(findings)}`);
    }, { runs: PROPERTY_RUNS, seed: seedFromEnv() });
    t.diagnostic(`捕获 console 输出 ${lines} 行；DO 连接失败路径触发 ${probes} 次（经 Worker /init 的实例与 DO 原生配置实例各 ${PROPERTY_RUNS} 次）`);
  });

  // Feature: v1-compliance-review, Property 1: 凭证明文与密文不外泄
  it('[SEC-17] 属性：audit_events 全部行（含 DO 私有 recordAuditEvent 写入的行）不含凭证明文且敏感键为 [REDACTED]', propertyOptions, async (t: TestContext) => {
    let rowsTotal = 0;
    let doRowsTotal = 0;
    const counter = { seen: 0 };
    await forAll(genProperty1Case, async (c) => {
      const obs = await runProperty1Flow(c);
      const { results } = await obs.scenario.ctx.db
        .prepare('SELECT * FROM audit_events ORDER BY timestamp ASC')
        .all<Record<string, unknown>>();
      const rows = results ?? [];

      // Positive controls (D9): rows from both writers exist — audit-service (sanitized, `audit_` ids) and the
      // DO's private recordAuditEvent (L14: resource_type 'ssh_session', JSON.stringify without sanitizing).
      const doRows = rows.filter((row) => row.resource_type === 'ssh_session');
      assert.ok(doRows.length > 0, '前置失败：没有 DO 私有 recordAuditEvent 写入的审计行');
      assert.ok(
        rows.some((row) => typeof row.id === 'string' && row.id.startsWith('audit_')),
        '前置失败：没有经 audit-service 写入的审计行',
      );
      rowsTotal += rows.length;
      doRowsTotal += doRows.length;

      const findings: string[] = [];
      rows.forEach((row, index) => {
        const where = `audit_events 行#${index}（${String(row.action)}，${row.resource_type === 'ssh_session' ? 'DO 写入' : 'audit-service 写入'}）`;
        for (const [column, value] of Object.entries(row)) {
          if (typeof value !== 'string') continue;
          for (const needle of obs.plaintexts) {
            if (value.includes(needle.value)) findings.push(`${where}.${column} 含${needle.label}`);
          }
        }
        if (typeof row.metadata_json === 'string' && row.metadata_json !== '') {
          let metadata: unknown;
          try {
            metadata = JSON.parse(row.metadata_json);
          } catch {
            findings.push(`${where}.metadata_json 不是合法 JSON`);
            return;
          }
          for (const jsonPath of locateUnredactedSensitiveKeys(metadata, '$', [], counter)) {
            findings.push(`${where}.metadata_json ${jsonPath} 未脱敏`);
          }
        }
      });
      assert.ok(findings.length === 0, `[判定] 审计事件中出现凭证明文或未脱敏的敏感键：${joinFindings(findings)}`);
    }, { runs: PROPERTY_RUNS, seed: seedFromEnv() });
    t.diagnostic(`检查审计行 ${rowsTotal} 条，其中 DO 私有 recordAuditEvent 写入 ${doRowsTotal} 条；metadata 中出现敏感键 ${counter.seen} 次`);
  });
});
