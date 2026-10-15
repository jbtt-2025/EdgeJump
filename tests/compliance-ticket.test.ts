// Supplementary verification tests for the v1-compliance-review spec: Session Ticket (SEC-12).
//
// Design reference: .kiro/specs/v1-compliance-review/design.md C6.1 (L3, L4, L5, L11), C6.3 (file plan),
// C6.5 (compliance-ticket), C6.7 (isolation), C6.8 (todo rules) and Property 7; tasks.md 10.1 / 10.2.
//
// Layers:
// - DO layer (task 10.1, this describe block):
//   * src/backend/security.ts createTicket / verifyTicket / parseTicketPayload — the HMAC ticket that
//     createSession() (src/sessions/session-service.ts) signs with SESSION_TICKET_SECRET and returns
//     to the browser. It is called here the same way createSession() calls it: TextEncoder-encoded secret, client IP
//     and the four binding IDs { sessionId, userId, assetId, accountId }.
//   * SSHSessionDO `/ticket` + `/connect?ticket=` — the DO's own single-use ticket map (validTickets). The DO is
//     reached through the mock SSH_SESSIONS namespace and never receives `/init`, so `/connect` never starts an SSH
//     connection (no config). The DO consumes the ticket before it checks the Upgrade header, therefore every
//     `/connect` probe carries `Upgrade: websocket` (a probe without it would get 426 and burn the ticket).
//     In Node, a 101 response is produced by the DO's fallback branch (status redefined on a 200 Response).
// - End-to-end layer (task 10.2): appended below as a separate describe block (POST /api/sessions ticket through
//   GET /api/sessions/:id/ws, L3/L4/L5).
//
// Time is controlled with node:test mock timers (Date only); DO timers are real but never started here because
// they are armed only after an SSH channel opens. Every DO instance is terminated after use.

import { after, describe, it } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';

import type { ApiResult, ComplianceContext, DemoTopology, MockDoStub, Rng } from './compliance-helpers.ts';
import { createTicket, toBase64Url, verifyTicket } from '../src/backend/security.ts';
import {
  PROPERTY_RUNS,
  TEST_ORIGIN,
  api,
  createContext,
  createRng,
  decodeTicket,
  forAll,
  seedDemoTopology,
  seedFromEnv,
} from './compliance-helpers.ts';

// -------------------------------------------------------------
// In-file helpers (shared by tasks 10.1 and 10.2)
// -------------------------------------------------------------

/** §32: tickets are short-lived (30–60 s suggested); the upper bound is the verdict threshold. */
const TICKET_TTL_LIMIT_MS = 60_000;

/** Property 7: the decoded payload may only carry these keys. */
const ALLOWED_TICKET_PAYLOAD_KEYS: ReadonlySet<string> = new Set([
  'sessionId',
  'userId',
  'assetId',
  'accountId',
  'exp',
  'nonce',
  'ip',
]);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** 2026-10-07T09:00:00Z, the example date used throughout AGENTS.md. */
const FIXED_NOW = Date.UTC(2026, 9, 7, 9, 0, 0);
const ONE_YEAR_MS = 365 * 86_400_000;
const ONE_HOUR_MS = 3_600_000;

const DO_BASE_URL = 'https://ssh-session.do.internal';

/** Deterministic RFC 4122 v4-shaped UUID from the property PRNG. */
function rngUuid(rng: Rng): string {
  const h = rng.hex(16);
  const variant = ((Number.parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** Public-looking client IP (IPv4 or IPv6); only used as ticket payload data, never connected to. */
function rngClientIp(rng: Rng): string {
  if (rng.bool(0.7)) {
    return `${rng.int(1, 223)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`;
  }
  return `2001:4860:${rng.hex(2)}:${rng.hex(2)}::${rng.hex(2)}`;
}

/** Offset strictly after a deadline: often the +1 ms edge, otherwise up to one hour later. */
function rngAfterOffset(rng: Rng): number {
  return rng.bool(0.25) ? 1 : rng.int(1, ONE_HOUR_MS);
}

interface SessionParams {
  sessionId: string;
  userId: string;
  assetId: string;
  accountId: string;
  clientIp: string;
  /** Ticket signing secret (stands in for SESSION_TICKET_SECRET); random per run, never a real secret. */
  signingSecret: string;
  /** Simulated issue time. */
  now: number;
}

function genSessionParams(rng: Rng): SessionParams {
  return {
    sessionId: `sess_${rngUuid(rng)}`,
    userId: `usr_${rngUuid(rng)}`,
    assetId: `ast_${rngUuid(rng)}`,
    accountId: `acc_${rngUuid(rng)}`,
    clientIp: rngClientIp(rng),
    signingSecret: `compliance-ticket-secret-${rng.hex(32)}`,
    now: FIXED_NOW + rng.int(0, ONE_YEAR_MS),
  };
}

interface ConnectResult {
  status: number;
  text: string;
  webSocket: unknown;
}

/** SSHSessionDO probe reached through the mock SSH_SESSIONS namespace, without ever calling `/init`. */
interface TicketDoProbe {
  sessionId: string;
  idHex: string;
  issueTicket(): Promise<{ status: number; ticket: string; expiresAt: number }>;
  connect(ticket: string): Promise<ConnectResult>;
  terminate(): Promise<void>;
}

async function openTicketDo(ctx: ComplianceContext, sessionId: string): Promise<TicketDoProbe> {
  const id = ctx.sessions.idFromName(sessionId);
  const idHex = id.toString();
  const stub: MockDoStub = ctx.sessions.get(id);

  await stub.fetch(new Request(`${DO_BASE_URL}/status`));
  const instance = ctx.sessions.instances.get(idHex)! as any;
  instance.config = { sessionId, userId: 'ticket-user', assetId: 'ticket-asset', accountId: 'ticket-account' };
  instance.sessionId = sessionId;
  instance.connectionStarted = true;
  return {
    sessionId,
    idHex,
    async issueTicket() {
      const response = await stub.fetch(new Request(`${DO_BASE_URL}/ticket`, { method: 'POST', headers: { 'x-user-id': 'ticket-user' } }));
      const json = (await response.json()) as { ticket?: unknown; expiresAt?: unknown };
      return {
        status: response.status,
        ticket: typeof json.ticket === 'string' ? json.ticket : '',
        expiresAt: typeof json.expiresAt === 'number' ? json.expiresAt : Number.NaN,
      };
    },
    async connect(ticket: string) {
      const response = await stub.fetch(
        new Request(`${DO_BASE_URL}/connect?ticket=${encodeURIComponent(ticket)}`, {
          method: 'GET',
          headers: { Upgrade: 'websocket', 'x-user-id': 'ticket-user' },
        }),
      );
      return {
        status: response.status,
        text: await response.text(),
        webSocket: (response as unknown as { webSocket?: unknown }).webSocket ?? null,
      };
    },
    async terminate() {
      const instance = ctx.sessions.instances.get(idHex);
      if (instance) await instance.terminate('compliance_ticket_probe');
    },
  };
}

// One context per test; `after` is a safety net for contexts left open by a failure.
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
// Task 10.1: DO layer
// -------------------------------------------------------------

describe('compliance-ticket: SEC-12 会话票据（DO 层）', () => {
  // Feature: v1-compliance-review, Property 7: 会话票据短时、单次且内容受限（DO 层）
  it('[SEC-12] createTicket 票据有效期不超过 60 秒、载荷键受限且不含密钥、越过 exp 后校验失败', { timeout: 60_000 }, async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
    const encoder = new TextEncoder();
    const seenNonces = new Set<string>();

    await forAll(
      (rng) => ({
        params: genSessionParams(rng),
        withinRatio: rng.next(),
        afterOffset: rngAfterOffset(rng),
      }),
      async ({ params: p, withinRatio, afterOffset }) => {
        t.mock.timers.setTime(p.now);
        const secretBytes = encoder.encode(p.signingSecret);

        // Same call shape as createSession() (src/sessions/session-service.ts, step 7).
        const { ticket, expiresAt } = await createTicket(secretBytes, p.clientIp, {
          sessionId: p.sessionId,
          userId: p.userId,
          assetId: p.assetId,
          accountId: p.accountId,
        });

        // Short-lived (§32).
        const ttl = expiresAt - p.now;
        assert.ok(Number.isFinite(ttl) && ttl > 0, '[判定] 票据过期时间应晚于签发时间（§32）');
        assert.ok(ttl <= TICKET_TTL_LIMIT_MS, '[判定] 票据有效期不应超过 60 秒（§32）');

        // Restricted content (§32).
        const parts = ticket.split('.');
        assert.equal(parts.length, 2, 'fixture: ticket has the <payload>.<signature> shape');
        const payload = decodeTicket(ticket);
        assert.ok(payload, 'fixture: ticket payload decodes through parseTicketPayload');

        const unexpectedKeys = Object.keys(payload).filter((key) => !ALLOWED_TICKET_PAYLOAD_KEYS.has(key));
        assert.ok(
          unexpectedKeys.length === 0,
          `[判定] 票据载荷含白名单之外的键（§32）：${unexpectedKeys.join(', ')}`,
        );
        assert.ok(
          Object.values(payload).every((value) => typeof value === 'string' || typeof value === 'number'),
          '[判定] 票据载荷只应包含标量绑定字段，不应携带嵌套对象（§32）',
        );
        assert.ok(
          payload.sessionId === p.sessionId &&
            payload.userId === p.userId &&
            payload.assetId === p.assetId &&
            payload.accountId === p.accountId,
          '[判定] 票据应绑定 session_id、user_id、asset_id、account_id（§32）',
        );
        assert.ok(payload.exp === expiresAt, '[判定] 票据载荷 exp 应等于返回的 expiresAt（§32）');
        assert.ok(
          typeof payload.nonce === 'string' && UUID_PATTERN.test(payload.nonce),
          '[判定] 票据应携带随机 nonce（§32）',
        );
        assert.ok(!seenNonces.has(payload.nonce as string), '[判定] 每张票据的 nonce 应互不相同（§32）');
        seenNonces.add(payload.nonce as string);
        assert.ok(payload.ip === p.clientIp, 'observation: payload.ip carries the client IP passed by the caller');

        const secretForms = [p.signingSecret, toBase64Url(secretBytes)];
        const payloadText = JSON.stringify(payload);
        assert.ok(
          secretForms.every((form) => !ticket.includes(form) && !payloadText.includes(form)),
          '[判定] 票据及其解码载荷不应包含签名密钥',
        );

        // Positive control: inside the validity window the ticket verifies.
        const withinOffset = Math.floor(withinRatio * ttl);
        t.mock.timers.setTime(p.now + Math.min(withinOffset, ttl - 1));
        assert.equal(
          await verifyTicket(secretBytes, ticket, p.clientIp),
          true,
          '[判定] 有效期内票据应通过 verifyTicket 校验（正向对照）',
        );

        // Negative: once simulated time passes exp, verification fails.
        t.mock.timers.setTime(expiresAt + afterOffset);
        assert.equal(
          await verifyTicket(secretBytes, ticket, p.clientIp),
          false,
          '[判定] 模拟时间越过 exp 后 verifyTicket 应返回 false（§32）',
        );
      },
      { runs: PROPERTY_RUNS, seed: seedFromEnv() },
    );
  });

  // Feature: v1-compliance-review, Property 7: 会话票据短时、单次且内容受限（DO 层）
  it('[SEC-12] DO /ticket 票据有效期内首次升级为 101，第二次使用与越过 60 秒后首次使用均为 403', { timeout: 60_000 }, async (t) => {
    await withContext(async (ctx) => {
      t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });

      await forAll(
        (rng) => ({
          sessionId: `sess_${rngUuid(rng)}`,
          now: FIXED_NOW + rng.int(0, ONE_YEAR_MS),
          withinRatio: rng.next(),
          afterOffset: rngAfterOffset(rng),
          forgedTicket: rngUuid(rng),
        }),
        async (c) => {
          t.mock.timers.setTime(c.now);
          const probe = await openTicketDo(ctx, c.sessionId);
          try {
            // Two tickets issued at the same instant: A is used inside the window, B only after 60 s.
            const issuedA = await probe.issueTicket();
            const issuedB = await probe.issueTicket();
            for (const issued of [issuedA, issuedB]) {
              assert.equal(issued.status, 200, 'fixture: DO /ticket answers 200');
              assert.ok(issued.ticket !== '', 'fixture: DO /ticket returns a ticket string');
              const ttl = issued.expiresAt - c.now;
              assert.ok(Number.isFinite(ttl) && ttl > 0, '[判定] DO 票据过期时间应晚于签发时间（§32）');
              assert.ok(ttl <= TICKET_TTL_LIMIT_MS, '[判定] DO 票据有效期不应超过 60 秒（§32）');
            }
            assert.ok(issuedA.ticket !== issuedB.ticket, '[判定] DO 每次签发的票据应互不相同（§32）');

            // A ticket that was never issued is rejected.
            const forged = await probe.connect(c.forgedTicket);
            assert.equal(forged.status, 403, '[判定] 未经 DO 签发的票据应被拒绝（§32）');

            // Positive control: first use inside the validity window upgrades.
            const ttlA = issuedA.expiresAt - c.now;
            t.mock.timers.setTime(c.now + Math.floor(c.withinRatio * ttlA));
            const first = await probe.connect(issuedA.ticket);
            assert.equal(first.status, 101, '[判定] 有效期内首次以 WebSocket 升级使用票据应成功（正向对照）');
            assert.ok(first.webSocket !== null, 'observation: the 101 response carries the client WebSocket');

            // Negative: the same ticket cannot be used twice.
            const second = await probe.connect(issuedA.ticket);
            assert.equal(second.status, 403, '[判定] 票据第二次使用应被拒绝（单次有效，§32）');
            assert.equal(second.text, 'Invalid or expired ticket', 'observation: a consumed ticket is unknown to the DO');

            // Negative: a never-used ticket is rejected once 60 s have passed since issue.
            t.mock.timers.setTime(c.now + TICKET_TTL_LIMIT_MS + c.afterOffset);
            const expired = await probe.connect(issuedB.ticket);
            assert.equal(expired.status, 403, '[判定] 越过 60 秒后票据首次使用也应被拒绝（§32）');

            const again = await probe.connect(issuedB.ticket);
            assert.equal(again.status, 403, '[判定] 过期被拒的票据之后仍应被拒绝（§32）');

            // Fixture invariants: no /init for this DO, hence no SSH connection attempt.
            assert.ok(
              !ctx.sessions.calls.some((call) => call.id === probe.idHex && call.path === '/init'),
              'fixture: the DO probe never receives /init',
            );
            assert.equal(ctx.network.attempts.length, 0, 'fixture: no network attempt is made by the DO probe');
          } finally {
            await probe.terminate();
          }
        },
        { runs: PROPERTY_RUNS, seed: seedFromEnv() },
      );
    });
  });
});

// -------------------------------------------------------------
// Task 10.2: end-to-end layer (appended by task 10.2)
// -------------------------------------------------------------
//
// Entry point: the default export of src/worker.ts through api(), i.e. the real router, createSession() and the mock
// SSH_SESSIONS namespace backed by real SSHSessionDO instances. The ticket under test is the one POST /api/sessions
// returns (createSession(), src/sessions/session-service.ts:151) together with the wsUrl handed to the browser
// (session-service.ts:219). Request bodies use the implementation field names { assetId, accountId } (L19).
//
// Every upgrade carries `Upgrade: websocket`, the same Origin (api() default, TEST_ORIGIN) and the same
// CF-Connecting-IP as the session creation, so a rejection can only come from the ticket / session checks.
// The router returns the DO response unwrapped, so a 101 produced by the DO fallback branch reaches the test.
//
// D9: the "second use", "expired" and "other user" rejections only mean something once the positive path (first use
// of the route-issued ticket upgrades with 101) works. Each of those tests asserts the positive path first, so a
// broken positive path can never let a rejection count as a pass.
//
// Mocked clock: Date is mocked from FIXED_NOW before the context is seeded (login cookies expire 8 h later); run N
// works inside [FIXED_NOW + (N + 1) · spacing, + 2 min], so 100 runs stay inside the login-session TTL.

/** Spacing between property iterations on the mocked clock (each run needs at most 60 s + 60 s + 1 s). */
const E2E_ITERATION_SPACING_MS = 3 * 60_000;

type OtherUserKey = 'bob' | 'auditor' | 'assetAdmin' | 'admin';
/** Users other than the session owner Alice; Bob (plain User) is picked in at least half of the runs. */
const OTHER_USER_KEYS: readonly OtherUserKey[] = ['bob', 'auditor', 'assetAdmin', 'admin'];

interface E2eCase {
  issueAt: number;
  clientIp: string;
  firstRatio: number;
  secondRatio: number;
  expiredOffset: number;
  holder: OtherUserKey;
}

function genE2eCase(rng: Rng, run: number): E2eCase {
  return {
    issueAt: FIXED_NOW + (run + 1) * E2E_ITERATION_SPACING_MS + rng.int(0, 999),
    clientIp: rngClientIp(rng),
    firstRatio: rng.next(),
    secondRatio: rng.next(),
    expiredOffset: rng.bool(0.25) ? 1 : rng.int(1, TICKET_TTL_LIMIT_MS),
    holder: rng.bool(0.5) ? 'bob' : rng.pick(OTHER_USER_KEYS),
  };
}

/** Simulated instant in [from, to] (inclusive) chosen by ratio ∈ [0, 1). */
function instantWithin(from: number, to: number, ratio: number): number {
  return from + Math.floor(ratio * (Math.max(to, from) - from + 1));
}

interface IssuedSession {
  sessionId: string;
  ticket: string;
  wsUrl: string;
  expiresAt: number;
  issuedAt: number;
  /** Raw POST /api/sessions response text (scanned for secrets, never printed). */
  responseText: string;
  /** Id of the SSHSessionDO that received createSession()'s /init for this session. */
  initDoId: string;
}

/** Alice creates a session on prod-web-01 / deploy through POST /api/sessions (positive precondition). */
async function createAliceSession(ctx: ComplianceContext, topo: DemoTopology, clientIp: string): Promise<IssuedSession> {
  const issuedAt = Date.now();
  const res = await api(ctx, 'POST', '/api/sessions', {
    cookie: topo.alice.cookie,
    body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id },
    headers: { 'CF-Connecting-IP': clientIp },
  });
  assert.equal(res.threw, false, 'fixture: POST /api/sessions does not throw');
  assert.equal(res.status, 201, 'fixture: authorized Alice creates a session (judged by SEC-06 / FUN-14)');

  const json = (res.json ?? {}) as { sessionId?: unknown; ticket?: unknown; wsUrl?: unknown; expiresAt?: unknown };
  const sessionId = typeof json.sessionId === 'string' ? json.sessionId : '';
  const ticket = typeof json.ticket === 'string' ? json.ticket : '';
  const wsUrl = typeof json.wsUrl === 'string' ? json.wsUrl : '';
  const expiresAt = typeof json.expiresAt === 'number' ? json.expiresAt : Number.NaN;
  assert.ok(sessionId !== '' && ticket !== '' && wsUrl !== '', 'fixture: the response carries sessionId, ticket and wsUrl');
  assert.ok(Number.isFinite(expiresAt) && expiresAt > issuedAt, 'fixture: the response carries a future expiresAt');

  const ws = new URL(wsUrl, TEST_ORIGIN);
  assert.equal(ws.pathname, `/api/sessions/${sessionId}/ws`, 'fixture: wsUrl points at the session WebSocket route');
  assert.ok(ws.searchParams.get('ticket') === ticket, 'fixture: wsUrl carries the issued ticket as ?ticket=');

  const init = ctx.sessions.calls.find(
    (call) => call.path === '/init' && (call.body as { sessionId?: unknown } | null)?.sessionId === sessionId,
  );
  assert.ok(init, 'fixture: createSession dispatches /init to the session DO');

  return { sessionId, ticket, wsUrl, expiresAt, issuedAt, responseText: res.text, initDoId: init.id };
}

interface UpgradeResult {
  res: ApiResult;
  /** DO ids called while the upgrade was handled, in call order. */
  doIds: string[];
}

/** Browser-side terminal upgrade: GET wsUrl with the holder's cookie, same Origin and the given client IP. */
async function upgradeTerminal(ctx: ComplianceContext, cookie: string, wsUrl: string, clientIp: string): Promise<UpgradeResult> {
  const before = ctx.sessions.calls.length;
  const res = await api(ctx, 'GET', wsUrl, {
    cookie,
    headers: { Upgrade: 'websocket', 'CF-Connecting-IP': clientIp },
  });
  return { res, doIds: ctx.sessions.calls.slice(before).map((call) => call.id) };
}

/** Status plus the route / DO error label for verdict messages; labels that are not plain short text are dropped. */
function outcome(res: ApiResult): string {
  const label: unknown = typeof res.json?.error === 'string' ? res.json.error : res.json === null ? res.text : '';
  const safe = typeof label === 'string' && /^[A-Za-z][A-Za-z0-9 .,'_-]{0,79}$/.test(label) ? label : '';
  return safe ? `${res.status} ${safe}` : String(res.status);
}

/** Mocked Date from FIXED_NOW, then a seeded §93 topology; the deploy key plaintext is random per test. */
async function withSeededContext(
  t: TestContext,
  fn: (ctx: ComplianceContext, topo: DemoTopology) => Promise<void>,
): Promise<void> {
  t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
  await withContext(async (ctx) => {
    const secretRng = createRng(seedFromEnv() ^ 0x5ec12);
    const topo = await seedDemoTopology(ctx, `EJ-SECRET-${secretRng.hex(24)}`);
    await fn(ctx, topo);
  });
}

describe('compliance-ticket: SEC-12 会话票据（端到端层）', () => {
  // Feature: v1-compliance-review, Property 7: 会话票据短时、单次且内容受限（端到端层）
  it(
    '[SEC-12] POST /api/sessions 签发的票据经 /api/sessions/:id/ws 有效期内首次升级为 101，第二次使用与过期后首次使用均为 403',
    { timeout: 60_000 },
    async (t) => {
      await withSeededContext(t, async (ctx, topo) => {
        await forAll(
          (rng, run) => genE2eCase(rng, run),
          async (c) => {
            t.mock.timers.setTime(c.issueAt);
            const session = await createAliceSession(ctx, topo, c.clientIp);
            const expiring = await createAliceSession(ctx, topo, c.clientIp);
            const lastValid = Math.min(session.expiresAt, c.issueAt + TICKET_TTL_LIMIT_MS) - 1;

            // Positive path: first use inside the validity window upgrades on the session's own DO.
            const firstAt = instantWithin(c.issueAt, lastValid, c.firstRatio);
            t.mock.timers.setTime(firstAt);
            const first = await upgradeTerminal(ctx, topo.alice.cookie, session.wsUrl, c.clientIp);
            assert.equal(first.res.threw, false, '[判定] WebSocket 升级处理不应抛出异常');
            assert.equal(
              first.res.status,
              101,
              `[判定] 路由签发的票据在有效期内首次经 /api/sessions/:id/ws 升级应为 101（§31、§32；实际 ${outcome(first.res)}）`,
            );
            assert.ok(first.res.webSocket !== null, '[判定] 101 响应应携带客户端 WebSocket');
            assert.ok(
              first.doIds.length > 0 && first.doIds.every((id) => id === session.initDoId),
              '[判定] 升级应转发到 createSession 发送 /init 的同一 SSHSessionDO（§33 DO_ID = session_id）',
            );

            // Negative: the same ticket cannot be used a second time, even inside the window.
            t.mock.timers.setTime(instantWithin(firstAt, lastValid, c.secondRatio));
            const second = await upgradeTerminal(ctx, topo.alice.cookie, session.wsUrl, c.clientIp);
            assert.equal(
              second.res.status,
              403,
              `[判定] 同一票据第二次升级应被拒绝为 403（单次有效，§32；实际 ${outcome(second.res)}）`,
            );
            assert.ok(second.res.webSocket === null, '[判定] 第二次使用不应获得 WebSocket');

            // Negative: a never-used ticket is rejected once its expiry has passed.
            t.mock.timers.setTime(expiring.expiresAt + c.expiredOffset);
            const expired = await upgradeTerminal(ctx, topo.alice.cookie, expiring.wsUrl, c.clientIp);
            assert.equal(
              expired.res.status,
              403,
              `[判定] 过期后首次使用路由签发的票据应被拒绝为 403（§32；实际 ${outcome(expired.res)}）`,
            );
            assert.ok(expired.res.webSocket === null, '[判定] 过期票据不应获得 WebSocket');
          },
          { runs: PROPERTY_RUNS, seed: seedFromEnv() },
        );
      });
    },
  );

  // Feature: v1-compliance-review, Property 7: 会话票据短时、单次且内容受限（端到端层）
  it('[SEC-12] Bob 等其他用户携带 Alice 的票据升级应被拒绝（票据绑定用户）', { timeout: 60_000 }, async (t) => {
    await withSeededContext(t, async (ctx, topo) => {
      await forAll(
        (rng, run) => genE2eCase(rng, run),
        async (c) => {
          t.mock.timers.setTime(c.issueAt);
          const control = await createAliceSession(ctx, topo, c.clientIp);
          const target = await createAliceSession(ctx, topo, c.clientIp);
          const lastValid = Math.min(control.expiresAt, target.expiresAt, c.issueAt + TICKET_TTL_LIMIT_MS) - 1;
          t.mock.timers.setTime(instantWithin(c.issueAt, lastValid, c.firstRatio));

          // Positive control (D9): Alice's own route-issued ticket upgrades; otherwise the binding cannot be verified.
          const own = await upgradeTerminal(ctx, topo.alice.cookie, control.wsUrl, c.clientIp);
          assert.equal(
            own.res.status,
            101,
            `[判定] 正向对照：Alice 以本人票据首次升级应为 101，否则票据绑定无法验证（实际 ${outcome(own.res)}）`,
          );

          // Negative: another logged-in user presents Alice's unused ticket from the same IP and Origin.
          const holder = topo[c.holder];
          const foreign = await upgradeTerminal(ctx, holder.cookie, target.wsUrl, c.clientIp);
          assert.equal(foreign.res.threw, false, '[判定] WebSocket 升级处理不应抛出异常');
          assert.notEqual(
            foreign.res.status,
            101,
            '[判定] 其他用户持 Alice 的票据不应完成 WebSocket 升级（§31 升级时再次校验 user_id，§32 票据绑定 user_id）',
          );
          assert.ok(foreign.res.webSocket === null, '[判定] 其他用户持 Alice 的票据不应获得 WebSocket');
          assert.ok(
            [401, 403, 404].includes(foreign.res.status),
            `[判定] 其他用户持 Alice 的票据应被拒绝为 401 / 403 / 404（实际 ${outcome(foreign.res)}）`,
          );
        },
        { runs: PROPERTY_RUNS, seed: seedFromEnv() },
      );
    });
  });

  // Feature: v1-compliance-review, Property 7: 会话票据短时、单次且内容受限（端到端层）
  it('[SEC-12] POST /api/sessions 签发的票据有效期不超过 60 秒、载荷只含绑定字段且不含凭证（端到端）', { timeout: 60_000 }, async (t) => {
    await withSeededContext(t, async (ctx, topo) => {
      const secretForms = [topo.secrets.deployKey, topo.secrets.rootPassword, ctx.kek, ctx.env.AUTH_PEPPER ?? ''].filter(
        (form) => form !== '',
      );
      const seenNonces = new Set<string>();

      await forAll(
        (rng, run) => genE2eCase(rng, run),
        async (c) => {
          t.mock.timers.setTime(c.issueAt);
          const session = await createAliceSession(ctx, topo, c.clientIp);

          // Short-lived (§32).
          const ttl = session.expiresAt - c.issueAt;
          assert.ok(ttl > 0, '[判定] 路由签发票据的过期时间应晚于签发时间（§32）');
          assert.ok(ttl <= TICKET_TTL_LIMIT_MS, '[判定] 路由签发票据的有效期不应超过 60 秒（§32）');

          // Restricted content (§32).
          const payload = decodeTicket(session.ticket);
          assert.ok(payload, 'fixture: the route-issued ticket decodes through parseTicketPayload');
          const unexpectedKeys = Object.keys(payload).filter((key) => !ALLOWED_TICKET_PAYLOAD_KEYS.has(key));
          assert.ok(
            unexpectedKeys.length === 0,
            `[判定] 路由签发票据的载荷含白名单之外的键（§32）：${unexpectedKeys.join(', ')}`,
          );
          assert.ok(
            Object.values(payload).every((value) => typeof value === 'string' || typeof value === 'number'),
            '[判定] 路由签发票据的载荷只应包含标量绑定字段（§32）',
          );
          assert.ok(
            payload.sessionId === session.sessionId &&
              payload.userId === topo.alice.id &&
              payload.assetId === topo.prodWeb01.id &&
              payload.accountId === topo.deploy.id,
            '[判定] 路由签发票据应绑定本次会话的 session_id、user_id、asset_id、account_id（§32）',
          );
          assert.ok(payload.exp === session.expiresAt, '[判定] 票据载荷 exp 应等于响应中的 expiresAt（§32）');
          assert.ok(
            typeof payload.nonce === 'string' && UUID_PATTERN.test(payload.nonce),
            '[判定] 路由签发票据应携带随机 nonce（§32）',
          );
          assert.ok(!seenNonces.has(payload.nonce as string), '[判定] 每张路由签发票据的 nonce 应互不相同（§32）');
          seenNonces.add(payload.nonce as string);
          assert.ok(payload.ip === c.clientIp, 'observation: payload.ip carries the CF-Connecting-IP of the request');

          // No credential, KEK or ticket signing key in the ticket, its payload, the wsUrl or the response (§22, §32).
          const payloadText = JSON.stringify(payload);
          const leaked = secretForms.some(
            (form) =>
              session.ticket.includes(form) ||
              payloadText.includes(form) ||
              session.wsUrl.includes(form) ||
              session.responseText.includes(form),
          );
          assert.ok(!leaked, '[判定] 路由签发的票据、wsUrl 与会话创建响应不应包含凭证明文、KEK 或票据签名密钥');
        },
        { runs: PROPERTY_RUNS, seed: seedFromEnv() },
      );
    });
  });
});
