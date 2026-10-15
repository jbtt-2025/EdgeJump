// Supplementary verification tests for the v1-compliance-review spec.
// Topic: session gate — SEC-08 (Disabled User 无法创建 Session) and SEC-09 (Expired Authorization
// 无法创建 Session). Both are boundary slices of Property 2 (授权结果与参考模型等价).
//
// Design reference: .kiro/specs/v1-compliance-review/design.md C6.3, C6.5 (compliance-session-gate),
// C6.7, C6.8.
// - Task 8.1 (this file's first version): shared in-file scenario helpers and the [SEC-08] cases.
// - Task 8.2: the [SEC-09] cases in the "[SEC-09]" describe block below, reusing withScenario(),
//   postSession(), gateSnapshot() and assertNoSessionSideEffects(), plus the SEC-09 helpers.
//
// Rules followed here (C6.7 / C6.8):
// - The implementation is only observed through src/worker.ts (via api()), exported service functions
//   (createSession, disableUser, enableUser) and the real Durable Object classes behind the mock
//   namespaces created by createContext(). Business code is never modified.
// - Every negative assertion is preceded by a positive control in the same scenario, so a 401 / rejection
//   cannot pass vacuously because the legitimate path was already broken (D9).
// - Verdict assertions start with `[判定]`; messages never echo credential plaintext or cookie values.
// - Every scenario owns an isolated context that is cleaned up in `finally`, so no DO timer keeps the
//   test process alive.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { checkUserAssetAccountAccess, getAuthorizedAssetsForUser } from '../src/authorization/authorization-service.ts';
import { createSession } from '../src/sessions/session-service.ts';
import { disableUser, enableUser } from '../src/users/user-service.ts';
import { api, createContext, createRng, issueCookie, seedDemoTopology, seedFromEnv } from './compliance-helpers.ts';
import type { ApiResult, ComplianceContext, DemoTopology, SeededAccount, SeededAsset } from './compliance-helpers.ts';

// -------------------------------------------------------------
// In-file constants
// -------------------------------------------------------------

/** Non-active user states of AGENTS.md §5; both must be denied (§31 step 2, §60, §92-8). */
type BlockedStatus = 'disabled' | 'locked';
const BLOCKED_STATUSES: readonly BlockedStatus[] = ['disabled', 'locked'];

/** Client IP passed to the service layer; it is never used as a connection target. */
const SERVICE_CLIENT_IP = '127.0.0.1';
const SERVICE_USER_AGENT = 'compliance-session-gate';

// -------------------------------------------------------------
// Scenario lifecycle (one isolated context + §93 topology per scenario)
// -------------------------------------------------------------

interface Scenario {
  ctx: ComplianceContext;
  topo: DemoTopology;
}

function fnv1a(text: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/**
 * Creates a fresh context, seeds the §93 topology (Alice is authorized for prod-web-01 / deploy through
 * Developers -> Production/Web), runs `fn`, and always cleans up. The credential plaintext is a
 * reproducible fake value derived from EJ_COMPLIANCE_SEED (or the default seed) and `label`.
 */
async function withScenario(label: string, fn: (scenario: Scenario) => Promise<void>): Promise<void> {
  const ctx = await createContext();
  try {
    const rng = createRng((seedFromEnv() ^ fnv1a(label)) >>> 0);
    const topo = await seedDemoTopology(ctx, `EJ-SECRET-${rng.hex(16)}`);
    await fn({ ctx, topo });
  } finally {
    await ctx.cleanup();
  }
}

/** POST /api/sessions with the implementation's camelCase body fields (L19). */
async function postSession(
  ctx: ComplianceContext,
  cookie: string,
  asset: Pick<SeededAsset, 'id'>,
  account: Pick<SeededAccount, 'id'>,
): Promise<ApiResult> {
  return api(ctx, 'POST', '/api/sessions', { cookie, body: { assetId: asset.id, accountId: account.id } });
}

/** Side effects a successful session creation leaves behind for one user. */
interface GateSnapshot {
  /** ssh_sessions rows owned by the user. */
  sshSessions: number;
  /** POST /init calls received by the SSH_SESSIONS namespace (credential dispatch to the DO). */
  initCalls: number;
  /** SESSION_CREATED audit events with the user as actor. */
  sessionCreatedEvents: number;
}

async function countRows(ctx: ComplianceContext, sql: string, ...params: unknown[]): Promise<number> {
  const row = await ctx.db.prepare(sql).bind(...params).first<{ n: number }>();
  return Number(row?.n ?? 0);
}

async function gateSnapshot(ctx: ComplianceContext, userId: string): Promise<GateSnapshot> {
  return {
    sshSessions: await countRows(ctx, 'SELECT COUNT(*) AS n FROM ssh_sessions WHERE user_id = ?', userId),
    initCalls: ctx.sessions.calls.filter((call) => call.method === 'POST' && call.path === '/init').length,
    sessionCreatedEvents: await countRows(
      ctx,
      "SELECT COUNT(*) AS n FROM audit_events WHERE action = 'SESSION_CREATED' AND actor_user_id = ?",
      userId,
    ),
  };
}

/** Asserts that a denied attempt left no session row, no DO dispatch and no SESSION_CREATED event. */
function assertNoSessionSideEffects(before: GateSnapshot, after: GateSnapshot, label: string): void {
  assert.equal(after.sshSessions, before.sshSessions, `[判定] ${label}：被拒绝的请求仍写入了 ssh_sessions 记录`);
  assert.equal(after.initCalls, before.initCalls, `[判定] ${label}：被拒绝的请求仍向 SSHSessionDO 下发了 /init`);
  assert.equal(
    after.sessionCreatedEvents,
    before.sessionCreatedEvents,
    `[判定] ${label}：被拒绝的请求仍产生了 SESSION_CREATED 审计事件`,
  );
}

/**
 * Positive control: the user's current cookie can create a session for the authorized pair.
 * Not a verdict assertion — if it fails, the scenario setup is broken (test defect), not the gate.
 */
async function assertSessionCreated(
  ctx: ComplianceContext,
  cookie: string,
  asset: Pick<SeededAsset, 'id'>,
  account: Pick<SeededAccount, 'id'>,
  label: string,
): Promise<void> {
  const res = await postSession(ctx, cookie, asset, account);
  assert.equal(res.threw, false, `正向对照（${label}）：路由抛出未捕获异常`);
  assert.equal(res.status, 201, `正向对照（${label}）：被授权的 active 用户创建会话应返回 201`);
  assert.equal(typeof res.json?.sessionId, 'string', `正向对照（${label}）：201 响应缺少 sessionId`);
}

async function setUserStatus(ctx: ComplianceContext, userId: string, status: 'active' | BlockedStatus): Promise<void> {
  await ctx.db.prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?').bind(status, Date.now(), userId).run();
}

async function countUnrevokedLoginSessions(ctx: ComplianceContext, userId: string): Promise<number> {
  return countRows(ctx, 'SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id = ? AND revoked_at IS NULL', userId);
}

// -------------------------------------------------------------
// [SEC-09] helpers (task 8.2)
// -------------------------------------------------------------

/**
 * Fixed "now" for the SEC-09 boundaries (2026-10-07 09:00:00.000 UTC, the §28 example day).
 * Route-level cases enable `t.mock.timers` for Date before the scenario is seeded, so login cookies
 * (expires_at = FIXED_NOW + SESSION_TTL_MS) stay valid and Date.now() does not advance on its own.
 */
const FIXED_NOW = Date.UTC(2026, 9, 7, 9, 0, 0, 0);

interface RuleWindowPatch {
  enabled?: boolean;
  validFrom?: number | null;
  validUntil?: number | null;
}

interface RuleWindowRow {
  enabled: number;
  valid_from: number | null;
  valid_until: number | null;
}

async function readRuleWindow(ctx: ComplianceContext, ruleId: string): Promise<RuleWindowRow | null> {
  return ctx.db
    .prepare('SELECT enabled, valid_from, valid_until FROM authorization_rules WHERE id = ?')
    .bind(ruleId)
    .first<RuleWindowRow>();
}

/**
 * Fixture step (not a verdict): changes the scenario rule through PATCH /api/admin/authorizations/:id as
 * Super Admin, then reads the row back so the exact millisecond boundary is confirmed in D1.
 */
async function patchRule(ctx: ComplianceContext, topo: DemoTopology, patch: RuleWindowPatch, label: string): Promise<void> {
  const res = await api(ctx, 'PATCH', `/api/admin/authorizations/${encodeURIComponent(topo.rule.id)}`, {
    cookie: topo.admin.cookie,
    body: patch,
  });
  assert.equal(res.threw, false, `布置（${label}）：更新授权规则时路由抛出未捕获异常`);
  assert.equal(res.status, 200, `布置（${label}）：Super Admin 更新授权规则应返回 200`);

  const row = await readRuleWindow(ctx, topo.rule.id);
  assert.ok(row, `布置（${label}）：授权规则行不存在`);
  if (patch.enabled !== undefined) {
    assert.equal(row.enabled, patch.enabled ? 1 : 0, `布置（${label}）：D1 中 enabled 未按请求更新`);
  }
  if (patch.validFrom !== undefined) {
    assert.equal(row.valid_from, patch.validFrom, `布置（${label}）：D1 中 valid_from 未按请求更新`);
  }
  if (patch.validUntil !== undefined) {
    assert.equal(row.valid_until, patch.validUntil, `布置（${label}）：D1 中 valid_until 未按请求更新`);
  }
}

/** Account ids listed for `asset` by GET /api/assets; null when the asset is not listed at all. */
async function visibleAccountIds(
  ctx: ComplianceContext,
  cookie: string,
  asset: Pick<SeededAsset, 'id'>,
): Promise<string[] | null> {
  const res = await api(ctx, 'GET', '/api/assets', { cookie });
  assert.equal(res.threw, false, 'GET /api/assets 路由抛出未捕获异常');
  assert.equal(res.status, 200, 'GET /api/assets 应返回 200');
  assert.ok(Array.isArray(res.json), 'GET /api/assets 应返回数组');
  const entries = res.json as Array<{ id?: unknown; accounts?: Array<{ id?: unknown }> }>;
  const entry = entries.find((item) => item?.id === asset.id);
  if (!entry) return null;
  return (entry.accounts ?? []).map((account) => String(account.id));
}

async function countSessionDenied(ctx: ComplianceContext, userId: string, assetId: string): Promise<number> {
  return countRows(
    ctx,
    "SELECT COUNT(*) AS n FROM audit_events WHERE action = 'SESSION_DENIED' AND actor_user_id = ? AND resource_id = ? AND result = 'denied'",
    userId,
    assetId,
  );
}

/**
 * Alice can create a session for prod-web-01 / deploy right now and sees it in GET /api/assets.
 * `kind = 'control'` marks a positive control (failure = broken setup); `kind = 'verdict'` marks the
 * allowed side of a boundary that is itself under test (messages start with `[判定]`).
 */
async function assertAuthorizedNow(
  ctx: ComplianceContext,
  topo: DemoTopology,
  label: string,
  kind: 'control' | 'verdict',
): Promise<void> {
  const tag = kind === 'verdict' ? '[判定] ' : '正向对照：';
  const res = await postSession(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy);
  assert.equal(res.threw, false, `${tag}${label}：路由抛出未捕获异常`);
  assert.equal(res.status, 201, `${tag}${label}：在有效授权下创建会话应返回 201`);
  assert.equal(typeof res.json?.sessionId, 'string', `${tag}${label}：201 响应缺少 sessionId`);

  const visible = await visibleAccountIds(ctx, topo.alice.cookie, topo.prodWeb01);
  assert.ok(
    visible !== null && visible.includes(topo.deploy.id),
    `${tag}${label}：GET /api/assets 应列出 prod-web-01 及其 deploy 账号`,
  );
}

/**
 * Verdict: Alice's POST /api/sessions is denied with 403, leaves no session row / DO dispatch /
 * SESSION_CREATED, writes exactly one SESSION_DENIED event, and the asset is hidden from both
 * GET /api/assets and GET /api/assets/:id/accounts.
 */
async function assertDeniedNow(ctx: ComplianceContext, topo: DemoTopology, label: string): Promise<void> {
  const before = await gateSnapshot(ctx, topo.alice.id);
  const deniedBefore = await countSessionDenied(ctx, topo.alice.id, topo.prodWeb01.id);
  const res = await postSession(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy);
  const after = await gateSnapshot(ctx, topo.alice.id);

  assert.equal(res.threw, false, `[判定] ${label}：路由抛出未捕获异常`);
  assert.equal(res.status, 403, `[判定] ${label}：创建会话未返回 403`);
  assertNoSessionSideEffects(before, after, label);
  assert.equal(
    await countSessionDenied(ctx, topo.alice.id, topo.prodWeb01.id),
    deniedBefore + 1,
    `[判定] ${label}：拒绝未写入一条 SESSION_DENIED 审计事件`,
  );

  const visible = await visibleAccountIds(ctx, topo.alice.cookie, topo.prodWeb01);
  assert.equal(visible, null, `[判定] ${label}：GET /api/assets 仍列出 prod-web-01`);
  const accounts = await api(ctx, 'GET', `/api/assets/${encodeURIComponent(topo.prodWeb01.id)}/accounts`, {
    cookie: topo.alice.cookie,
  });
  assert.equal(accounts.status, 200, 'GET /api/assets/:id/accounts 应返回 200');
  assert.deepEqual(accounts.json, [], `[判定] ${label}：GET /api/assets/:id/accounts 仍返回账号`);
}

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

describe('compliance-session-gate', () => {
  // Boundary slice of Property 2 (授权结果与参考模型等价): user status is the only variable; the
  // authorization rule Developers -> Production/Web -> deploy -> connect stays valid throughout.
  describe('[SEC-08] Disabled User 无法创建 Session', () => {
    it('[SEC-08] 正向对照：active 用户以原 Cookie 创建会话得到 201 并下发 /init', async () => {
      await withScenario('SEC-08 positive control', async ({ ctx, topo }) => {
        const before = await gateSnapshot(ctx, topo.alice.id);
        await assertSessionCreated(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy, 'Alice active');
        const after = await gateSnapshot(ctx, topo.alice.id);
        assert.equal(after.sshSessions, before.sshSessions + 1, '正向对照：201 后应新增一条 ssh_sessions 记录');
        assert.equal(after.initCalls, before.initCalls + 1, '正向对照：201 后 SSHSessionDO 应收到一次 /init');
        assert.equal(after.sessionCreatedEvents, before.sessionCreatedEvents + 1, '正向对照：201 后应产生 SESSION_CREATED');
      });
    });

    for (const status of BLOCKED_STATUSES) {
      it(`[SEC-08] 用户状态改为 ${status} 后原 Cookie 调用 POST /api/sessions 返回 401`, async () => {
        await withScenario(`SEC-08 route ${status}`, async ({ ctx, topo }) => {
          await assertSessionCreated(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy, 'Alice active');

          await setUserStatus(ctx, topo.alice.id, status);
          const before = await gateSnapshot(ctx, topo.alice.id);
          const res = await postSession(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy);
          const after = await gateSnapshot(ctx, topo.alice.id);

          assert.equal(res.threw, false, `[判定] ${status} 用户请求导致路由抛出未捕获异常`);
          assert.equal(res.status, 401, `[判定] ${status} 用户以原 Cookie 创建会话未返回 401`);
          assertNoSessionSideEffects(before, after, `${status} 用户`);

          // Restoring the status restores access with the same cookie: the 401 above came from the
          // status check in validateSession, not from an unrelated failure of the cookie.
          await setUserStatus(ctx, topo.alice.id, 'active');
          await assertSessionCreated(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy, `Alice 由 ${status} 恢复为 active`);
        });
      });
    }

    it('[SEC-08] 经 disableUser 禁用后登录会话被撤销，原 Cookie 调用 POST /api/sessions 返回 401', async () => {
      await withScenario('SEC-08 disableUser', async ({ ctx, topo }) => {
        await assertSessionCreated(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy, 'Alice active');
        assert.ok((await countUnrevokedLoginSessions(ctx, topo.alice.id)) > 0, '正向对照：Alice 应持有未撤销的登录会话');

        await disableUser(topo.alice.id, topo.admin.id, ctx.env, SERVICE_CLIENT_IP);

        assert.equal(
          await countUnrevokedLoginSessions(ctx, topo.alice.id),
          0,
          '[判定] disableUser 后 auth_sessions 中仍有未撤销的登录会话',
        );

        const before = await gateSnapshot(ctx, topo.alice.id);
        const res = await postSession(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy);
        const after = await gateSnapshot(ctx, topo.alice.id);
        assert.equal(res.threw, false, '[判定] 禁用用户请求导致路由抛出未捕获异常');
        assert.equal(res.status, 401, '[判定] disableUser 后原 Cookie 创建会话未返回 401');
        assertNoSessionSideEffects(before, after, 'disableUser 后');

        // Re-enabling must not revive the revoked login session (revocation, not just a status gate) ...
        await enableUser(topo.alice.id, topo.admin.id, ctx.db, SERVICE_CLIENT_IP);
        const revived = await postSession(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy);
        assert.equal(revived.status, 401, '[判定] 重新启用用户后被撤销的原 Cookie 恢复了会话创建能力');

        // ... while a new login session of the re-enabled user works (positive control for the 401 above).
        const freshCookie = await issueCookie(ctx.db, topo.alice.id);
        await assertSessionCreated(ctx, freshCookie, topo.prodWeb01, topo.deploy, 'Alice 重新启用后的新登录会话');
      });
    });

    it('[SEC-08] 管理员经 POST /api/admin/users/:id/disable 禁用后原 Cookie 调用 POST /api/sessions 返回 401', async () => {
      await withScenario('SEC-08 admin route', async ({ ctx, topo }) => {
        await assertSessionCreated(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy, 'Alice active');

        const disabled = await api(ctx, 'POST', `/api/admin/users/${encodeURIComponent(topo.alice.id)}/disable`, {
          cookie: topo.admin.cookie,
          body: {},
        });
        assert.equal(disabled.status, 200, '正向对照：Super Admin 禁用用户应返回 200');

        const status = await ctx.db.prepare('SELECT status FROM users WHERE id = ?').bind(topo.alice.id).first<{ status: string }>();
        assert.equal(status?.status, 'disabled', '[判定] 禁用路由返回 200 但用户状态不是 disabled');
        assert.equal(
          await countUnrevokedLoginSessions(ctx, topo.alice.id),
          0,
          '[判定] 禁用路由执行后 auth_sessions 中仍有未撤销的登录会话',
        );

        const before = await gateSnapshot(ctx, topo.alice.id);
        const res = await postSession(ctx, topo.alice.cookie, topo.prodWeb01, topo.deploy);
        const after = await gateSnapshot(ctx, topo.alice.id);
        assert.equal(res.status, 401, '[判定] 经管理路由禁用后原 Cookie 创建会话未返回 401');
        assertNoSessionSideEffects(before, after, '管理路由禁用后');
      });
    });

    for (const status of BLOCKED_STATUSES) {
      it(`[SEC-08] 服务层 createSession 对 ${status} 用户抛错且无副作用`, async () => {
        await withScenario(`SEC-08 service ${status}`, async ({ ctx, topo }) => {
          // Positive control at the same layer: the active user gets a ticket.
          const ok = await createSession(
            topo.alice.id,
            topo.prodWeb01.id,
            topo.deploy.id,
            SERVICE_CLIENT_IP,
            SERVICE_USER_AGENT,
            ctx.env,
          );
          assert.equal(typeof ok.sessionId, 'string', '正向对照：active 用户的 createSession 应返回 sessionId');
          assert.equal(typeof ok.ticket, 'string', '正向对照：active 用户的 createSession 应返回票据');

          await setUserStatus(ctx, topo.alice.id, status);
          const before = await gateSnapshot(ctx, topo.alice.id);
          await assert.rejects(
            createSession(topo.alice.id, topo.prodWeb01.id, topo.deploy.id, SERVICE_CLIENT_IP, SERVICE_USER_AGENT, ctx.env),
            (err: unknown) => err instanceof Error,
            `[判定] createSession 未拒绝 ${status} 用户`,
          );
          const after = await gateSnapshot(ctx, topo.alice.id);
          assertNoSessionSideEffects(before, after, `服务层 ${status} 用户`);
        });
      });
    }
  });

  // Boundary slice of Property 2 (授权结果与参考模型等价): the rule window / enabled flag / existence of
  // Developers -> Production/Web -> deploy -> connect is the only variable; Alice stays active.
  // Reference semantics (design C6.5): closed interval valid_from <= now <= valid_until, null = unbounded.
  // Route-level cases set the window through PATCH /api/admin/authorizations/:id (exercising the admin
  // route) and read the row back to confirm the exact millisecond value in D1.
  describe('[SEC-09] Expired Authorization 无法创建 Session', () => {
    it('[SEC-09] 固定 now：valid_until = now - 1 时 POST /api/sessions 返回 403 并写 SESSION_DENIED，GET /api/assets 隐藏资产', async (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
      await withScenario('SEC-09 valid_until past', async ({ ctx, topo }) => {
        assert.equal(Date.now(), FIXED_NOW, '布置：Date.now() 应被固定为 FIXED_NOW');
        await assertAuthorizedNow(ctx, topo, '规则无有效期限制', 'control');

        await patchRule(ctx, topo, { validUntil: FIXED_NOW - 1 }, 'valid_until = now - 1');
        await assertDeniedNow(ctx, topo, 'valid_until = now - 1');
      });
    });

    it('[SEC-09] 固定 now：valid_until = now（闭区间上界）时允许创建会话且资产可见，时钟前进 1 ms 后拒绝', async (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
      await withScenario('SEC-09 valid_until now', async ({ ctx, topo }) => {
        await patchRule(ctx, topo, { validUntil: FIXED_NOW }, 'valid_until = now');
        await assertAuthorizedNow(ctx, topo, 'valid_until = now', 'verdict');

        // Same rule, clock moved past the upper bound by 1 ms: the authorization has just expired.
        t.mock.timers.setTime(FIXED_NOW + 1);
        assert.equal(Date.now(), FIXED_NOW + 1, '布置：Date.now() 应前进到 FIXED_NOW + 1');
        await assertDeniedNow(ctx, topo, 'now = valid_until + 1');
      });
    });

    it('[SEC-09] 固定 now：valid_from = now + 1 时拒绝创建会话并隐藏资产，valid_from = now 与时钟到达后允许', async (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
      await withScenario('SEC-09 valid_from future', async ({ ctx, topo }) => {
        // Positive control at the closed lower bound.
        await patchRule(ctx, topo, { validFrom: FIXED_NOW }, 'valid_from = now');
        await assertAuthorizedNow(ctx, topo, 'valid_from = now', 'control');

        await patchRule(ctx, topo, { validFrom: FIXED_NOW + 1 }, 'valid_from = now + 1');
        await assertDeniedNow(ctx, topo, 'valid_from = now + 1');

        // Once the clock reaches valid_from the same rule takes effect: the 403 above came from the window.
        t.mock.timers.setTime(FIXED_NOW + 1);
        await assertAuthorizedNow(ctx, topo, '时钟到达 valid_from', 'verdict');
      });
    });

    it('[SEC-09] 规则 enabled = 0 时拒绝创建会话并隐藏资产，重新启用后恢复', async (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
      await withScenario('SEC-09 rule disabled', async ({ ctx, topo }) => {
        await assertAuthorizedNow(ctx, topo, '规则启用', 'control');

        await patchRule(ctx, topo, { enabled: false }, 'enabled = 0');
        await assertDeniedNow(ctx, topo, '规则 enabled = 0');

        await patchRule(ctx, topo, { enabled: true }, 'enabled = 1');
        await assertAuthorizedNow(ctx, topo, '规则重新启用', 'control');
      });
    });

    it('[SEC-09] 删除授权规则后（§61）拒绝创建会话并隐藏资产', async (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
      await withScenario('SEC-09 rule deleted', async ({ ctx, topo }) => {
        await assertAuthorizedNow(ctx, topo, '规则存在', 'control');

        const deleted = await api(ctx, 'DELETE', `/api/admin/authorizations/${encodeURIComponent(topo.rule.id)}`, {
          cookie: topo.admin.cookie,
        });
        assert.equal(deleted.threw, false, '布置：删除授权规则时路由抛出未捕获异常');
        assert.equal(deleted.status, 200, '布置：Super Admin 删除授权规则应返回 200');
        assert.equal(await readRuleWindow(ctx, topo.rule.id), null, '布置：删除路由返回 200 但授权规则行仍存在');

        await assertDeniedNow(ctx, topo, '授权规则删除后');
      });
    });

    it('[SEC-09] 服务层 checkUserAssetAccountAccess 与 getAuthorizedAssetsForUser 在有效期闭区间边界 ±1 ms 上判定一致', async () => {
      await withScenario('SEC-09 service boundaries', async ({ ctx, topo }) => {
        // Service-level observation with an explicit `now` argument; the window is written through SQL
        // because no route is involved here.
        const from = FIXED_NOW;
        const until = FIXED_NOW + 60_000;
        await ctx.db
          .prepare('UPDATE authorization_rules SET valid_from = ?, valid_until = ? WHERE id = ?')
          .bind(from, until, topo.rule.id)
          .run();

        const probes: Array<{ now: number; expected: boolean; label: string }> = [
          { now: from - 1, expected: false, label: 'now = valid_from - 1' },
          { now: from, expected: true, label: 'now = valid_from' },
          { now: until, expected: true, label: 'now = valid_until' },
          { now: until + 1, expected: false, label: 'now = valid_until + 1' },
        ];

        for (const probe of probes) {
          const access = await checkUserAssetAccountAccess(
            topo.alice.id,
            topo.prodWeb01.id,
            topo.deploy.id,
            'connect',
            ctx.db,
            probe.now,
          );
          assert.equal(access.authorized, probe.expected, `[判定] checkUserAssetAccountAccess 在 ${probe.label} 上的判定错误`);
          if (probe.expected) {
            assert.equal(access.matchedRuleId, topo.rule.id, `[判定] ${probe.label}：允许结果未指向场景授权规则`);
          }

          const visible = await getAuthorizedAssetsForUser(topo.alice.id, ctx.db, probe.now);
          const entry = visible.find((asset) => asset.id === topo.prodWeb01.id);
          const listed = entry !== undefined && entry.accounts.some((account) => account.id === topo.deploy.id);
          assert.equal(listed, probe.expected, `[判定] getAuthorizedAssetsForUser 在 ${probe.label} 上的可见性错误`);
        }
      });
    });
  });
});
