// Supplementary verification tests for the v1-compliance-review spec: Origin / CSRF (SEC-13, SEC-20).
//
// Design reference: .kiro/specs/v1-compliance-review/design.md C6.1 (L10), C6.3 (file plan),
// C6.5 (compliance-origin-csrf), C6.6 (route list), C6.7 (isolation), C6.8 (todo rules), Properties 8 and 9;
// tasks.md 11.1 (Property 8) and 11.2 (Property 9, same-origin mutation without a CSRF token).
//
// Observation surface (read-only, business code is never modified):
// - Every request enters through the default export of src/worker.ts via api() from ./compliance-helpers.ts,
//   so the HTTPS gate, /api/health and the CSRF check in handleApiRequest (src/api/router.ts) all apply.
// - Mutation routes: handleApiRequest calls validateCsrfOrigin() (src/http-security.ts) before routing and
//   before authentication, so routes listed in AGENTS.md §66–§73 that the router does not implement are
//   exercised as well (a cross-origin request must be rejected before it can reach the 404 fallback).
// - WebSocket routes (/api/sessions/:id/ws, /api/admin/sessions/:id/monitor) are GET requests, which
//   validateCsrfOrigin() lets through; they rely on hasValidWebSocketOrigin() inside the route branch.
// - D1 invariance is checked with one compound query per snapshot: SQLite total_changes() (counts every
//   INSERT/UPDATE/DELETE on the single node:sqlite connection used by tests/mock-d1.ts, so UPDATEs from
//   PATCH/PUT are caught too) plus COUNT(*) of every table. A rejected cross-origin request must leave both
//   unchanged; no table is excluded because the CSRF rejection happens before any D1 access (it does not
//   even write an audit row). total_changes() is a property of the test database connection, not of real D1.
//
// Property 9 (end of file) reuses withFixture(), createD1Probe() / diffSnapshots() and randomLabel(), and has
// its own route table (TOKENLESS_ROUTES) so that every iteration sends a fresh, valid body.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import type { ApiResult, ComplianceContext, DemoTopology, Rng } from './compliance-helpers.ts';
import { bytesToHex } from '../src/crypto/utils.ts';
import {
  PROPERTY_RUNS,
  TEST_BOOTSTRAP_TOKEN,
  TEST_ORIGIN,
  api,
  createContext,
  flushAsync,
  forAll,
  seedDemoTopology,
  seedFromEnv,
} from './compliance-helpers.ts';

// -------------------------------------------------------------
// Constants
// -------------------------------------------------------------

/** Error body of handleApiRequest when validateCsrfOrigin() fails (src/api/router.ts, CSRF block). */
const CSRF_REJECTION_ERROR = 'CSRF protection: Invalid Origin or cross-site request';

/** Error body of the /ws and /monitor branches when hasValidWebSocketOrigin() fails (src/api/router.ts). */
const WS_ORIGIN_ERROR = 'Invalid WebSocket origin';

/**
 * Errors produced by the gates that run up to and including the WebSocket Origin check (authentication,
 * permission, Upgrade header, Origin). A same-origin positive control must get past all of them, which proves
 * the negative assertions are not satisfied by an earlier, unrelated rejection (D9).
 */
const WS_GATE_ERRORS: readonly string[] = [
  'Authentication required',
  'Invalid or expired session',
  'Permission denied',
  'WebSocket upgrade required',
  WS_ORIGIN_ERROR,
];

const TEST_HOST = new URL(TEST_ORIGIN).hostname;

/** Fixed, obviously-fake password used in request bodies (not a real secret). */
const TEST_PASSWORD = 'Compliance-Test-Passw0rd!';

/** Random lowercase hex of `bytes` bytes (fixture names and test-only secrets). */
function randomHex(bytes: number): string {
  return bytesToHex(new Uint8Array(randomBytes(bytes)));
}

// -------------------------------------------------------------
// Fixture
// -------------------------------------------------------------

interface Fixture {
  ctx: ComplianceContext;
  topo: DemoTopology;
  /** Alice's live session created through POST /api/sessions (201) during fixture setup. */
  session: { sessionId: string; ticket: string; wsUrl: string };
  /**
   * Credential created through POST /api/admin/credentials (201) that no account references, so an accepted
   * DELETE would really remove a row (the seeded credentials are referenced by accounts and cannot be deleted).
   */
  spareCredentialId: string;
  /** Random per-fixture suffix for names and test secrets. */
  nonce: string;
  probe: D1Probe;
}

/**
 * Fresh context + §93 topology + one session created by Alice through the route. Always cleans up (terminates
 * every SSHSessionDO, restores fetch / socket connector / console).
 */
async function withFixture(fn: (fx: Fixture) => Promise<void>): Promise<void> {
  const ctx = await createContext();
  try {
    const nonce = randomHex(6);
    const topo = await seedDemoTopology(ctx, `EJ-SECRET-${randomHex(16)}`);
    const created = await api(ctx, 'POST', '/api/sessions', {
      cookie: topo.alice.cookie,
      body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id },
    });
    assert.equal(created.status, 201, 'fixture: Alice POST /api/sessions should return 201');
    const { sessionId, ticket, wsUrl } = created.json as { sessionId: string; ticket: string; wsUrl: string };
    assert.ok(typeof sessionId === 'string' && sessionId !== '', 'fixture: POST /api/sessions should return sessionId');
    assert.ok(typeof ticket === 'string' && ticket !== '', 'fixture: POST /api/sessions should return ticket');
    assert.ok(typeof wsUrl === 'string' && wsUrl !== '', 'fixture: POST /api/sessions should return wsUrl');
    const spare = await api(ctx, 'POST', '/api/admin/credentials', {
      cookie: topo.admin.cookie,
      body: { name: `spare-cred-${nonce}`, type: 'password', secret: `EJ-SECRET-${nonce}-spare` },
    });
    assert.equal(spare.status, 201, 'fixture: admin POST /api/admin/credentials should return 201');
    const spareCredentialId = (spare.json as { id?: unknown } | null)?.id;
    assert.ok(typeof spareCredentialId === 'string' && spareCredentialId !== '', 'fixture: credential id expected');
    await flushAsync();
    const probe = await createD1Probe(ctx.db);
    await fn({ ctx, topo, session: { sessionId, ticket, wsUrl }, spareCredentialId, nonce, probe });
  } finally {
    await ctx.cleanup();
  }
}

// -------------------------------------------------------------
// D1 snapshot probe
// -------------------------------------------------------------

interface D1Snapshot {
  /** SQLite total_changes() of the test connection: rows inserted, updated or deleted so far. */
  totalChanges: number;
  rowCounts: Record<string, number>;
}

interface D1Probe {
  tables: string[];
  snapshot(): Promise<D1Snapshot>;
}

function quoteIdentifier(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

/** Lists every user table once and prepares a single compound snapshot query. */
async function createD1Probe(db: D1Database): Promise<D1Probe> {
  const { results } = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all<{ name: string }>();
  const tables = (results ?? []).map((row) => row.name);
  assert.ok(tables.length > 0, 'fixture: the test database should contain tables');
  const columns = tables.map((table, i) => `(SELECT COUNT(*) FROM ${quoteIdentifier(table)}) AS c${i}`);
  const sql = `SELECT total_changes() AS total_changes, ${columns.join(', ')}`;

  return {
    tables,
    async snapshot(): Promise<D1Snapshot> {
      const row = await db.prepare(sql).first<Record<string, number | bigint>>();
      assert.ok(row, 'fixture: snapshot query should return one row');
      const rowCounts: Record<string, number> = {};
      tables.forEach((table, i) => {
        rowCounts[table] = Number(row[`c${i}`]);
      });
      return { totalChanges: Number(row.total_changes), rowCounts };
    },
  };
}

/** Human-readable list of differences (table names and counts only, never cell values). */
function diffSnapshots(before: D1Snapshot, after: D1Snapshot): string[] {
  const changes: string[] = [];
  if (before.totalChanges !== after.totalChanges) {
    changes.push(`total_changes ${before.totalChanges}->${after.totalChanges}`);
  }
  for (const table of Object.keys(before.rowCounts)) {
    if (before.rowCounts[table] !== after.rowCounts[table]) {
      changes.push(`${table} ${before.rowCounts[table]}->${after.rowCounts[table]}`);
    }
  }
  return changes;
}

// -------------------------------------------------------------
// Origin variants
// -------------------------------------------------------------

/** How the Origin / Sec-Fetch-Site headers of a request are set. */
interface OriginSpec {
  /** Origin header value; null omits the header. */
  origin: string | null;
  /** Sec-Fetch-Site header value; null omits the header. */
  secFetchSite: string | null;
}

/** What a browser sends for a same-origin request from the EdgeJump frontend. */
const SAME_ORIGIN_REQUEST: OriginSpec = { origin: TEST_ORIGIN, secFetchSite: 'same-origin' };

type OriginAttackKind =
  | 'other-domain'
  | 'subdomain'
  | 'http-downgrade'
  | 'other-port'
  | 'null-origin'
  | 'missing-origin-cross-site'
  | 'missing-origin';

/** Kinds are assigned round-robin by run index so that 100 runs cover every kind at least 14 times. */
const ORIGIN_ATTACK_KINDS: readonly OriginAttackKind[] = [
  'other-domain',
  'subdomain',
  'http-downgrade',
  'other-port',
  'null-origin',
  'missing-origin-cross-site',
  'missing-origin',
];

interface OriginAttack extends OriginSpec {
  kind: OriginAttackKind;
  /** Non-secret description used in assertion messages. */
  label: string;
}

/** DNS label starting with a letter, e.g. "k3fa9". */
function randomLabel(rng: Rng): string {
  return rng.pick('abcdefghijklmnopqrstuvwxyz'.split('')) + rng.hex(rng.int(1, 4));
}

/** Sec-Fetch-Site sent alongside a present (malicious) Origin; includes a forged "same-origin". */
function randomFetchSite(rng: Rng): string | null {
  return rng.pick([null, 'cross-site', 'same-site', 'same-origin'] as const);
}

/**
 * Generates an Origin that differs from TEST_ORIGIN: another domain (including suffix / prefix look-alikes),
 * a subdomain, an http downgrade, another port, the opaque "null" origin, or no Origin at all (with and without
 * `Sec-Fetch-Site: cross-site`).
 */
function genOriginAttack(rng: Rng, run: number): OriginAttack {
  const kind = ORIGIN_ATTACK_KINDS[run % ORIGIN_ATTACK_KINDS.length];
  let origin: string | null;
  let secFetchSite: string | null;

  switch (kind) {
    case 'other-domain': {
      const label = randomLabel(rng);
      origin = rng.pick([
        `https://${label}.example`,
        `https://${TEST_HOST}.${label}.example`,
        `https://${label}${TEST_HOST}`,
        `https://${label}-${TEST_HOST.replace(/\./g, '-')}.invalid`,
      ]);
      secFetchSite = randomFetchSite(rng);
      break;
    }
    case 'subdomain': {
      origin = rng.bool()
        ? `https://${randomLabel(rng)}.${TEST_HOST}`
        : `https://${randomLabel(rng)}.${randomLabel(rng)}.${TEST_HOST}`;
      secFetchSite = randomFetchSite(rng);
      break;
    }
    case 'http-downgrade': {
      origin = rng.pick([`http://${TEST_HOST}`, `http://${TEST_HOST}:80`, `http://${TEST_HOST}:443`]);
      secFetchSite = randomFetchSite(rng);
      break;
    }
    case 'other-port': {
      let port = rng.int(1, 65535);
      if (port === 443) port = 8443; // :443 is the default https port and would normalise to TEST_ORIGIN
      origin = `https://${TEST_HOST}:${port}`;
      secFetchSite = randomFetchSite(rng);
      break;
    }
    case 'null-origin': {
      origin = 'null';
      secFetchSite = rng.pick([null, 'cross-site'] as const);
      break;
    }
    case 'missing-origin-cross-site': {
      origin = null;
      secFetchSite = 'cross-site';
      break;
    }
    case 'missing-origin': {
      origin = null;
      secFetchSite = null;
      break;
    }
  }

  // Generator sanity (test defect, not a verdict): every attack origin must really be cross-origin.
  if (origin !== null && origin !== 'null') {
    assert.notEqual(new URL(origin).origin, TEST_ORIGIN, `generator: ${kind} produced a same-origin value`);
  }

  const label = `${kind}: Origin=${origin === null ? '<none>' : origin}, Sec-Fetch-Site=${secFetchSite ?? '<none>'}`;
  return { kind, origin, secFetchSite, label };
}

// -------------------------------------------------------------
// Mutation route table (design C6.6 + AGENTS.md §66–§73)
// -------------------------------------------------------------

type Actor = 'anonymous' | 'admin' | 'alice';

interface MutationRoute {
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Path template as written in design C6.6 / AGENTS.md. */
  template: string;
  /** Where the route is listed. */
  listedIn: string;
  /** false: listed in AGENTS.md §66–§73 but absent from src/api/router.ts (L18). */
  implemented: boolean;
  /** Whose login cookie is attached. Admin is Super Admin, so a 403 cannot come from a permission check. */
  actor: Actor;
  /** Concrete path and a realistic body that would mutate D1 if the request were accepted. */
  build(fx: Fixture): { path: string; body?: unknown };
}

function routeLabel(route: MutationRoute): string {
  return `${route.method} ${route.template}${route.implemented ? '' : '（未实现路由）'}`;
}

const id = (value: string): string => encodeURIComponent(value);

const MUTATION_ROUTES: readonly MutationRoute[] = [
  // --- Public (C6.6; §9, §67) ---
  {
    method: 'POST', template: '/api/auth/bootstrap', listedIn: 'C6.6 / §9', implemented: true, actor: 'anonymous',
    build: () => ({
      path: '/api/auth/bootstrap',
      body: { bootstrapToken: TEST_BOOTSTRAP_TOKEN, username: 'second-admin', password: TEST_PASSWORD },
    }),
  },
  {
    method: 'POST', template: '/api/auth/login', listedIn: 'C6.6 / §67', implemented: true, actor: 'anonymous',
    build: (fx) => ({ path: '/api/auth/login', body: { username: `nobody-${fx.nonce}`, password: TEST_PASSWORD } }),
  },
  {
    method: 'POST', template: '/api/auth/mfa', listedIn: '§67', implemented: false, actor: 'anonymous',
    build: (fx) => ({ path: '/api/auth/mfa', body: { userId: fx.topo.alice.id, totpCode: '000000' } }),
  },
  {
    method: 'POST', template: '/api/auth/logout', listedIn: 'C6.6 / §67', implemented: true, actor: 'admin',
    build: () => ({ path: '/api/auth/logout' }),
  },

  // --- User (C6.6; §69) ---
  {
    method: 'POST', template: '/api/sessions', listedIn: 'C6.6 / §69', implemented: true, actor: 'alice',
    build: (fx) => ({ path: '/api/sessions', body: { assetId: fx.topo.prodWeb01.id, accountId: fx.topo.deploy.id } }),
  },
  {
    method: 'POST', template: '/api/sessions/:id/resume-ticket', listedIn: '§69', implemented: false, actor: 'alice',
    build: (fx) => ({ path: `/api/sessions/${id(fx.session.sessionId)}/resume-ticket` }),
  },
  {
    method: 'POST', template: '/api/sessions/:id/disconnect', listedIn: 'C6.6 / §69', implemented: true, actor: 'alice',
    build: (fx) => ({ path: `/api/sessions/${id(fx.session.sessionId)}/disconnect` }),
  },

  // --- Admin users (C6.6; §70) ---
  {
    method: 'POST', template: '/api/admin/users', listedIn: 'C6.6 / §70', implemented: true, actor: 'admin',
    build: (fx) => ({
      path: '/api/admin/users',
      body: { username: `carol-${fx.nonce}`, password: TEST_PASSWORD, displayName: 'Carol' },
    }),
  },
  {
    method: 'PATCH', template: '/api/admin/users/:id', listedIn: 'C6.6 / §70', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/users/${id(fx.topo.bob.id)}`, body: { displayName: 'Bob (updated)' } }),
  },
  {
    method: 'POST', template: '/api/admin/users/:id/disable', listedIn: 'C6.6 / §70', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/users/${id(fx.topo.bob.id)}/disable` }),
  },
  {
    method: 'POST', template: '/api/admin/users/:id/enable', listedIn: 'C6.6 / §70', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/users/${id(fx.topo.bob.id)}/enable` }),
  },
  {
    method: 'POST', template: '/api/admin/users/:id/reset-password', listedIn: 'C6.6 / §70', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/users/${id(fx.topo.bob.id)}/reset-password`, body: { password: TEST_PASSWORD } }),
  },

  // --- Admin groups (C6.6; §66) ---
  {
    method: 'POST', template: '/api/admin/groups', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({ path: '/api/admin/groups', body: { name: `Compliance-${fx.nonce}` } }),
  },
  {
    method: 'PATCH', template: '/api/admin/groups/:id', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/groups/${id(fx.topo.developers.id)}`, body: { name: 'Developers-Renamed' } }),
  },
  {
    method: 'DELETE', template: '/api/admin/groups/:id', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/groups/${id(fx.topo.developers.id)}` }),
  },

  // --- Admin assets, accounts, asset groups (C6.6; §66) ---
  {
    method: 'POST', template: '/api/admin/assets', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({
      path: '/api/admin/assets',
      body: { name: `compliance-${fx.nonce}`, hostname: '9.9.9.9', port: 22, platform: 'linux', environment: 'production' },
    }),
  },
  {
    method: 'PATCH', template: '/api/admin/assets/:id', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/assets/${id(fx.topo.prodWeb01.id)}`, body: { description: 'updated by compliance test' } }),
  },
  {
    method: 'DELETE', template: '/api/admin/assets/:id', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/assets/${id(fx.topo.prodDb01.id)}` }),
  },
  {
    method: 'POST', template: '/api/admin/assets/:id/accounts', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({
      path: `/api/admin/assets/${id(fx.topo.prodWeb01.id)}/accounts`,
      body: { username: 'ops', credentialId: fx.topo.rootPassword.id },
    }),
  },
  {
    method: 'POST', template: '/api/admin/asset-groups', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: (fx) => ({ path: '/api/admin/asset-groups', body: { name: `Staging-${fx.nonce}`, parentId: null } }),
  },

  // --- Admin credentials (C6.6; §71) ---
  {
    method: 'POST', template: '/api/admin/credentials', listedIn: 'C6.6 / §71', implemented: true, actor: 'admin',
    build: (fx) => ({
      path: '/api/admin/credentials',
      body: { name: `compliance-cred-${fx.nonce}`, type: 'password', secret: `EJ-SECRET-${fx.nonce}-new` },
    }),
  },
  {
    method: 'PUT', template: '/api/admin/credentials/:id', listedIn: 'C6.6 / §71', implemented: true, actor: 'admin',
    build: (fx) => ({
      path: `/api/admin/credentials/${id(fx.topo.deployKey.id)}`,
      body: { secret: `EJ-SECRET-${fx.nonce}-replaced` },
    }),
  },
  {
    method: 'DELETE', template: '/api/admin/credentials/:id', listedIn: 'C6.6 / §71', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/credentials/${id(fx.spareCredentialId)}` }),
  },

  // --- Admin authorization rules (C6.6; §72) ---
  {
    method: 'POST', template: '/api/admin/authorizations', listedIn: 'C6.6 / §72', implemented: true, actor: 'admin',
    build: (fx) => ({
      path: '/api/admin/authorizations',
      body: {
        name: `compliance-rule-${fx.nonce}`,
        userIds: [fx.topo.bob.id],
        assetIds: [fx.topo.prodDb01.id],
        accountIds: [fx.topo.dba.id],
        actions: ['connect'],
      },
    }),
  },
  {
    method: 'PATCH', template: '/api/admin/authorizations/:id', listedIn: 'C6.6 / §72', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/authorizations/${id(fx.topo.rule.id)}`, body: { enabled: false } }),
  },
  {
    method: 'DELETE', template: '/api/admin/authorizations/:id', listedIn: 'C6.6 / §72', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/authorizations/${id(fx.topo.rule.id)}` }),
  },

  // --- Admin sessions, host keys, settings, recordings (C6.6; §73) ---
  {
    method: 'POST', template: '/api/admin/sessions/:id/terminate', listedIn: 'C6.6 / §73', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/sessions/${id(fx.session.sessionId)}/terminate` }),
  },
  {
    method: 'POST', template: '/api/admin/assets/:id/host-key/reset', listedIn: 'C6.6', implemented: true, actor: 'admin',
    build: (fx) => ({ path: `/api/admin/assets/${id(fx.topo.prodWeb01.id)}/host-key/reset` }),
  },
  {
    method: 'PATCH', template: '/api/admin/settings', listedIn: 'C6.6 / §66', implemented: true, actor: 'admin',
    build: () => ({ path: '/api/admin/settings', body: { key: 'session_idle_timeout', value: '900' } }),
  },
  {
    method: 'POST', template: '/api/admin/recordings/cleanup', listedIn: 'C6.6', implemented: true, actor: 'admin',
    build: () => ({ path: '/api/admin/recordings/cleanup' }),
  },
];

function actorCookie(fx: Fixture, actor: Actor): string | undefined {
  switch (actor) {
    case 'admin':
      return fx.topo.admin.cookie;
    case 'alice':
      return fx.topo.alice.cookie;
    case 'anonymous':
      return undefined;
  }
}

function fetchSiteHeaders(spec: OriginSpec, base: Record<string, string> = {}): Record<string, string> {
  const headers = { ...base };
  if (spec.secFetchSite !== null) headers['Sec-Fetch-Site'] = spec.secFetchSite;
  return headers;
}

/** Sends one mutation route with the given Origin / Sec-Fetch-Site and extra headers. */
async function sendMutation(
  fx: Fixture,
  route: MutationRoute,
  spec: OriginSpec,
  extraHeaders: Record<string, string> = {},
): Promise<ApiResult> {
  const { path, body } = route.build(fx);
  return api(fx.ctx, route.method, path, {
    cookie: actorCookie(fx, route.actor),
    origin: spec.origin,
    body,
    headers: fetchSiteHeaders(spec, extraHeaders),
  });
}

function isCsrfRejection(res: ApiResult): boolean {
  return res.status === 403 && res.json?.error === CSRF_REJECTION_ERROR;
}

// -------------------------------------------------------------
// WebSocket routes (design C6.5 / C6.6)
// -------------------------------------------------------------

interface WsRoute {
  template: string;
  /** /ws: the session owner (Alice); /monitor: the built-in Security Auditor, which holds session.monitor. */
  actor: 'alice' | 'auditor';
  build(fx: Fixture): string;
}

const WS_ROUTES: readonly WsRoute[] = [
  {
    template: '/api/sessions/:id/ws',
    actor: 'alice',
    // wsUrl returned by POST /api/sessions already carries `?ticket=<ticket>`.
    build: (fx) => fx.session.wsUrl,
  },
  {
    template: '/api/admin/sessions/:id/monitor',
    actor: 'auditor',
    build: (fx) => `/api/admin/sessions/${id(fx.session.sessionId)}/monitor`,
  },
];

async function sendWsUpgrade(fx: Fixture, route: WsRoute, spec: OriginSpec): Promise<ApiResult> {
  const cookie = route.actor === 'alice' ? fx.topo.alice.cookie : fx.topo.auditor.cookie;
  return api(fx.ctx, 'GET', route.build(fx), {
    cookie,
    origin: spec.origin,
    headers: fetchSiteHeaders(spec, { Upgrade: 'websocket' }),
  });
}

// -------------------------------------------------------------
// [SEC-20] Cross-origin mutation requests (Property 8, mutation half)
// -------------------------------------------------------------

describe('[SEC-20] 跨源变更请求被拒绝（Property 8）', () => {
  for (const route of MUTATION_ROUTES) {
    // Feature: v1-compliance-review, Property 8: 跨源请求被拒绝
    it(`[SEC-20] 跨源变更请求被拒绝：${route.method} ${route.template}`, { timeout: 60_000 }, async () => {
      await withFixture(async (fx) => {
        await forAll(
          genOriginAttack,
          async (attack) => {
            const before = await fx.probe.snapshot();
            const res = await sendMutation(fx, route, attack);
            const after = await fx.probe.snapshot();

            assert.equal(
              res.status,
              403,
              `[判定] 跨源变更请求未被拒绝（期望 403，实际 ${res.status}）：${routeLabel(route)} ← ${attack.label}`,
            );
            const changes = diffSnapshots(before, after);
            assert.equal(
              changes.length,
              0,
              `[判定] 被拒绝的跨源请求改变了 D1：${routeLabel(route)} ← ${attack.label}：${changes.join('; ')}`,
            );
            assert.equal(
              res.json?.error,
              CSRF_REJECTION_ERROR,
              `[判定] 跨源变更请求的 403 不是由 Origin/CSRF 校验产生：${routeLabel(route)} ← ${attack.label}`,
            );
          },
          { runs: PROPERTY_RUNS, seed: seedFromEnv() },
        );
      });
    });
  }
});

describe('[SEC-20] 正向对照：同源变更请求不被 Origin 校验拒绝', () => {
  for (const route of MUTATION_ROUTES) {
    it(`[SEC-20] 正向对照：同源请求通过 Origin 校验：${route.method} ${route.template}`, async () => {
      await withFixture(async (fx) => {
        const res = await sendMutation(fx, route, SAME_ORIGIN_REQUEST);
        assert.ok(
          !isCsrfRejection(res),
          `[正向对照] 同源请求被 Origin/CSRF 校验拒绝：${routeLabel(route)}（状态 ${res.status}）`,
        );
      });
    });
  }
});

// -------------------------------------------------------------
// [SEC-13] Cross-origin WebSocket upgrades (Property 8, WebSocket half)
// -------------------------------------------------------------

describe('[SEC-13] 跨源 WebSocket 升级被拒绝（Property 8）', () => {
  for (const route of WS_ROUTES) {
    // Feature: v1-compliance-review, Property 8: 跨源请求被拒绝
    it(`[SEC-13] 跨源 WebSocket 升级被拒绝：GET ${route.template}`, { timeout: 60_000 }, async () => {
      await withFixture(async (fx) => {
        await forAll(
          genOriginAttack,
          async (attack) => {
            const callsBefore = fx.ctx.sessions.calls.length;
            const res = await sendWsUpgrade(fx, route, attack);

            assert.equal(
              res.status,
              403,
              `[判定] 跨源 WebSocket 升级未被拒绝（期望 403，实际 ${res.status}）：GET ${route.template} ← ${attack.label}`,
            );
            assert.equal(
              res.json?.error,
              WS_ORIGIN_ERROR,
              `[判定] 跨源 WebSocket 升级的 403 不是由 Origin 校验产生：GET ${route.template} ← ${attack.label}`,
            );
            assert.equal(
              fx.ctx.sessions.calls.length,
              callsBefore,
              `[判定] 跨源 WebSocket 升级仍调用了 SSHSessionDO：GET ${route.template} ← ${attack.label}`,
            );
          },
          { runs: PROPERTY_RUNS, seed: seedFromEnv() },
        );
      });
    });
  }
});

describe('[SEC-13] 正向对照：同源 WebSocket 升级不因 Origin 被拒', () => {
  for (const route of WS_ROUTES) {
    it(`[SEC-13] 正向对照：同源 WebSocket 升级通过 Origin 校验：GET ${route.template}`, async () => {
      await withFixture(async (fx) => {
        const res = await sendWsUpgrade(fx, route, SAME_ORIGIN_REQUEST);
        const error: unknown = res.json?.error;
        assert.ok(
          !(typeof error === 'string' && WS_GATE_ERRORS.includes(error)),
          `[正向对照] 同源 WebSocket 升级未越过认证/权限/Upgrade/Origin 关卡：GET ${route.template}（状态 ${res.status}，错误 ${String(error)}）`,
        );
      });
    });
  }
});

// -------------------------------------------------------------
// [SEC-20] Same-origin mutation without a CSRF token (Property 9, L10)
// -------------------------------------------------------------
//
// AGENTS.md §63 requires three layers for every mutation: SameSite cookie, Origin check and a CSRF token.
// Property 9 isolates the third layer: the request is same-origin (passes the Origin check exercised by
// Property 8), carries a valid Super Admin cookie (so no authentication or permission gate can reject it)
// and a valid body, but no CSRF token in any form (no token header, no token field in the body). §63 then
// requires a 403 and an unchanged D1.

/**
 * Gate errors that must not explain a 403 here: the request carries a Super Admin cookie, so a 403 with one
 * of these messages would mean the fixture is broken, not that a CSRF token check rejected the request.
 */
const AUTH_GATE_ERRORS: readonly string[] = ['Authentication required', 'Invalid or expired session', 'Permission denied'];

/**
 * Non-CSRF headers a same-origin browser request may carry. None of them is (or resembles) a CSRF token;
 * X-Requested-With is included because it is sometimes mistaken for CSRF protection.
 */
const NON_CSRF_HEADER_POOL: ReadonlyArray<(rng: Rng) => [string, string]> = [
  () => ['X-Requested-With', 'XMLHttpRequest'],
  () => ['Accept', 'application/json'],
  (rng) => ['Referer', `${TEST_ORIGIN}/admin/${randomLabel(rng)}`],
  () => ['Sec-Fetch-Mode', 'cors'],
  () => ['Sec-Fetch-Dest', 'empty'],
  (rng) => ['User-Agent', `Mozilla/5.0 (compliance-test ${rng.hex(4)})`],
];

/** One same-origin, tokenless mutation request. */
interface TokenlessCase {
  path: string;
  body: unknown;
  headers: Record<string, string>;
  /** Non-secret description (route, target name, header names). Never contains a secret or a body value. */
  label: string;
}

interface TokenlessRoute {
  method: 'POST' | 'PUT';
  template: string;
  /** Fresh, valid body and target for each iteration (random names / secrets, random existing targets). */
  build(fx: Fixture, rng: Rng): { path: string; body: unknown; target: string };
}

/** The three representative mutation routes of task 11.2 / design C6.5. */
const TOKENLESS_ROUTES: readonly TokenlessRoute[] = [
  {
    method: 'POST',
    template: '/api/admin/groups',
    build: (_fx, rng) => ({
      path: '/api/admin/groups',
      body: {
        name: `CSRF-Probe-${rng.hex(6)}`,
        ...(rng.bool() ? { description: `csrf probe ${rng.hex(4)}` } : {}),
      },
      target: 'new group',
    }),
  },
  {
    method: 'PUT',
    template: '/api/admin/credentials/:id',
    build: (fx, rng) => {
      const target = rng.pick([
        { id: fx.topo.deployKey.id, name: fx.topo.deployKey.name },
        { id: fx.topo.rootPassword.id, name: fx.topo.rootPassword.name },
        { id: fx.spareCredentialId, name: 'spare credential' },
      ] as const);
      return {
        path: `/api/admin/credentials/${id(target.id)}`,
        body: { secret: `EJ-SECRET-${rng.hex(16)}` },
        target: target.name,
      };
    },
  },
  {
    method: 'POST',
    template: '/api/admin/authorizations',
    build: (fx, rng) => {
      const subject = rng.pick([
        { userIds: [fx.topo.bob.id] },
        { userIds: [fx.topo.alice.id] },
        { groupIds: [fx.topo.developers.id] },
      ]);
      const target = rng.pick([
        { assetIds: [fx.topo.prodDb01.id], accountIds: [fx.topo.dba.id] },
        { assetIds: [fx.topo.prodWeb01.id], accountIds: [fx.topo.root.id] },
        { assetGroupIds: [fx.topo.web.id], accountIds: [fx.topo.deploy.id] },
      ]);
      return {
        path: '/api/admin/authorizations',
        body: { name: `csrf-probe-rule-${rng.hex(6)}`, ...subject, ...target, actions: ['connect'], enabled: rng.bool() },
        target: 'new authorization rule',
      };
    },
  },
];

/** Same-origin Origin header, optional `Sec-Fetch-Site: same-origin`, random non-CSRF headers, no token. */
function genTokenlessCase(fx: Fixture, route: TokenlessRoute, rng: Rng): TokenlessCase {
  const { path, body, target } = route.build(fx, rng);
  const headers: Record<string, string> = {};
  if (rng.bool()) headers['Sec-Fetch-Site'] = 'same-origin';
  for (const make of NON_CSRF_HEADER_POOL) {
    if (rng.bool()) {
      const [name, value] = make(rng);
      headers[name] = value;
    }
  }
  const headerNames = Object.keys(headers);
  const label =
    `${route.method} ${route.template}（目标 ${target}；Origin=${TEST_ORIGIN}；` +
    `附加头 ${headerNames.length > 0 ? headerNames.join(', ') : '<无>'}；无 CSRF Token）`;
  return { path, body, headers, label };
}

async function sendTokenless(fx: Fixture, route: TokenlessRoute, c: TokenlessCase): Promise<ApiResult> {
  return api(fx.ctx, route.method, c.path, {
    csrf: false,
    cookie: fx.topo.admin.cookie,
    origin: TEST_ORIGIN,
    body: c.body,
    headers: c.headers,
  });
}

describe('[SEC-20] 缺少 CSRF Token 的同源变更被拒绝（Property 9）', () => {
  for (const route of TOKENLESS_ROUTES) {
    // Feature: v1-compliance-review, Property 9: 缺少 CSRF Token 的同源变更被拒绝
    it(
      `[SEC-20] 同源无 CSRF Token 的变更被拒绝：${route.method} ${route.template}`,
      { timeout: 60_000 },
      async () => {
        await withFixture(async (fx) => {
          await forAll(
            (rng) => genTokenlessCase(fx, route, rng),
            async (c) => {
              const before = await fx.probe.snapshot();
              const res = await sendTokenless(fx, route, c);
              const after = await fx.probe.snapshot();

              assert.equal(
                res.status,
                403,
                `[判定] 同源无 CSRF Token 的变更未被拒绝（期望 403，实际 ${res.status}）：${c.label}`,
              );
              const changes = diffSnapshots(before, after);
              assert.equal(
                changes.length,
                0,
                `[判定] 被拒绝的同源无 Token 变更改变了 D1：${c.label}：${changes.join('; ')}`,
              );
              const error: unknown = res.json?.error;
              assert.ok(
                !(typeof error === 'string' && AUTH_GATE_ERRORS.includes(error)),
                `[前提] 403 来自认证/权限关卡而非 CSRF 校验（夹具的管理员 Cookie 无效）：${c.label}`,
              );
            },
            { runs: PROPERTY_RUNS, seed: seedFromEnv() },
          );
        });
      },
    );
  }
});

describe('[SEC-20] 正向对照：同源无 Token 请求越过认证、权限与参数校验', () => {
  for (const route of TOKENLESS_ROUTES) {
    // A 403 in Property 9 is only meaningful if the same request is otherwise well-formed: authenticated,
    // authorised, targeting existing resources and with a valid body. This control sends the run-0 case and
    // requires that no earlier gate rejects it. It holds both today (request accepted) and after a CSRF token
    // check is added (403 from that check, which is not one of AUTH_GATE_ERRORS).
    it(`[SEC-20] 正向对照：同源无 Token 请求越过认证、权限与参数校验：${route.method} ${route.template}`, async () => {
      await withFixture(async (fx) => {
        await forAll(
          (rng) => genTokenlessCase(fx, route, rng),
          async (c) => {
            const res = await sendTokenless(fx, route, c);
            const error: unknown = res.json?.error;
            assert.ok(!res.threw, `[正向对照] 处理器抛出未捕获异常：${c.label}`);
            assert.ok(
              ![400, 401, 404].includes(res.status) && res.status < 500,
              `[正向对照] 请求被认证、路由或参数校验拒绝（状态 ${res.status}）：${c.label}`,
            );
            assert.ok(
              !(typeof error === 'string' && AUTH_GATE_ERRORS.includes(error)),
              `[正向对照] 请求被认证/权限关卡拒绝（错误 ${String(error)}）：${c.label}`,
            );
          },
          { runs: 1, seed: seedFromEnv() },
        );
      });
    });
  }
});
