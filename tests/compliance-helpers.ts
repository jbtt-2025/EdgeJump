// Shared support for the v1-compliance-review verification tests (tests/compliance-*.test.ts).
//
// Design reference: .kiro/specs/v1-compliance-review/design.md (C6.4, D6, D7, C6.7).
// - This file is NOT a test file (it does not match *.test.ts) and is never run by `npm test` on its own.
// - It only observes the implementation under review through its exported functions, route handlers
//   (src/worker.ts default export) and Durable Object classes. Business code is never modified.
// - Every secret used here is either a per-context random value (KEK) or a fixed test constant
//   (pepper, bootstrap token). No real Cloudflare resource or network access is used.

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { format } from 'node:util';

import type { Env } from '../src/types.ts';
import type { SocketConnector } from '../src/durable/SSHSessionDO.ts';
import worker from '../src/worker.ts';
import { SSHSessionDO, setCustomSocketConnector } from '../src/durable/SSHSessionDO.ts';
import { RateLimitDO } from '../src/durable/RateLimitDO.ts';
import { PasswordKdfDO } from '../src/durable/PasswordKdfDO.ts';
import { COOKIE_NAME, SESSION_TTL_MS } from '../src/auth/auth-service.ts';
import { generateSessionToken, hashToken } from '../src/crypto/token.ts';
import { bytesToHex } from '../src/crypto/utils.ts';
import { parseTicketPayload } from '../src/backend/security.ts';
import { createCredential } from '../src/credentials/credential-service.ts';
import { createAsset, createAssetAccount, createAssetGroup } from '../src/assets/asset-service.ts';
import { createAuthorizationRule } from '../src/authorization/authorization-service.ts';
import { createGroup } from '../src/users/user-service.ts';
import { createTestDatabase } from './mock-d1.ts';

// -------------------------------------------------------------
// Constants
// -------------------------------------------------------------

/** Default number of iterations for every property (design: Testing strategy, at least 100). */
export const PROPERTY_RUNS = 100;

/** Same-origin value used for Origin headers and request URLs. */
export const TEST_ORIGIN = 'https://bastion.test';

/** Fixed default seed for the property PRNG; overridable through EJ_COMPLIANCE_SEED (D6). */
export const DEFAULT_SEED = 60782;

/** Fixed, obviously-fake test constants. They are not real secrets. */
export const TEST_AUTH_PEPPER = 'compliance-test-pepper-not-a-real-secret';
export const TEST_BOOTSTRAP_TOKEN = 'compliance-test-bootstrap-token-not-a-real-secret';

/** Error message thrown by the network block for both fetch() and TCP sockets. */
export const NETWORK_DISABLED_MESSAGE = 'compliance-test: network disabled';

/** Built-in role name -> role id, as seeded by migrations/0002_initial_roles_permissions.sql. */
export const BUILTIN_ROLE_IDS = {
  'Super Admin': 'role_super_admin',
  'Asset Admin': 'role_asset_admin',
  'Security Auditor': 'role_security_auditor',
  User: 'role_user',
} as const;

export type BuiltinRole = keyof typeof BUILTIN_ROLE_IDS;

// Captured at module load so helpers keep working when a test enables node:test mock timers.
const realSetImmediate: (callback: () => void) => unknown = globalThis.setImmediate.bind(globalThis);

// Placeholder password material for users inserted directly through SQL. The hash/salt are not hex,
// so verifyPassword() rejects them immediately: such users can never log in with a password.
const PLACEHOLDER_PASSWORD_HASH = 'compliance-placeholder-hash';
const PLACEHOLDER_PASSWORD_SALT = 'compliance-placeholder-salt';

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

// -------------------------------------------------------------
// Reproducible randomness (D6)
// -------------------------------------------------------------

export interface Rng {
  /** Uniform float in [0, 1). */
  next(): number;
  /** Uniform integer in [min, max] (both inclusive). */
  int(min: number, max: number): number;
  pick<T>(items: readonly T[]): T;
  /** true with probability p (default 0.5). */
  bool(p?: number): boolean;
  /** Deterministic lowercase hex string of `bytes` bytes (2 * bytes characters). */
  hex(bytes: number): string;
}

/**
 * Reads EJ_COMPLIANCE_SEED (decimal integer in [0, 2^32 - 1]); falls back to `defaultSeed`,
 * then DEFAULT_SEED. An invalid value throws so that a mistyped seed is never silently ignored.
 */
export function seedFromEnv(defaultSeed: number = DEFAULT_SEED): number {
  const raw = process.env.EJ_COMPLIANCE_SEED;
  if (raw === undefined || raw.trim() === '') return defaultSeed >>> 0;
  const value = Number(raw.trim());
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new TypeError('EJ_COMPLIANCE_SEED must be an integer in [0, 4294967295]');
  }
  return value >>> 0;
}

/** mulberry32 PRNG. */
export function createRng(seed: number): Rng {
  let state = seed >>> 0;

  const next = (): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  const int = (min: number, max: number): number => {
    if (!Number.isInteger(min) || !Number.isInteger(max) || min > max) {
      throw new RangeError(`Rng.int requires integers with min <= max (got ${min}, ${max})`);
    }
    return min + Math.floor(next() * (max - min + 1));
  };

  return {
    next,
    int,
    pick<T>(items: readonly T[]): T {
      if (items.length === 0) throw new RangeError('Rng.pick requires a non-empty array');
      return items[int(0, items.length - 1)];
    },
    bool(p: number = 0.5): boolean {
      return next() < p;
    },
    hex(bytes: number): string {
      let out = '';
      for (let i = 0; i < bytes; i++) out += int(0, 255).toString(16).padStart(2, '0');
      return out;
    },
  };
}

// Derives an independent per-run seed so each run's generator only depends on (seed, run).
function deriveRunSeed(seed: number, run: number): number {
  let h = (seed ^ Math.imul(run + 1, 0x9e3779b1)) >>> 0;
  h = Math.imul(h ^ (h >>> 16), 0x85ebca6b) >>> 0;
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35) >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
}

/**
 * Runs `check(gen(rng, run), run)` for `runs` iterations (default PROPERTY_RUNS).
 * Any failure is rethrown as `[seed=<seed>, run=<run>] <original message>` with the original error as
 * `cause`. The generated value is never included in the message (it may contain test secrets).
 * Reproduce a failure with EJ_COMPLIANCE_SEED=<seed>; run N always receives the same generator.
 */
export async function forAll<T>(
  gen: (rng: Rng, run: number) => T | Promise<T>,
  check: (value: T, run: number) => void | Promise<void>,
  opts: { runs?: number; seed?: number } = {},
): Promise<void> {
  const runs = opts.runs ?? PROPERTY_RUNS;
  const seed = (opts.seed ?? seedFromEnv()) >>> 0;
  for (let run = 0; run < runs; run++) {
    try {
      const value = await gen(createRng(deriveRunSeed(seed, run)), run);
      await check(value, run);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`[seed=${seed}, run=${run}] ${message}`, { cause: err });
    }
  }
}

/** Lets pending promise chains and immediates (e.g. background DO work) settle. */
export async function flushAsync(rounds: number = 5): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise<void>((resolve) => realSetImmediate(resolve));
  }
}

// -------------------------------------------------------------
// Durable Object namespace mock (D7)
// -------------------------------------------------------------

export interface MockDoId {
  toString(): string;
  equals(other: { toString(): string }): boolean;
  readonly name?: string;
}

export interface MockDoCall {
  id: string;
  method: string;
  path: string;
  url: string;
  headers: Record<string, string>;
  /** Parsed JSON body, raw text when not JSON, or null when empty. */
  body: unknown;
}

export interface MockDoStub {
  readonly id: MockDoId;
  readonly name?: string;
  fetch(input: Request | string | URL, init?: RequestInit): Promise<Response>;
}

export interface MockDoNamespace<T = unknown> {
  /** Deterministic id: sha256(name) as 64 lowercase hex characters. */
  idFromName(name: string): MockDoId & { readonly name: string };
  /** Accepts only 64-hex-character strings; anything else throws TypeError (Cloudflare semantics). */
  idFromString(id: string): MockDoId;
  get(id: { toString(): string; name?: string }): MockDoStub;
  /** Every stub.fetch() in call order, recorded before the instance handles it. */
  calls: MockDoCall[];
  /** Real Durable Object instances keyed by id string (created lazily on first fetch). */
  instances: Map<string, T>;
}

interface DoInstance {
  fetch(request: Request): Promise<Response>;
}

const DO_ID_PATTERN = /^[0-9a-f]{64}$/i;

function makeDoId(hex: string, name?: string): MockDoId {
  const id: { toString(): string; equals(other: { toString(): string }): boolean; name?: string } = {
    toString: () => hex,
    equals: (other) => other.toString() === hex,
  };
  if (name !== undefined) id.name = name;
  return id;
}

function parseRecordedBody(text: string): unknown {
  if (text === '') return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function createMockDoNamespace<T extends DoInstance>(
  factory: (state: DurableObjectState) => T,
): MockDoNamespace<T> {
  const calls: MockDoCall[] = [];
  const instances = new Map<string, T>();

  return {
    calls,
    instances,

    idFromName(name: string) {
      return makeDoId(sha256Hex(name), name) as MockDoId & { readonly name: string };
    },

    idFromString(id: string) {
      if (typeof id !== 'string' || !DO_ID_PATTERN.test(id)) {
        throw new TypeError('Invalid Durable Object ID: expected 64 hexadecimal digits');
      }
      return makeDoId(id.toLowerCase());
    },

    get(idLike: { toString(): string; name?: string }): MockDoStub {
      const hex = idLike.toString();
      const id = makeDoId(hex, idLike.name);
      return {
        id,
        name: idLike.name,
        async fetch(input: Request | string | URL, init?: RequestInit): Promise<Response> {
          const request = input instanceof Request && init === undefined ? input : new Request(input, init);
          const url = new URL(request.url);
          const bodyText = request.body ? await request.clone().text() : '';
          const headers: Record<string, string> = {};
          request.headers.forEach((value, key) => {
            headers[key] = value;
          });
          calls.push({
            id: hex,
            method: request.method.toUpperCase(),
            path: url.pathname,
            url: request.url,
            headers,
            body: parseRecordedBody(bodyText),
          });

          let instance = instances.get(hex);
          if (!instance) {
            const state = { id, storage: undefined, waitUntil() {} } as unknown as DurableObjectState;
            instance = factory(state);
            instances.set(hex, instance);
          }
          return instance.fetch(request);
        },
      };
    },
  };
}

// -------------------------------------------------------------
// Network block (fetch + TCP sockets)
// -------------------------------------------------------------

export interface NetworkAttempt {
  kind: 'fetch' | 'socket';
  /** fetch: request URL; socket: "<hostname>:<port>". */
  target: string;
}

const networkSinks = new Set<NetworkAttempt[]>();
const fetchSlot = globalThis as unknown as { fetch: unknown };
let savedFetch: unknown = null;

function recordNetworkAttempt(attempt: NetworkAttempt): void {
  for (const sink of networkSinks) sink.push({ ...attempt });
}

function describeFetchTarget(input: unknown): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  if (input && typeof input === 'object' && typeof (input as { url?: unknown }).url === 'string') {
    return (input as { url: string }).url;
  }
  return String(input);
}

async function blockedFetch(input: unknown): Promise<never> {
  recordNetworkAttempt({ kind: 'fetch', target: describeFetchTarget(input) });
  throw new Error(NETWORK_DISABLED_MESSAGE);
}

const blockedSocketConnector: SocketConnector = async (address) => {
  recordNetworkAttempt({ kind: 'socket', target: `${address.hostname}:${address.port}` });
  throw new Error(NETWORK_DISABLED_MESSAGE);
};

// Reference-counted: installed by the first active context, removed with the last one.
function installNetworkBlock(sink: NetworkAttempt[]): void {
  if (networkSinks.size === 0) {
    savedFetch = fetchSlot.fetch;
    fetchSlot.fetch = blockedFetch;
    setCustomSocketConnector(blockedSocketConnector);
  }
  networkSinks.add(sink);
}

function releaseNetworkBlock(sink: NetworkAttempt[]): void {
  if (!networkSinks.delete(sink)) return;
  if (networkSinks.size === 0) {
    fetchSlot.fetch = savedFetch;
    savedFetch = null;
    // SSHSessionDO exposes no getter; the module default is null.
    setCustomSocketConnector(null);
  }
}

// -------------------------------------------------------------
// Console capture
// -------------------------------------------------------------

type ConsoleMethod = 'log' | 'info' | 'warn' | 'error' | 'debug';
const CONSOLE_METHODS: readonly ConsoleMethod[] = ['log', 'info', 'warn', 'error', 'debug'];

interface ActiveCapture {
  lines: string[];
  passthrough: boolean;
}

const activeCaptures = new Set<ActiveCapture>();
let savedConsole: Record<ConsoleMethod, (...args: unknown[]) => void> | null = null;

function installConsolePatch(): void {
  if (savedConsole) return;
  const saved = {} as Record<ConsoleMethod, (...args: unknown[]) => void>;
  for (const method of CONSOLE_METHODS) {
    const original = console[method];
    saved[method] = original;
    console[method] = (...args: unknown[]): void => {
      const line = `[${method}] ${format(...args)}`;
      let passthrough = false;
      for (const capture of activeCaptures) {
        capture.lines.push(line);
        if (capture.passthrough) passthrough = true;
      }
      if (passthrough) original.apply(console, args);
    };
  }
  savedConsole = saved;
}

function uninstallConsolePatchIfIdle(): void {
  if (activeCaptures.size > 0 || !savedConsole) return;
  for (const method of CONSOLE_METHODS) console[method] = savedConsole[method];
  savedConsole = null;
}

function restoreAllConsoleCaptures(): void {
  activeCaptures.clear();
  uninstallConsolePatchIfIdle();
}

/**
 * Captures console.log/info/warn/error/debug as `[<method>] <util.format output>` lines.
 * Output is swallowed unless `passthrough` is true. `restore()` is idempotent; lines stay readable
 * afterwards. ComplianceContext.cleanup() restores any capture that is still active.
 */
export function captureConsole(opts: { passthrough?: boolean } = {}): { lines: string[]; restore(): void } {
  const capture: ActiveCapture = { lines: [], passthrough: opts.passthrough ?? false };
  activeCaptures.add(capture);
  installConsolePatch();
  return {
    lines: capture.lines,
    restore(): void {
      activeCaptures.delete(capture);
      uninstallConsolePatchIfIdle();
    },
  };
}

// -------------------------------------------------------------
// Compliance context
// -------------------------------------------------------------

export interface ComplianceContext {
  env: Env;
  db: D1Database;
  /** SSH_SESSIONS binding; instances are real SSHSessionDO(state, env). */
  sessions: MockDoNamespace<SSHSessionDO>;
  /** RATE_LIMIT binding; instances are real RateLimitDO(state, env). */
  rateLimit: MockDoNamespace<RateLimitDO>;
  /** CREDENTIAL_KEK_V1 of this context: 32 random bytes as hex. */
  kek: string;
  network: { attempts: NetworkAttempt[] };
  /** Registers an SSHSessionDO constructed directly by a test so cleanup() terminates it too. */
  track(instance: SSHSessionDO): SSHSessionDO;
  /**
   * Terminates every SSHSessionDO (namespace instances and tracked ones), lets background work
   * settle, then restores fetch, the socket connector and console. Idempotent.
   */
  cleanup(): Promise<void>;
}

export interface CreateContextOptions {
  deployType?: string;
  /** Defaults to TEST_BOOTSTRAP_TOKEN; pass null to leave BOOTSTRAP_TOKEN unset. */
  bootstrapToken?: string | null;
}

function createMemoryKv(): KVNamespace {
  const store = new Map<string, string>();
  return {
    async get(key: string) {
      return store.get(key) ?? null;
    },
    async put(key: string, value: string) {
      store.set(key, String(value));
    },
    async delete(key: string) {
      store.delete(key);
    },
    async list() {
      return { keys: [...store.keys()].map((name) => ({ name })), list_complete: true, cacheStatus: null };
    },
  } as unknown as KVNamespace;
}

export async function createContext(opts: CreateContextOptions = {}): Promise<ComplianceContext> {
  const db = await createTestDatabase();
  const kek = bytesToHex(new Uint8Array(randomBytes(32)));
  const attempts: NetworkAttempt[] = [];
  const tracked = new Set<SSHSessionDO>();

  let doEnv: Env | undefined;
  const sessions = createMockDoNamespace<SSHSessionDO>((state) => new SSHSessionDO(state, doEnv));
  const rateLimit = createMockDoNamespace<RateLimitDO>((state) => new RateLimitDO(state, doEnv));
  const passwordKdf = createMockDoNamespace<PasswordKdfDO>((state) => new PasswordKdfDO(state, doEnv!));

  const env: Env = {
    DB: db,
    SSH_SESSIONS: sessions as unknown as DurableObjectNamespace,
    RATE_LIMIT: rateLimit as unknown as DurableObjectNamespace,
    PASSWORD_KDF: passwordKdf as unknown as DurableObjectNamespace,
    KV_CACHE: createMemoryKv(),
    CREDENTIAL_KEK_V1: kek,
    AUTH_PEPPER: TEST_AUTH_PEPPER,
    SESSION_TICKET_SECRET: 'compliance-independent-ticket-key',
    BOOTSTRAP_TOKEN: opts.bootstrapToken === null ? undefined : (opts.bootstrapToken ?? TEST_BOOTSTRAP_TOKEN),
    DEPLOY_TYPE: opts.deployType ?? 'production',
  };
  doEnv = env;

  installNetworkBlock(attempts);

  let cleaned = false;
  return {
    env,
    db,
    sessions,
    rateLimit,
    kek,
    network: { attempts },
    track(instance: SSHSessionDO): SSHSessionDO {
      tracked.add(instance);
      return instance;
    },
    async cleanup(): Promise<void> {
      if (cleaned) return;
      cleaned = true;
      // RateLimitDO has neither timers nor terminate(); only SSHSessionDO instances are terminated.
      for (const instance of [...sessions.instances.values(), ...tracked]) {
        try {
          await instance.terminate('compliance_cleanup');
        } catch {
          // Cleanup must not mask the test result.
        }
      }
      await flushAsync();
      releaseNetworkBlock(attempts);
      restoreAllConsoleCaptures();
    },
  };
}

// -------------------------------------------------------------
// Fixtures
// -------------------------------------------------------------

/**
 * Inserts a user directly through SQL with placeholder password material (no PBKDF2, cannot log in
 * with a password). `roles` defaults to ['User'] like createUser(); pass [] for no role.
 */
export async function insertUser(
  db: D1Database,
  u: { username: string; status?: 'active' | 'disabled' | 'locked'; roles?: BuiltinRole[] },
): Promise<{ id: string; username: string }> {
  const id = `usr_${randomUUID()}`;
  const username = u.username.trim().toLowerCase();
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO users (
         id, username, display_name, email, password_hash, password_algorithm,
         password_params, password_salt, status, mfa_enabled, created_at, updated_at, created_by
       ) VALUES (?, ?, ?, NULL, ?, 'pbkdf2-sha256', ?, ?, ?, 1, ?, ?, 'compliance-test')`
    )
    .bind(
      id,
      username,
      username,
      PLACEHOLDER_PASSWORD_HASH,
      JSON.stringify({ iterations: 600000 }),
      PLACEHOLDER_PASSWORD_SALT,
      u.status ?? 'active',
      now,
      now
    )
    .run();

  for (const role of u.roles ?? ['User']) {
    await db
      .prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)')
      .bind(id, BUILTIN_ROLE_IDS[role])
      .run();
  }
  return { id, username };
}

/**
 * Grants one permission code to one user through a per-user custom (non built-in) role, creating the
 * permission row when the code is not seeded. Other users are unaffected.
 */
export async function grantPermission(db: D1Database, userId: string, code: string): Promise<void> {
  const permissionCode = code.trim();
  if (!permissionCode) throw new TypeError('grantPermission requires a non-empty permission code');

  let permission = await db
    .prepare('SELECT id FROM permissions WHERE code = ?')
    .bind(permissionCode)
    .first<{ id: string }>();
  if (!permission) {
    const permissionId = `perm_compliance_${sha256Hex(permissionCode).slice(0, 16)}`;
    await db
      .prepare('INSERT INTO permissions (id, code, description) VALUES (?, ?, ?)')
      .bind(permissionId, permissionCode, 'Compliance test permission')
      .run();
    permission = { id: permissionId };
  }

  const roleKey = sha256Hex(userId).slice(0, 16);
  const roleId = `role_compliance_${roleKey}`;
  await db
    .prepare('INSERT OR IGNORE INTO roles (id, name, description, is_builtin, created_at) VALUES (?, ?, ?, 0, ?)')
    .bind(roleId, `Compliance Custom Role ${roleKey}`, 'Per-user role configured by compliance tests', Date.now())
    .run();
  await db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)').bind(userId, roleId).run();
  await db
    .prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)')
    .bind(roleId, permission.id)
    .run();
}

/**
 * Creates a login session the same way login() stores it (random token, SHA-256 hash in D1) and
 * returns the Cookie header value `edgejump_session=<token>`. A negative ttlMs yields an expired session.
 */
export async function issueCookie(db: D1Database, userId: string, ttlMs: number = SESSION_TTL_MS): Promise<string> {
  const token = generateSessionToken();
  const tokenHash = await hashToken(token);
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO auth_sessions (
         id, user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent, revoked_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`
    )
    .bind(`sess_${randomUUID()}`, userId, tokenHash, now, now, now + ttlMs, '127.0.0.1', 'compliance-test')
    .run();
  return `${COOKIE_NAME}=${token}`;
}

// -------------------------------------------------------------
// HTTP entry point
// -------------------------------------------------------------

export interface ApiOptions {
  /** Send the valid double-submit token by default; false exercises token rejection. */
  csrf?: boolean;
  /** Full Cookie header value, e.g. from issueCookie(). */
  cookie?: string | null;
  /** Defaults to TEST_ORIGIN; null sends no Origin header. */
  origin?: string | null;
  /** Objects are JSON-encoded; strings are sent verbatim. Both set Content-Type: application/json. */
  body?: unknown;
  /** Applied last, so they override the defaults above. */
  headers?: Record<string, string>;
}

/** Seed the metadata normally inserted by createSession, before a direct DO probe. */
export async function seedSessionMetadata(db: D1Database, config: { sessionId?: string; userId: string; assetId: string; accountId: string; usernameSnapshot?: string; assetNameSnapshot?: string; accountNameSnapshot?: string }): Promise<void> {
  await db.prepare(`INSERT OR IGNORE INTO ssh_sessions (id, user_id, username_snapshot, asset_id, asset_name_snapshot,
    account_id, account_name_snapshot, source_ip, started_at, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, 'creating', ?)`)
    .bind(config.sessionId, config.userId, config.usernameSnapshot ?? 'probe', config.assetId, config.assetNameSnapshot ?? 'probe', config.accountId, config.accountNameSnapshot ?? 'probe', Date.now(), Date.now()).run();
}

export interface ApiResult {
  status: number;
  text: string;
  json: any;
  headers: Headers;
  /** true when the handler threw instead of returning a Response (reported as status 500). */
  threw: boolean;
  /** Client end of a WebSocket upgrade (status 101), otherwise null. */
  webSocket: unknown;
  /** Raw thrown value when threw = true. Non-enumerable so it is never printed by accident. */
  readonly error?: unknown;
}

/**
 * Sends a request through the default export of src/worker.ts (so HTTPS enforcement, /api/health
 * and security headers are covered). An exception thrown by the handler is captured as
 * { status: 500, threw: true, text: <exception class name> }.
 */
export async function api(
  ctx: Pick<ComplianceContext, 'env'>,
  method: string,
  path: string,
  opts: ApiOptions = {},
): Promise<ApiResult> {
  const url = new URL(path, TEST_ORIGIN);
  const headers = new Headers();
  if (opts.origin !== null) headers.set('Origin', opts.origin ?? TEST_ORIGIN);
  if (opts.cookie) headers.set('Cookie', opts.cookie);
  if (opts.csrf !== false && !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) {
    const token = 'a'.repeat(64);
    headers.set('Cookie', `${opts.cookie ?? ''}; __Host-edgejump_csrf=${token}`);
    headers.set('X-CSRF-Token', token);
  }

  let body: string | undefined;
  if (opts.body !== undefined) {
    body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
    headers.set('Content-Type', 'application/json');
  }
  for (const [key, value] of Object.entries(opts.headers ?? {})) headers.set(key, value);

  const request = new Request(url.toString(), { method: method.toUpperCase(), headers, body });

  let response: Response;
  try {
    response = await worker.fetch(request, ctx.env);
  } catch (err) {
    const result: ApiResult = {
      status: 500,
      text: err instanceof Error ? err.constructor.name || 'Error' : typeof err,
      json: null,
      headers: new Headers(),
      threw: true,
      webSocket: null,
    };
    Object.defineProperty(result, 'error', { value: err, enumerable: false });
    return result;
  }

  const text = await response.text();
  let json: any = null;
  if (text !== '') {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  return {
    status: response.status,
    text,
    json,
    headers: response.headers,
    threw: false,
    webSocket: (response as unknown as { webSocket?: unknown }).webSocket ?? null,
  };
}

// -------------------------------------------------------------
// §93 demo topology
// -------------------------------------------------------------

export interface SeededUser {
  id: string;
  username: string;
  /** Cookie header value of an active login session. */
  cookie: string;
}

export interface SeededAsset {
  id: string;
  name: string;
  hostname: string;
  port: number;
}

export interface SeededAccount {
  id: string;
  assetId: string;
  username: string;
  credentialId: string;
}

/**
 * §93 topology:
 *   Production (asset group) ── Web (asset group) ── prod-web-01 (8.8.8.8:22): deploy, root
 *   Production ── prod-db-01 (1.1.1.1:22, not authorized): dba
 *   Credentials: prod-deploy-key (private_key, `secret`) for deploy;
 *                prod-root-password (password, secrets.rootPassword) for root and dba
 *   Group Developers = { alice }; rule: Developers -> Production/Web -> deploy -> connect
 *   Users: admin (Super Admin), assetAdmin (Asset Admin), auditor (Security Auditor),
 *          alice and bob (User; bob is in no group)
 */
export interface DemoTopology {
  admin: SeededUser;
  assetAdmin: SeededUser;
  auditor: SeededUser;
  alice: SeededUser;
  bob: SeededUser;
  developers: { id: string; name: string };
  production: { id: string; name: string };
  web: { id: string; name: string; parentId: string };
  prodWeb01: SeededAsset;
  prodDb01: SeededAsset;
  deployKey: { id: string; name: string; type: 'private_key' };
  rootPassword: { id: string; name: string; type: 'password' };
  deploy: SeededAccount;
  root: SeededAccount;
  dba: SeededAccount;
  rule: { id: string; name: string };
  /** Plaintexts stored by this fixture (for leak scans). */
  secrets: { deployKey: string; rootPassword: string };
}

async function seedUser(db: D1Database, username: string, roles: BuiltinRole[]): Promise<SeededUser> {
  const user = await insertUser(db, { username, roles });
  return { ...user, cookie: await issueCookie(db, user.id) };
}

/**
 * Seeds the §93 topology through the implementation's service functions (real envelope encryption
 * with ctx.kek). `secret` becomes the prod-deploy-key plaintext; the root password is derived from it
 * deterministically and does not contain it as a substring.
 */
export async function seedDemoTopology(ctx: ComplianceContext, secret: string): Promise<DemoTopology> {
  const db = ctx.db;
  const rootPasswordSecret = `EJ-ROOTPW-${sha256Hex(`root:${secret}`).slice(0, 24)}`;

  // Users before anything that references them (node:sqlite enforces foreign keys).
  const admin = await seedUser(db, 'admin', ['Super Admin']);
  const assetAdmin = await seedUser(db, 'asset-admin', ['Asset Admin']);
  const auditor = await seedUser(db, 'auditor', ['Security Auditor']);
  const alice = await seedUser(db, 'alice', ['User']);
  const bob = await seedUser(db, 'bob', ['User']);

  const developersGroup = await createGroup({ name: 'Developers' }, admin.id, db);
  await db
    .prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)')
    .bind(developersGroup.id, alice.id, Date.now())
    .run();

  const productionGroup = await createAssetGroup({ name: 'Production' }, db);
  const webGroup = await createAssetGroup({ name: 'Web', parentId: productionGroup.id }, db);

  const prodWeb01 = await createAsset(
    { name: 'prod-web-01', hostname: '8.8.8.8', port: 22, platform: 'linux', environment: 'production', groupIds: [webGroup.id] },
    admin.id,
    db
  );
  const prodDb01 = await createAsset(
    { name: 'prod-db-01', hostname: '1.1.1.1', port: 22, platform: 'linux', environment: 'production', groupIds: [productionGroup.id] },
    admin.id,
    db
  );

  const deployKey = await createCredential({ name: 'prod-deploy-key', type: 'private_key', secret }, ctx.kek, db);
  const rootPassword = await createCredential(
    { name: 'prod-root-password', type: 'password', secret: rootPasswordSecret },
    ctx.kek,
    db
  );

  const deploy = await createAssetAccount({ assetId: prodWeb01.id, username: 'deploy', credentialId: deployKey.id }, db);
  const root = await createAssetAccount({ assetId: prodWeb01.id, username: 'root', credentialId: rootPassword.id }, db);
  const dba = await createAssetAccount({ assetId: prodDb01.id, username: 'dba', credentialId: rootPassword.id }, db);

  const rule = await createAuthorizationRule(
    {
      name: 'Developers -> Production/Web -> deploy',
      groupIds: [developersGroup.id],
      assetGroupIds: [webGroup.id],
      accountIds: [deploy.id],
      actions: ['connect'],
    },
    admin.id,
    db
  );

  const toAsset = (a: { id: string; name: string; hostname: string; port: number }): SeededAsset => ({
    id: a.id,
    name: a.name,
    hostname: a.hostname,
    port: a.port,
  });
  const toAccount = (a: { id: string; assetId: string; username: string; credentialId: string }): SeededAccount => ({
    id: a.id,
    assetId: a.assetId,
    username: a.username,
    credentialId: a.credentialId,
  });

  return {
    admin,
    assetAdmin,
    auditor,
    alice,
    bob,
    developers: { id: developersGroup.id, name: developersGroup.name },
    production: { id: productionGroup.id, name: productionGroup.name },
    web: { id: webGroup.id, name: webGroup.name, parentId: productionGroup.id },
    prodWeb01: toAsset(prodWeb01),
    prodDb01: toAsset(prodDb01),
    deployKey: { id: deployKey.id, name: deployKey.name, type: 'private_key' },
    rootPassword: { id: rootPassword.id, name: rootPassword.name, type: 'password' },
    deploy: toAccount(deploy),
    root: toAccount(root),
    dba: toAccount(dba),
    rule: { id: rule.id, name: rule.name },
    secrets: { deployKey: secret, rootPassword: rootPasswordSecret },
  };
}

// -------------------------------------------------------------
// Observation helpers
// -------------------------------------------------------------

function cellToText(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return new TextDecoder('utf-8', { fatal: false }).decode(value);
  if (value instanceof ArrayBuffer) return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(value));
  return String(value);
}

/**
 * Scans every column of every row of every user table and returns the distinct (table, column)
 * pairs whose text contains a needle; `needleIndex` identifies which needle (the value itself is
 * never returned). Empty needles are rejected because they would match everything.
 */
export async function scanDatabase(
  db: D1Database,
  needles: string[],
): Promise<Array<{ table: string; column: string; needleIndex: number }>> {
  if (needles.some((needle) => needle === '')) {
    throw new TypeError('scanDatabase needles must be non-empty strings');
  }
  const { results: tables } = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all<{ name: string }>();

  const hits: Array<{ table: string; column: string; needleIndex: number }> = [];
  const seen = new Set<string>();
  for (const { name: table } of tables ?? []) {
    const { results: rows } = await db
      .prepare(`SELECT * FROM "${table.replace(/"/g, '""')}"`)
      .all<Record<string, unknown>>();
    for (const row of rows ?? []) {
      for (const [column, value] of Object.entries(row)) {
        const text = cellToText(value);
        if (text === null) continue;
        needles.forEach((needle, needleIndex) => {
          const key = `${table}\u0000${column}\u0000${needleIndex}`;
          if (!seen.has(key) && text.includes(needle)) {
            seen.add(key);
            hits.push({ table, column, needleIndex });
          }
        });
      }
    }
  }
  return hits;
}

/** Decodes a session ticket payload without verifying it (delegates to parseTicketPayload). */
export function decodeTicket(ticket: string): Record<string, unknown> | null {
  return parseTicketPayload(ticket) as Record<string, unknown> | null;
}
