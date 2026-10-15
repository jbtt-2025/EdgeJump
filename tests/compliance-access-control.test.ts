// Feature: v1-compliance-review — supplementary verification tests for SEC-05 / SEC-06 / SEC-07
// (design C6.3, C6.5; Properties 2–5).
//
// Task 7.1 provides the shared building blocks of this file:
//   - oracle() / oracleVisibleAssets(): reference model written ONLY from AGENTS.md §23–§31; it never
//     calls the implementation under review.
//   - generateTopology(rng, now): random topology generator (design C6.5 sizes and boundaries).
//   - seedTopology(ctx, topology): writes a topology into the in-memory D1 and returns id maps + cookies.
//   - probe builders (pairProbes / tamperedProbes) and request helpers (postSession / getVisibleAssets).
//   - positive controls (design D9) and self-checks of the oracle, generator and fixture.
// Tasks 7.2–7.5 add the property cases (P2–P5) at the end of this file.
//
// Reference-model semantics (design C6.5, 判定口径):
//   - validity is the closed interval valid_from ≤ now ≤ valid_until; null means unbounded (§28)
//   - an asset-group target covers the assets of that group and of all its descendant groups
//     (§15 parent_id tree, §25, §79.1 Node mapping) — 经用户确认
//   - all_accounts = 1 (@ALL, EXT-003) covers every account of a targeted asset — 经用户确认
//   - an empty action set grants only `connect` (§27)
//   - Default Deny / Allow-only (§29); a login session of a non-active user is invalid (§31 steps 1–2)
//
// Fixture notes: users are inserted through compliance-helpers insertUser(); assets, asset groups,
// accounts and the credential go through the implementation's services; user groups and authorization
// rules (with link tables) are written with SQL so that an empty action set — reachable through
// PATCH /api/admin/authorizations/:id with `actions: []` — is persisted exactly as generated.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';

import {
  PROPERTY_RUNS,
  api,
  captureConsole,
  createContext,
  decodeTicket,
  flushAsync,
  forAll,
  insertUser,
  issueCookie,
  seedDemoTopology,
  seedFromEnv,
} from './compliance-helpers.ts';
import type {
  ApiResult,
  ComplianceContext,
  DemoTopology,
  NetworkAttempt,
  Rng,
  SeededUser,
} from './compliance-helpers.ts';
import { createAsset, createAssetAccount, createAssetGroup } from '../src/assets/asset-service.ts';
import { createAuthorizationRule } from '../src/authorization/authorization-service.ts';
import { createCredential } from '../src/credentials/credential-service.ts';
import { createGroup } from '../src/users/user-service.ts';
import { createTestDatabase } from './mock-d1.ts';

// -------------------------------------------------------------
// Topology model (logical keys only; no D1 ids, no secrets)
// -------------------------------------------------------------

/** Fixed reference time for generated validity windows (2026-10-07 09:00 UTC, cf. AGENTS.md §28 example). */
const FIXED_NOW = Date.UTC(2026, 9, 7, 9, 0, 0, 0);
const DAY_MS = 24 * 60 * 60 * 1000;

/** §27 actions: connect plus the reserved actions. */
const RULE_ACTIONS = ['connect', 'sftp_read', 'sftp_upload', 'sftp_download', 'port_forward'] as const;
type RuleAction = (typeof RULE_ACTIONS)[number];
const NON_CONNECT_ACTIONS: readonly RuleAction[] = RULE_ACTIONS.filter((action) => action !== 'connect');

type UserStatus = 'active' | 'disabled' | 'locked';

interface TopoUser {
  key: string;
  status: UserStatus;
  /** User groups the user belongs to (§13). */
  groupKeys: string[];
}

interface TopoGroup {
  key: string;
}

interface TopoAssetGroup {
  key: string;
  parentKey: string | null;
}

interface TopoAsset {
  key: string;
  hostname: string;
  port: number;
  enabled: boolean;
  /** Asset groups the asset is a direct member of. */
  groupKeys: string[];
}

interface TopoAccount {
  key: string;
  assetKey: string;
  username: string;
  enabled: boolean;
}

interface TopoRule {
  key: string;
  enabled: boolean;
  /** Absolute epoch ms or null (unbounded). */
  validFrom: number | null;
  validUntil: number | null;
  allAccounts: boolean;
  /** Persisted action set; may be empty. */
  actions: RuleAction[];
  userKeys: string[];
  groupKeys: string[];
  assetKeys: string[];
  assetGroupKeys: string[];
  /** May reference accounts of assets the rule does not target. */
  accountKeys: string[];
}

interface Topology {
  /** Reference time the validity windows were generated against. */
  generatedAt: number;
  users: TopoUser[];
  groups: TopoGroup[];
  assetGroups: TopoAssetGroup[];
  assets: TopoAsset[];
  accounts: TopoAccount[];
  rules: TopoRule[];
}

/** A request target: a topology key (resolved to the seeded D1 id) or a raw, non-existent id. */
type IdRef = { kind: 'key'; key: string } | { kind: 'raw'; raw: string };

interface SessionProbe {
  /** null = anonymous request without a login cookie. */
  userKey: string | null;
  asset: IdRef;
  account: IdRef;
  /** Item ids + combination description; never contains secrets. */
  label: string;
}

type ExpectedSessionStatus = 201 | 401 | 403;

/** assetKey -> visible account keys. */
type Visibility = Map<string, Set<string>>;

function keyRef(key: string): IdRef {
  return { kind: 'key', key };
}

function rawRef(raw: string): IdRef {
  return { kind: 'raw', raw };
}

function findByKey<T extends { key: string }>(items: readonly T[], key: string): T | undefined {
  return items.find((item) => item.key === key);
}

function makeRule(partial: Partial<TopoRule> & { key: string }): TopoRule {
  return {
    enabled: true,
    validFrom: null,
    validUntil: null,
    allAccounts: false,
    actions: ['connect'],
    userKeys: [],
    groupKeys: [],
    assetKeys: [],
    assetGroupKeys: [],
    accountKeys: [],
    ...partial,
  };
}

/** Compact, secret-free description for failure messages (validity relative to generatedAt). */
function describeTopology(topology: Topology): string {
  const rel = (value: number | null): number | null => (value === null ? null : value - topology.generatedAt);
  return JSON.stringify({
    users: topology.users,
    groups: topology.groups.map((g) => g.key),
    assetGroups: topology.assetGroups,
    assets: topology.assets.map((a) => ({ key: a.key, enabled: a.enabled, groupKeys: a.groupKeys })),
    accounts: topology.accounts.map((a) => ({ key: a.key, enabled: a.enabled })),
    rules: topology.rules.map((r) => ({ ...r, validFrom: rel(r.validFrom), validUntil: rel(r.validUntil) })),
  });
}

// -------------------------------------------------------------
// Reference model (AGENTS.md §23–§31 only)
// -------------------------------------------------------------

/** §15 / §25: an asset-group target covers the group itself and all of its descendants. */
function descendantGroupKeys(topology: Topology, rootKey: string): Set<string> {
  const covered = new Set<string>([rootKey]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const group of topology.assetGroups) {
      if (group.parentKey !== null && covered.has(group.parentKey) && !covered.has(group.key)) {
        covered.add(group.key);
        grew = true;
      }
    }
  }
  return covered;
}

/** §25: assets targeted by a rule = direct assets ∪ members of targeted groups (and descendants). */
function ruleTargetAssetKeys(topology: Topology, rule: TopoRule): Set<string> {
  const targets = new Set<string>(rule.assetKeys);
  const coveredGroups = new Set<string>();
  for (const groupKey of rule.assetGroupKeys) {
    for (const key of descendantGroupKeys(topology, groupKey)) coveredGroups.add(key);
  }
  for (const asset of topology.assets) {
    if (asset.groupKeys.some((groupKey) => coveredGroups.has(groupKey))) targets.add(asset.key);
  }
  return targets;
}

/** §28: enabled and now within the closed interval [valid_from, valid_until]; null = unbounded. */
function ruleInEffect(rule: TopoRule, now: number): boolean {
  return (
    rule.enabled &&
    (rule.validFrom === null || rule.validFrom <= now) &&
    (rule.validUntil === null || now <= rule.validUntil)
  );
}

/** §27: an empty action set grants only `connect`. */
function ruleGrantsAction(rule: TopoRule, action: RuleAction): boolean {
  const effective: readonly RuleAction[] = rule.actions;
  return effective.includes(action);
}

/** §24: subject = the user directly or one of the user's groups. */
function ruleCoversUser(rule: TopoRule, user: TopoUser): boolean {
  return rule.userKeys.includes(user.key) || rule.groupKeys.some((groupKey) => user.groupKeys.includes(groupKey));
}

/** §26: the account must be explicitly authorized (or covered by @ALL, EXT-003 declared semantics). */
function ruleCoversAccount(rule: TopoRule, account: TopoAccount): boolean {
  return rule.allAccounts || rule.accountKeys.includes(account.key);
}

/** §23 five elements + §31 checks 2–7; §29 Default Deny when no rule allows. */
function isConnectAuthorized(
  topology: Topology,
  userKey: string,
  assetKey: string,
  accountKey: string,
  now: number,
): boolean {
  const user = findByKey(topology.users, userKey);
  const asset = findByKey(topology.assets, assetKey);
  const account = findByKey(topology.accounts, accountKey);
  if (!user || !asset || !account) return false;
  if (user.status !== 'active') return false; // §31 step 2
  if (!asset.enabled) return false; // §31 step 3
  if (!account.enabled) return false; // §31 step 4
  if (account.assetKey !== asset.key) return false; // §31 step 7: account mapping
  return topology.rules.some(
    (rule) =>
      ruleInEffect(rule, now) && // §28, §31 step 6
      ruleGrantsAction(rule, 'connect') && // §27
      ruleCoversUser(rule, user) && // §24
      ruleTargetAssetKeys(topology, rule).has(asset.key) && // §25
      ruleCoversAccount(rule, account), // §26
  );
}

/**
 * Expected status of POST /api/sessions for a probe:
 * 401 without a valid login session (anonymous, or a disabled / locked user, §31 steps 1–2),
 * 201 when an allow rule matches, otherwise 403 (§29 Default Deny; unknown ids included).
 */
function oracle(topology: Topology, probe: SessionProbe, now: number): ExpectedSessionStatus {
  if (probe.userKey === null) return 401;
  const user = findByKey(topology.users, probe.userKey);
  if (!user || user.status !== 'active') return 401;
  if (probe.asset.kind !== 'key' || probe.account.kind !== 'key') return 403;
  return isConnectAuthorized(topology, probe.userKey, probe.asset.key, probe.account.key, now) ? 201 : 403;
}

/**
 * Expected GET /api/assets result (§30): only assets with at least one account the user may connect
 * to, each listing exactly those accounts. null means the request is expected to be 401.
 */
function oracleVisibleAssets(topology: Topology, userKey: string | null, now: number): Visibility | null {
  if (userKey === null) return null;
  const user = findByKey(topology.users, userKey);
  if (!user || user.status !== 'active') return null;
  const visible: Visibility = new Map();
  for (const account of topology.accounts) {
    if (!isConnectAuthorized(topology, userKey, account.assetKey, account.key, now)) continue;
    const accounts = visible.get(account.assetKey) ?? new Set<string>();
    accounts.add(account.key);
    visible.set(account.assetKey, accounts);
  }
  return visible;
}

/** Order-independent representation of a Visibility for deepEqual. */
function visibilityToRecord(visibility: Visibility | null): Record<string, string[]> | null {
  if (visibility === null) return null;
  const record: Record<string, string[]> = {};
  for (const assetKey of [...visibility.keys()].sort()) {
    record[assetKey] = [...(visibility.get(assetKey) ?? [])].sort();
  }
  return record;
}

// -------------------------------------------------------------
// Topology generator (design C6.5)
// -------------------------------------------------------------

/** valid_from / valid_until offsets relative to `now`: include 0 and ±1 ms boundaries; null = unbounded. */
const VALID_FROM_OFFSETS: readonly (number | null)[] = [null, null, -DAY_MS, -1, 0, 1, DAY_MS];
const VALID_UNTIL_OFFSETS: readonly (number | null)[] = [null, null, DAY_MS, 1, 0, -1, -DAY_MS];

/** Public IP literals only (TEST-NET ranges are rejected by the asset service). */
const PUBLIC_HOSTS: readonly string[] = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112'];
const ACCOUNT_USERNAMES: readonly string[] = ['root', 'deploy', 'admin', 'ops'];

function subset<T>(rng: Rng, items: readonly T[], p: number): T[] {
  return items.filter(() => rng.bool(p));
}

function shuffled<T>(rng: Rng, items: readonly T[]): T[] {
  const out = [...items];
  for (let i = out.length - 1; i > 0; i--) {
    const j = rng.int(0, i);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function offsetToTime(now: number, offset: number | null): number | null {
  return offset === null ? null : now + offset;
}

/** Action sets: empty (→ connect only), connect, connect + reserved, reserved only. */
function generateActions(rng: Rng): RuleAction[] {
  const r = rng.next();
  if (r < 0.25) return [];
  if (r < 0.6) return ['connect'];
  if (r < 0.8) return ['connect', rng.pick(NON_CONNECT_ACTIONS)];
  const first = rng.pick(NON_CONNECT_ACTIONS);
  const second = rng.pick(NON_CONNECT_ACTIONS);
  return first === second ? [first] : [first, second];
}

/**
 * Random topology: 2–4 users (u0 active, others active / disabled / locked), 1–3 user groups,
 * 1–4 asset groups forming a forest (parents always generated earlier), 2–4 assets (some disabled),
 * 1–3 accounts per asset (some disabled), 1–4 rules with random enabled flag, validity offsets
 * (0 / ±1 ms boundaries included), all_accounts and action sets (empty set included).
 */
function generateTopology(rng: Rng, now: number): Topology {
  const groupCount = rng.int(1, 3);
  const groups: TopoGroup[] = [];
  for (let i = 0; i < groupCount; i++) groups.push({ key: `g${i}` });
  const groupKeys = groups.map((g) => g.key);

  const userCount = rng.int(2, 4);
  const users: TopoUser[] = [];
  for (let i = 0; i < userCount; i++) {
    const status: UserStatus = i === 0 || rng.bool(0.6) ? 'active' : rng.pick(['disabled', 'locked'] as const);
    users.push({ key: `u${i}`, status, groupKeys: subset(rng, groupKeys, 0.5) });
  }

  const assetGroupCount = rng.int(1, 4);
  const assetGroups: TopoAssetGroup[] = [];
  for (let i = 0; i < assetGroupCount; i++) {
    const parentKey = i === 0 || rng.bool(0.4) ? null : rng.pick(assetGroups).key;
    assetGroups.push({ key: `ag${i}`, parentKey });
  }
  const assetGroupKeys = assetGroups.map((g) => g.key);

  const assetCount = rng.int(2, 4);
  const assets: TopoAsset[] = [];
  const accounts: TopoAccount[] = [];
  for (let i = 0; i < assetCount; i++) {
    const asset: TopoAsset = {
      key: `a${i}`,
      hostname: rng.pick(PUBLIC_HOSTS),
      port: rng.bool(0.5) ? 22 : rng.int(1024, 65535),
      enabled: rng.bool(0.8),
      groupKeys: subset(rng, assetGroupKeys, 0.45),
    };
    assets.push(asset);
    const usernames = shuffled(rng, ACCOUNT_USERNAMES).slice(0, rng.int(1, 3));
    for (const username of usernames) {
      accounts.push({ key: `${asset.key}.${username}`, assetKey: asset.key, username, enabled: rng.bool(0.8) });
    }
  }
  const userKeys = users.map((u) => u.key);
  const assetKeys = assets.map((a) => a.key);
  const accountKeys = accounts.map((a) => a.key);

  const topology: Topology = { generatedAt: now, users, groups, assetGroups, assets, accounts, rules: [] };

  const ruleCount = rng.int(1, 4);
  for (let i = 0; i < ruleCount; i++) {
    const rule: TopoRule = {
      key: `r${i}`,
      enabled: rng.bool(0.8),
      validFrom: offsetToTime(now, rng.pick(VALID_FROM_OFFSETS)),
      validUntil: offsetToTime(now, rng.pick(VALID_UNTIL_OFFSETS)),
      allAccounts: rng.bool(0.3),
      actions: generateActions(rng),
      userKeys: subset(rng, userKeys, 0.35),
      groupKeys: subset(rng, groupKeys, 0.4),
      assetKeys: subset(rng, assetKeys, 0.35),
      assetGroupKeys: subset(rng, assetGroupKeys, 0.35),
      accountKeys: subset(rng, accountKeys, 0.25),
    };
    // Bias toward meaningful rules; ~10% keep an empty subject / target to exercise Default Deny (§29).
    if (rule.userKeys.length + rule.groupKeys.length === 0 && rng.bool(0.9)) {
      if (rng.bool(0.5)) rule.userKeys.push(rng.pick(userKeys));
      else rule.groupKeys.push(rng.pick(groupKeys));
    }
    if (rule.assetKeys.length + rule.assetGroupKeys.length === 0 && rng.bool(0.9)) {
      if (rng.bool(0.5)) rule.assetKeys.push(rng.pick(assetKeys));
      else rule.assetGroupKeys.push(rng.pick(assetGroupKeys));
    }
    if (!rule.allAccounts && rng.bool(0.85)) {
      const targets = ruleTargetAssetKeys(topology, rule);
      const reachable = accounts.filter((a) => targets.has(a.assetKey) && !rule.accountKeys.includes(a.key));
      if (reachable.length > 0) rule.accountKeys.push(rng.pick(reachable).key);
    }
    topology.rules.push(rule);
  }
  return topology;
}

// -------------------------------------------------------------
// seedTopology fixture
// -------------------------------------------------------------

interface SeededTopology {
  topology: Topology;
  userIds: Map<string, string>;
  groupIds: Map<string, string>;
  assetGroupIds: Map<string, string>;
  assetIds: Map<string, string>;
  accountIds: Map<string, string>;
  ruleIds: Map<string, string>;
  assetKeyById: Map<string, string>;
  accountKeyById: Map<string, string>;
  /** userKey -> Cookie header value of an unexpired login session (also for disabled / locked users). */
  cookies: Map<string, string>;
  /** Shared password credential of every account (plaintext is not kept). */
  credentialId: string;
}

function idOf(ids: Map<string, string>, key: string): string {
  const id = ids.get(key);
  if (id === undefined) throw new Error(`seedTopology: unknown topology key ${key}`);
  return id;
}

async function insertRuleLinks(
  db: D1Database,
  table: string,
  column: string,
  ruleId: string,
  values: readonly string[],
): Promise<void> {
  for (const value of values) {
    await db.prepare(`INSERT INTO ${table} (rule_id, ${column}) VALUES (?, ?)`).bind(ruleId, value).run();
  }
}

/**
 * Writes `topology` into ctx.db respecting foreign keys:
 * users (+ cookies) → user groups → group members → credential → asset groups (parents first)
 * → assets (+ group members) → accounts → rules → rule link tables.
 */
async function seedTopology(ctx: ComplianceContext, topology: Topology): Promise<SeededTopology> {
  const db = ctx.db;
  const tag = randomUUID().slice(0, 8);
  const now = Date.now();
  const seeded: SeededTopology = {
    topology,
    userIds: new Map(),
    groupIds: new Map(),
    assetGroupIds: new Map(),
    assetIds: new Map(),
    accountIds: new Map(),
    ruleIds: new Map(),
    assetKeyById: new Map(),
    accountKeyById: new Map(),
    cookies: new Map(),
    credentialId: '',
  };

  for (const user of topology.users) {
    const row = await insertUser(db, { username: `acl-${tag}-${user.key}`, status: user.status, roles: ['User'] });
    seeded.userIds.set(user.key, row.id);
    seeded.cookies.set(user.key, await issueCookie(db, row.id));
  }

  for (const group of topology.groups) {
    const id = `grp_${randomUUID()}`;
    await db
      .prepare('INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, NULL, ?, ?)')
      .bind(id, `acl-${tag}-${group.key}`, now, now)
      .run();
    seeded.groupIds.set(group.key, id);
  }
  for (const user of topology.users) {
    for (const groupKey of user.groupKeys) {
      await db
        .prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)')
        .bind(idOf(seeded.groupIds, groupKey), idOf(seeded.userIds, user.key), now)
        .run();
    }
  }

  const credential = await createCredential(
    { name: `acl-${tag}-cred`, type: 'password', secret: `EJ-ACL-${randomUUID()}` },
    ctx.kek,
    db,
  );
  seeded.credentialId = credential.id;

  const pending = [...topology.assetGroups];
  while (pending.length > 0) {
    const index = pending.findIndex((g) => g.parentKey === null || seeded.assetGroupIds.has(g.parentKey));
    if (index < 0) throw new Error('seedTopology: asset group tree has a cycle or a dangling parent');
    const [group] = pending.splice(index, 1);
    const created = await createAssetGroup(
      {
        name: `acl-${tag}-${group.key}`,
        parentId: group.parentKey === null ? null : idOf(seeded.assetGroupIds, group.parentKey),
      },
      db,
    );
    seeded.assetGroupIds.set(group.key, created.id);
  }

  for (const asset of topology.assets) {
    const created = await createAsset(
      {
        name: `acl-${tag}-${asset.key}`,
        hostname: asset.hostname,
        port: asset.port,
        platform: 'linux',
        environment: 'production',
        enabled: asset.enabled,
        groupIds: asset.groupKeys.map((key) => idOf(seeded.assetGroupIds, key)),
      },
      'compliance-test',
      db,
    );
    seeded.assetIds.set(asset.key, created.id);
    seeded.assetKeyById.set(created.id, asset.key);
  }

  for (const account of topology.accounts) {
    const created = await createAssetAccount(
      {
        assetId: idOf(seeded.assetIds, account.assetKey),
        username: account.username,
        credentialId: credential.id,
        enabled: account.enabled,
      },
      db,
    );
    seeded.accountIds.set(account.key, created.id);
    seeded.accountKeyById.set(created.id, account.key);
  }

  for (const rule of topology.rules) {
    const id = `rule_${randomUUID()}`;
    await db
      .prepare(
        `INSERT INTO authorization_rules (
           id, name, description, all_accounts, enabled, valid_from, valid_until, created_at, updated_at, created_by
         ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'compliance-test')`
      )
      .bind(
        id,
        `acl-${tag}-${rule.key}`,
        rule.allAccounts ? 1 : 0,
        rule.enabled ? 1 : 0,
        rule.validFrom,
        rule.validUntil,
        now,
        now
      )
      .run();
    seeded.ruleIds.set(rule.key, id);
    await insertRuleLinks(db, 'authorization_rule_users', 'user_id', id, rule.userKeys.map((k) => idOf(seeded.userIds, k)));
    await insertRuleLinks(db, 'authorization_rule_groups', 'group_id', id, rule.groupKeys.map((k) => idOf(seeded.groupIds, k)));
    await insertRuleLinks(db, 'authorization_rule_assets', 'asset_id', id, rule.assetKeys.map((k) => idOf(seeded.assetIds, k)));
    await insertRuleLinks(
      db,
      'authorization_rule_asset_groups',
      'asset_group_id',
      id,
      rule.assetGroupKeys.map((k) => idOf(seeded.assetGroupIds, k)),
    );
    await insertRuleLinks(
      db,
      'authorization_rule_accounts',
      'account_id',
      id,
      rule.accountKeys.map((k) => idOf(seeded.accountIds, k)),
    );
    await insertRuleLinks(db, 'authorization_rule_actions', 'action', id, rule.actions);
  }

  return seeded;
}

// -------------------------------------------------------------
// Probe builders and request helpers
// -------------------------------------------------------------

function refLabel(ref: IdRef): string {
  return ref.kind === 'key' ? ref.key : `随机ID(${ref.raw})`;
}

function probeLabel(userKey: string | null, asset: IdRef, account: IdRef, note: string = ''): string {
  return `[SEC-06][SEC-07] ${userKey ?? '匿名'} → ${refLabel(asset)} / ${refLabel(account)}${note}`;
}

/** Every asset × every account of the topology (cross-asset pairs included) for one user. */
function pairProbes(topology: Topology, userKey: string | null): SessionProbe[] {
  const probes: SessionProbe[] = [];
  for (const asset of topology.assets) {
    for (const account of topology.accounts) {
      const note = account.assetKey === asset.key ? '' : '（跨资产账号）';
      probes.push({
        userKey,
        asset: keyRef(asset.key),
        account: keyRef(account.key),
        label: probeLabel(userKey, keyRef(asset.key), keyRef(account.key), note),
      });
    }
  }
  return probes;
}

function randomId(rng: Rng, prefix: string): string {
  return `${prefix}${rng.hex(4)}-${rng.hex(2)}-${rng.hex(2)}-${rng.hex(2)}-${rng.hex(6)}`;
}

/** Tampered combinations: random asset id, random account id, or both (§84 IDOR / §92-7). */
function tamperedProbes(rng: Rng, topology: Topology, userKey: string | null, count: number): SessionProbe[] {
  const probes: SessionProbe[] = [];
  for (let i = 0; i < count; i++) {
    const realAsset = keyRef(rng.pick(topology.assets).key);
    const realAccount = keyRef(rng.pick(topology.accounts).key);
    const fakeAsset = rawRef(randomId(rng, rng.pick(['asset_', ''])));
    const fakeAccount = rawRef(randomId(rng, rng.pick(['acc_', ''])));
    const variant = rng.int(0, 2);
    const asset = variant === 1 ? realAsset : fakeAsset;
    const account = variant === 0 ? realAccount : fakeAccount;
    probes.push({ userKey, asset, account, label: probeLabel(userKey, asset, account, '（篡改ID）') });
  }
  return probes;
}

function resolveRef(ids: Map<string, string>, ref: IdRef): string {
  return ref.kind === 'raw' ? ref.raw : idOf(ids, ref.key);
}

/** POST /api/sessions body with the implementation's field names (L19: assetId / accountId). */
function sessionRequestBody(seeded: SeededTopology, probe: SessionProbe): { assetId: string; accountId: string } {
  return {
    assetId: resolveRef(seeded.assetIds, probe.asset),
    accountId: resolveRef(seeded.accountIds, probe.account),
  };
}

function cookieFor(seeded: SeededTopology, userKey: string | null): string | null {
  return userKey === null ? null : (seeded.cookies.get(userKey) ?? null);
}

async function postSession(ctx: ComplianceContext, seeded: SeededTopology, probe: SessionProbe): Promise<ApiResult> {
  return api(ctx, 'POST', '/api/sessions', {
    cookie: cookieFor(seeded, probe.userKey),
    body: sessionRequestBody(seeded, probe),
  });
}

/** Maps a GET /api/assets response back to topology keys (unknown ids stay visible as `unknown:<id>`). */
function visibilityFromResponse(seeded: SeededTopology, json: unknown): Visibility {
  const visibility: Visibility = new Map();
  if (!Array.isArray(json)) return visibility;
  for (const asset of json as Array<{ id?: unknown; accounts?: unknown }>) {
    const assetId = String(asset?.id);
    const assetKey = seeded.assetKeyById.get(assetId) ?? `unknown:${assetId}`;
    const accounts = visibility.get(assetKey) ?? new Set<string>();
    if (Array.isArray(asset?.accounts)) {
      for (const account of asset.accounts as Array<{ id?: unknown }>) {
        const accountId = String(account?.id);
        accounts.add(seeded.accountKeyById.get(accountId) ?? `unknown:${accountId}`);
      }
    }
    visibility.set(assetKey, accounts);
  }
  return visibility;
}

async function getVisibleAssets(
  ctx: ComplianceContext,
  seeded: SeededTopology,
  userKey: string | null,
): Promise<{ result: ApiResult; visibility: Visibility | null }> {
  const result = await api(ctx, 'GET', '/api/assets', { cookie: cookieFor(seeded, userKey) });
  return { result, visibility: result.status === 200 ? visibilityFromResponse(seeded, result.json) : null };
}

async function withContext<T>(fn: (ctx: ComplianceContext) => Promise<T>): Promise<T> {
  const ctx = await createContext();
  try {
    return await fn(ctx);
  } finally {
    await ctx.cleanup();
  }
}

// -------------------------------------------------------------
// Handcrafted topologies
// -------------------------------------------------------------

/** Minimal positive-control topology: alice → web (direct) → deploy → connect, no time window. */
function positiveControlTopology(now: number): Topology {
  return {
    generatedAt: now,
    users: [{ key: 'alice', status: 'active', groupKeys: [] }],
    groups: [],
    assetGroups: [{ key: 'prod', parentKey: null }],
    assets: [{ key: 'web', hostname: '8.8.8.8', port: 22, enabled: true, groupKeys: ['prod'] }],
    accounts: [
      { key: 'web.deploy', assetKey: 'web', username: 'deploy', enabled: true },
      { key: 'web.root', assetKey: 'web', username: 'root', enabled: true },
    ],
    rules: [makeRule({ key: 'r-direct', userKeys: ['alice'], assetKeys: ['web'], accountKeys: ['web.deploy'] })],
  };
}

/** Oracle self-check topology covering every §23–§31 dimension. */
function handcraftedTopology(now: number): Topology {
  return {
    generatedAt: now,
    users: [
      { key: 'alice', status: 'active', groupKeys: ['dev'] },
      { key: 'bob', status: 'active', groupKeys: [] },
      { key: 'carol', status: 'disabled', groupKeys: ['dev'] },
      { key: 'dave', status: 'locked', groupKeys: ['dev'] },
      { key: 'erin', status: 'active', groupKeys: ['ops'] },
    ],
    groups: [{ key: 'dev' }, { key: 'ops' }],
    assetGroups: [
      { key: 'prod', parentKey: null },
      { key: 'prod-web', parentKey: 'prod' },
      { key: 'staging', parentKey: null },
    ],
    assets: [
      { key: 'web', hostname: '8.8.8.8', port: 22, enabled: true, groupKeys: ['prod-web'] },
      { key: 'db', hostname: '1.1.1.1', port: 2222, enabled: true, groupKeys: ['prod'] },
      { key: 'stg', hostname: '9.9.9.9', port: 22, enabled: true, groupKeys: ['staging'] },
      { key: 'off', hostname: '8.8.4.4', port: 22, enabled: false, groupKeys: ['prod-web'] },
    ],
    accounts: [
      { key: 'web.deploy', assetKey: 'web', username: 'deploy', enabled: true },
      { key: 'web.root', assetKey: 'web', username: 'root', enabled: true },
      { key: 'web.old', assetKey: 'web', username: 'old', enabled: false },
      { key: 'db.dba', assetKey: 'db', username: 'dba', enabled: true },
      { key: 'stg.deploy', assetKey: 'stg', username: 'deploy', enabled: true },
      { key: 'stg.admin', assetKey: 'stg', username: 'admin', enabled: true },
      { key: 'off.deploy', assetKey: 'off', username: 'deploy', enabled: true },
    ],
    rules: [
      makeRule({ key: 'r-direct', userKeys: ['bob'], assetKeys: ['stg'], accountKeys: ['stg.deploy'] }),
      makeRule({
        key: 'r-group-tree',
        groupKeys: ['dev'],
        assetGroupKeys: ['prod'],
        accountKeys: ['web.deploy', 'web.old', 'off.deploy', 'stg.admin'],
        actions: ['connect'],
      }),
      makeRule({ key: 'r-all', userKeys: ['erin'], assetKeys: ['web'], allAccounts: true, actions: ['connect', 'sftp_read'] }),
      makeRule({ key: 'r-sftp-only', userKeys: ['bob'], assetKeys: ['db'], accountKeys: ['db.dba'], actions: ['sftp_read'] }),
      makeRule({ key: 'r-disabled', userKeys: ['bob'], assetKeys: ['web'], accountKeys: ['web.root'], enabled: false }),
      makeRule({ key: 'r-window', userKeys: ['erin'], assetKeys: ['stg'], accountKeys: ['stg.deploy'], validFrom: now, validUntil: now }),
      makeRule({ key: 'r-expired', userKeys: ['erin'], assetKeys: ['db'], accountKeys: ['db.dba'], validUntil: now - 1 }),
      makeRule({ key: 'r-future', userKeys: ['erin'], assetKeys: ['stg'], accountKeys: ['stg.admin'], validFrom: now + 1 }),
      makeRule({ key: 'r-no-subject', assetKeys: ['db'], accountKeys: ['db.dba'] }),
    ],
  };
}

// -------------------------------------------------------------
// Generator / fixture self-check helpers
// -------------------------------------------------------------

function assertTopologyWellFormed(topology: Topology): void {
  const where = `拓扑生成器自检失败：${describeTopology(topology)}`;
  const inRange = (n: number, min: number, max: number): boolean => n >= min && n <= max;
  assert.ok(inRange(topology.users.length, 2, 4), `${where}（用户数）`);
  assert.ok(inRange(topology.groups.length, 1, 3), `${where}（用户组数）`);
  assert.ok(inRange(topology.assetGroups.length, 1, 4), `${where}（资产组数）`);
  assert.ok(inRange(topology.assets.length, 2, 4), `${where}（资产数）`);
  assert.ok(inRange(topology.rules.length, 1, 4), `${where}（规则数）`);

  const allKeys = [
    ...topology.users,
    ...topology.groups,
    ...topology.assetGroups,
    ...topology.assets,
    ...topology.accounts,
    ...topology.rules,
  ].map((item) => item.key);
  assert.equal(new Set(allKeys).size, allKeys.length, `${where}（键重复）`);

  const groupKeys = new Set(topology.groups.map((g) => g.key));
  const userKeys = new Set(topology.users.map((u) => u.key));
  const assetKeys = new Set(topology.assets.map((a) => a.key));
  const accountKeys = new Set(topology.accounts.map((a) => a.key));
  const seenAssetGroups = new Set<string>();
  for (const group of topology.assetGroups) {
    assert.ok(group.parentKey === null || seenAssetGroups.has(group.parentKey), `${where}（资产组父节点须先生成）`);
    seenAssetGroups.add(group.key);
  }
  for (const user of topology.users) {
    assert.ok(user.groupKeys.every((k) => groupKeys.has(k)), `${where}（用户组引用）`);
  }
  for (const asset of topology.assets) {
    assert.ok(asset.groupKeys.every((k) => seenAssetGroups.has(k)), `${where}（资产组引用）`);
    const own = topology.accounts.filter((a) => a.assetKey === asset.key);
    assert.ok(inRange(own.length, 1, 3), `${where}（每资产账号数）`);
    assert.equal(new Set(own.map((a) => a.username)).size, own.length, `${where}（同资产账号名重复）`);
  }
  for (const rule of topology.rules) {
    assert.ok(rule.userKeys.every((k) => userKeys.has(k)), `${where}（规则用户引用）`);
    assert.ok(rule.groupKeys.every((k) => groupKeys.has(k)), `${where}（规则用户组引用）`);
    assert.ok(rule.assetKeys.every((k) => assetKeys.has(k)), `${where}（规则资产引用）`);
    assert.ok(rule.assetGroupKeys.every((k) => seenAssetGroups.has(k)), `${where}（规则资产组引用）`);
    assert.ok(rule.accountKeys.every((k) => accountKeys.has(k)), `${where}（规则账号引用）`);
    assert.equal(new Set(rule.actions).size, rule.actions.length, `${where}（动作重复）`);
    assert.ok(rule.actions.every((a) => (RULE_ACTIONS as readonly string[]).includes(a)), `${where}（动作取值）`);
  }
}

/** Boundary features the generator must reach across PROPERTY_RUNS topologies (design C6.5). */
const REQUIRED_FEATURES: readonly string[] = [
  'user:disabled',
  'user:locked',
  'user:multi-group',
  'asset:disabled',
  'asset:no-group',
  'account:disabled',
  'asset-group:nested',
  'rule:disabled',
  'rule:all-accounts',
  'rule:explicit-accounts',
  'rule:empty-actions',
  'rule:no-connect-action',
  'rule:cross-target-account',
  'rule:no-subject',
  'validFrom:null',
  'validFrom:-1',
  'validFrom:0',
  'validFrom:+1',
  'validUntil:null',
  'validUntil:-1',
  'validUntil:0',
  'validUntil:+1',
];

function offsetFeature(prefix: string, value: number | null, now: number): string | null {
  if (value === null) return `${prefix}:null`;
  const offset = value - now;
  if (offset === 0) return `${prefix}:0`;
  if (offset === 1) return `${prefix}:+1`;
  if (offset === -1) return `${prefix}:-1`;
  return null;
}

function collectFeatures(topology: Topology, seen: Set<string>): void {
  for (const user of topology.users) {
    if (user.status !== 'active') seen.add(`user:${user.status}`);
    if (user.groupKeys.length > 1) seen.add('user:multi-group');
  }
  for (const asset of topology.assets) {
    if (!asset.enabled) seen.add('asset:disabled');
    if (asset.groupKeys.length === 0) seen.add('asset:no-group');
  }
  if (topology.accounts.some((a) => !a.enabled)) seen.add('account:disabled');
  if (topology.assetGroups.some((g) => g.parentKey !== null)) seen.add('asset-group:nested');
  for (const rule of topology.rules) {
    if (!rule.enabled) seen.add('rule:disabled');
    seen.add(rule.allAccounts ? 'rule:all-accounts' : 'rule:explicit-accounts');
    if (rule.actions.length === 0) seen.add('rule:empty-actions');
    if (rule.actions.length > 0 && !rule.actions.includes('connect')) seen.add('rule:no-connect-action');
    if (rule.userKeys.length + rule.groupKeys.length === 0) seen.add('rule:no-subject');
    const targets = ruleTargetAssetKeys(topology, rule);
    const crossTarget = rule.accountKeys.some((key) => {
      const account = findByKey(topology.accounts, key);
      return account !== undefined && !targets.has(account.assetKey);
    });
    if (crossTarget) seen.add('rule:cross-target-account');
    const from = offsetFeature('validFrom', rule.validFrom, topology.generatedAt);
    const until = offsetFeature('validUntil', rule.validUntil, topology.generatedAt);
    if (from) seen.add(from);
    if (until) seen.add(until);
  }
}

async function selectValues(db: D1Database, sql: string, param: string): Promise<string[]> {
  const { results } = await db.prepare(sql).bind(param).all<{ v: unknown }>();
  return (results ?? []).map((row) => String(row.v)).sort();
}

function sortedIds(ids: Map<string, string>, keys: readonly string[]): string[] {
  return keys.map((key) => idOf(ids, key)).sort();
}

/** Reads the seeded rows back and compares them with the topology (fixture fidelity). */
async function assertSeededMatches(ctx: ComplianceContext, seeded: SeededTopology): Promise<void> {
  const db = ctx.db;
  const { topology } = seeded;
  const fail = (what: string): string => `seedTopology 自检失败：${what}`;

  for (const user of topology.users) {
    const userId = idOf(seeded.userIds, user.key);
    const row = await db.prepare('SELECT status FROM users WHERE id = ?').bind(userId).first<{ status: string }>();
    assert.equal(row?.status, user.status, fail(`${user.key} 状态`));
    assert.deepEqual(
      await selectValues(db, 'SELECT group_id AS v FROM group_members WHERE user_id = ?', userId),
      sortedIds(seeded.groupIds, user.groupKeys),
      fail(`${user.key} 用户组成员`),
    );
  }
  for (const group of topology.assetGroups) {
    const row = await db
      .prepare('SELECT parent_id FROM asset_groups WHERE id = ?')
      .bind(idOf(seeded.assetGroupIds, group.key))
      .first<{ parent_id: string | null }>();
    const expected = group.parentKey === null ? null : idOf(seeded.assetGroupIds, group.parentKey);
    assert.equal(row?.parent_id ?? null, expected, fail(`${group.key} parent_id`));
  }
  for (const asset of topology.assets) {
    const assetId = idOf(seeded.assetIds, asset.key);
    const row = await db
      .prepare('SELECT hostname, port, enabled FROM assets WHERE id = ?')
      .bind(assetId)
      .first<{ hostname: string; port: number; enabled: number }>();
    assert.deepEqual(
      row ? { hostname: row.hostname, port: Number(row.port), enabled: Number(row.enabled) } : null,
      { hostname: asset.hostname, port: asset.port, enabled: asset.enabled ? 1 : 0 },
      fail(`${asset.key} 资产字段`),
    );
    assert.deepEqual(
      await selectValues(db, 'SELECT group_id AS v FROM asset_group_members WHERE asset_id = ?', assetId),
      sortedIds(seeded.assetGroupIds, asset.groupKeys),
      fail(`${asset.key} 资产组成员`),
    );
  }
  for (const account of topology.accounts) {
    const row = await db
      .prepare('SELECT asset_id, username, enabled FROM asset_accounts WHERE id = ?')
      .bind(idOf(seeded.accountIds, account.key))
      .first<{ asset_id: string; username: string; enabled: number }>();
    assert.deepEqual(
      row ? { assetId: row.asset_id, username: row.username, enabled: Number(row.enabled) } : null,
      { assetId: idOf(seeded.assetIds, account.assetKey), username: account.username, enabled: account.enabled ? 1 : 0 },
      fail(`${account.key} 账号字段`),
    );
  }
  for (const rule of topology.rules) {
    const ruleId = idOf(seeded.ruleIds, rule.key);
    const row = await db
      .prepare('SELECT enabled, all_accounts, valid_from, valid_until FROM authorization_rules WHERE id = ?')
      .bind(ruleId)
      .first<{ enabled: number; all_accounts: number; valid_from: number | null; valid_until: number | null }>();
    assert.deepEqual(
      row
        ? {
            enabled: Number(row.enabled),
            allAccounts: Number(row.all_accounts),
            validFrom: row.valid_from === null ? null : Number(row.valid_from),
            validUntil: row.valid_until === null ? null : Number(row.valid_until),
          }
        : null,
      {
        enabled: rule.enabled ? 1 : 0,
        allAccounts: rule.allAccounts ? 1 : 0,
        validFrom: rule.validFrom,
        validUntil: rule.validUntil,
      },
      fail(`${rule.key} 规则字段`),
    );
    const links: Array<[string, string[]]> = [
      ['SELECT user_id AS v FROM authorization_rule_users WHERE rule_id = ?', sortedIds(seeded.userIds, rule.userKeys)],
      ['SELECT group_id AS v FROM authorization_rule_groups WHERE rule_id = ?', sortedIds(seeded.groupIds, rule.groupKeys)],
      ['SELECT asset_id AS v FROM authorization_rule_assets WHERE rule_id = ?', sortedIds(seeded.assetIds, rule.assetKeys)],
      [
        'SELECT asset_group_id AS v FROM authorization_rule_asset_groups WHERE rule_id = ?',
        sortedIds(seeded.assetGroupIds, rule.assetGroupKeys),
      ],
      ['SELECT account_id AS v FROM authorization_rule_accounts WHERE rule_id = ?', sortedIds(seeded.accountIds, rule.accountKeys)],
      ['SELECT action AS v FROM authorization_rule_actions WHERE rule_id = ?', [...rule.actions].sort()],
    ];
    for (const [sql, expected] of links) {
      assert.deepEqual(await selectValues(db, sql, ruleId), expected, fail(`${rule.key} 关联表 ${sql.split(' ')[5]}`));
    }
  }
}

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

describe('compliance-access-control: SEC-05 / SEC-06 / SEC-07（AGENTS.md §23–§31、§84）', () => {
  describe('参考模型与夹具自检', () => {
    it('[SEC-06] 参考模型自检：手工拓扑的会话判定符合 §23–§31', () => {
      const now = FIXED_NOW;
      const topology = handcraftedTopology(now);
      const p = (userKey: string | null, asset: IdRef, account: IdRef): SessionProbe => ({
        userKey,
        asset,
        account,
        label: probeLabel(userKey, asset, account),
      });
      const cases: Array<[SessionProbe, number, ExpectedSessionStatus, string]> = [
        [p('alice', keyRef('web'), keyRef('web.deploy')), now, 201, '§24 用户组 + §25 子孙资产组 + §27 空动作集仅授予 connect'],
        [p('alice', keyRef('web'), keyRef('web.root')), now, 403, '§26 未显式授权的账号'],
        [p('alice', keyRef('web'), keyRef('web.old')), now, 403, '§31 第 4 步 账号停用'],
        [p('alice', keyRef('off'), keyRef('off.deploy')), now, 403, '§31 第 3 步 资产停用'],
        [p('alice', keyRef('stg'), keyRef('stg.admin')), now, 403, '§25 账号在规则中但资产不在目标内'],
        [p('alice', keyRef('web'), keyRef('stg.deploy')), now, 403, '§31 第 7 步 跨资产账号'],
        [p('alice', keyRef('db'), keyRef('db.dba')), now, 403, '§29 无主体规则不授予任何人'],
        [p('alice', rawRef('asset_does-not-exist'), keyRef('web.deploy')), now, 403, '§84 不存在的资产 ID'],
        [p('alice', keyRef('web'), rawRef('acc_does-not-exist')), now, 403, '§84 不存在的账号 ID'],
        [p('bob', keyRef('stg'), keyRef('stg.deploy')), now, 201, '§24 直接用户授权'],
        [p('bob', keyRef('db'), keyRef('db.dba')), now, 403, '§27 动作集不含 connect'],
        [p('bob', keyRef('web'), keyRef('web.root')), now, 403, '§28 规则停用'],
        [p('erin', keyRef('web'), keyRef('web.root')), now, 201, 'EXT-003 @ALL 覆盖目标资产全部账号'],
        [p('erin', keyRef('web'), keyRef('web.deploy')), now, 201, 'EXT-003 @ALL'],
        [p('erin', keyRef('web'), keyRef('web.old')), now, 403, '@ALL 不覆盖停用账号'],
        [p('erin', keyRef('db'), keyRef('db.dba')), now, 403, '§28 已过期（valid_until = now - 1）'],
        [p('erin', keyRef('stg'), keyRef('stg.deploy')), now, 201, '§28 闭区间 valid_from = valid_until = now'],
        [p('erin', keyRef('stg'), keyRef('stg.deploy')), now + 1, 403, '§28 越过 valid_until 1 ms'],
        [p('erin', keyRef('stg'), keyRef('stg.deploy')), now - 1, 403, '§28 早于 valid_from 1 ms'],
        [p('erin', keyRef('stg'), keyRef('stg.admin')), now, 403, '§28 未生效（valid_from = now + 1）'],
        [p('erin', keyRef('stg'), keyRef('stg.admin')), now + 1, 201, '§28 到达 valid_from'],
        [p('carol', keyRef('web'), keyRef('web.deploy')), now, 401, '§31 第 2 步 disabled 用户'],
        [p('dave', keyRef('web'), keyRef('web.deploy')), now, 401, '§31 第 2 步 locked 用户'],
        [p(null, keyRef('web'), keyRef('web.deploy')), now, 401, '§31 第 1 步 无登录会话'],
      ];
      for (const [probe, at, expected, why] of cases) {
        assert.equal(oracle(topology, probe, at), expected, `参考模型自检失败：${probe.label} @${at - now}ms（${why}）`);
      }
    });

    it('[SEC-05] 参考模型自检：可见资产只含授权资产与授权账号（§30）', () => {
      const now = FIXED_NOW;
      const topology = handcraftedTopology(now);
      const expectations: Array<[string | null, number, Record<string, string[]> | null]> = [
        ['alice', now, { web: ['web.deploy'] }],
        ['bob', now, { stg: ['stg.deploy'] }],
        ['erin', now, { stg: ['stg.deploy'], web: ['web.deploy', 'web.root'] }],
        ['erin', now + 1, { stg: ['stg.admin'], web: ['web.deploy', 'web.root'] }],
        ['carol', now, null],
        ['dave', now, null],
        [null, now, null],
      ];
      for (const [userKey, at, expected] of expectations) {
        assert.deepEqual(
          visibilityToRecord(oracleVisibleAssets(topology, userKey, at)),
          expected,
          `参考模型自检失败：${userKey ?? '匿名'} @${at - now}ms 的可见资产`,
        );
      }
    });

    it('[SEC-06] 拓扑生成器自检：规模、结构与边界覆盖', { timeout: 60_000 }, async () => {
      const seen = new Set<string>();
      const statusCounts: Record<ExpectedSessionStatus, number> = { 201: 0, 401: 0, 403: 0 };
      let crossAssetProbes = 0;
      let tamperedGranted = 0;
      await forAll(
        (rng) => {
          const topology = generateTopology(rng, FIXED_NOW);
          return { topology, tampered: tamperedProbes(rng, topology, 'u0', 4) };
        },
        async ({ topology, tampered }) => {
          assertTopologyWellFormed(topology);
          collectFeatures(topology, seen);
          for (const userKey of [...topology.users.map((u) => u.key), null]) {
            for (const probe of pairProbes(topology, userKey)) {
              statusCounts[oracle(topology, probe, FIXED_NOW)]++;
              if (probe.label.includes('跨资产')) crossAssetProbes++;
            }
          }
          for (const probe of tampered) {
            if (oracle(topology, probe, FIXED_NOW) === 201) tamperedGranted++;
          }
        },
        { runs: PROPERTY_RUNS, seed: seedFromEnv() },
      );
      const missing = REQUIRED_FEATURES.filter((feature) => !seen.has(feature));
      assert.deepEqual(missing, [], `拓扑生成器未覆盖的边界：${missing.join(', ')}`);
      assert.ok(statusCounts[201] > 0, '拓扑生成器自检失败：参考模型从未得出 201（属性将退化为全拒绝）');
      assert.ok(statusCounts[403] > 0, '拓扑生成器自检失败：参考模型从未得出 403');
      assert.ok(statusCounts[401] > 0, '拓扑生成器自检失败：参考模型从未得出 401');
      assert.ok(crossAssetProbes > 0, '拓扑生成器自检失败：未生成跨资产账号组合');
      assert.equal(tamperedGranted, 0, '参考模型自检失败：篡改 ID 组合被判为 201');
    });

    it('[SEC-06] seedTopology 自检：写入 D1 的状态与拓扑一致（含空动作集）', { timeout: 60_000 }, async () => {
      // The handcrafted topology always contains an empty action set (r-group-tree), a nested asset
      // group, disabled / locked users and boundary validity values.
      await withContext(async (ctx) => {
        await assertSeededMatches(ctx, await seedTopology(ctx, handcraftedTopology(FIXED_NOW)));
      });
      await forAll(
        (rng) => generateTopology(rng, FIXED_NOW),
        async (topology) => {
          await withContext(async (ctx) => {
            await assertSeededMatches(ctx, await seedTopology(ctx, topology));
          });
        },
        { runs: 10, seed: seedFromEnv() },
      );
    });
  });

  describe('正向对照（D9）', () => {
    it('[SEC-05] 正向对照：被授权用户的可见资产非空且包含授权账号', async () => {
      await withContext(async (ctx) => {
        const now = Date.now();
        const topology = positiveControlTopology(now);
        const seeded = await seedTopology(ctx, topology);
        const expected = oracleVisibleAssets(topology, 'alice', now);
        assert.ok(expected !== null && expected.size > 0, '正向对照失败：参考模型对授权用户给出空可见集');

        const { result, visibility } = await getVisibleAssets(ctx, seeded, 'alice');
        assert.equal(result.status, 200, `正向对照失败：GET /api/assets 返回 ${result.status}`);
        assert.ok(visibility !== null && visibility.size > 0, '正向对照失败：被授权用户的可见资产为空');
        assert.ok(visibility.get('web')?.has('web.deploy'), '正向对照失败：可见资产不含被授权的 web / deploy');
      });
    });

    it('[SEC-06] 正向对照：被授权用户创建会话得到 201', async () => {
      await withContext(async (ctx) => {
        const now = Date.now();
        const topology = positiveControlTopology(now);
        const seeded = await seedTopology(ctx, topology);
        const probe: SessionProbe = {
          userKey: 'alice',
          asset: keyRef('web'),
          account: keyRef('web.deploy'),
          label: probeLabel('alice', keyRef('web'), keyRef('web.deploy')),
        };
        assert.equal(oracle(topology, probe, now), 201, '正向对照失败：参考模型未授权该组合');

        const res = await postSession(ctx, seeded, probe);
        assert.equal(res.status, 201, `正向对照失败：POST /api/sessions 返回 ${res.status}`);
        const sessionId: unknown = res.json?.sessionId;
        assert.ok(typeof sessionId === 'string' && sessionId.length > 0, '正向对照失败：响应缺少 sessionId');
        assert.ok(typeof res.json?.ticket === 'string' && res.json.ticket.length > 0, '正向对照失败：响应缺少 ticket');

        const row = await ctx.db
          .prepare('SELECT user_id, asset_id, account_id FROM ssh_sessions WHERE id = ?')
          .bind(sessionId)
          .first<{ user_id: string; asset_id: string; account_id: string }>();
        assert.deepEqual(
          row ? { userId: row.user_id, assetId: row.asset_id, accountId: row.account_id } : null,
          {
            userId: idOf(seeded.userIds, 'alice'),
            assetId: idOf(seeded.assetIds, 'web'),
            accountId: idOf(seeded.accountIds, 'web.deploy'),
          },
          '正向对照失败：ssh_sessions 记录与请求不一致',
        );
        const initCalls = ctx.sessions.calls.filter(
          (call) => call.path === '/init' && (call.body as { sessionId?: unknown } | null)?.sessionId === sessionId,
        );
        assert.equal(initCalls.length, 1, '正向对照失败：SSHSessionDO 未收到该会话的 /init');
      });
    });
  });

  // Feature: v1-compliance-review, Property 2: 授权结果与参考模型等价
  //
  // Every iteration seeds a fresh random topology (generateTopology) into a fresh context and compares
  // the implementation with the reference model at the fixed instant FIXED_NOW. Date is mocked BEFORE
  // seeding so login cookies (expires_at = FIXED_NOW + 8 h), validity windows and Date.now() inside
  // validateSession / createSession / the resolvers all refer to the same instant; only Date is mocked,
  // real timers and immediates (flushAsync, DO cleanup) keep working. All failure messages carry the
  // secret-free describeTopology() output and the probe label, never credential values.
  describe('Property 2: 授权结果与参考模型等价（§23–§31）', () => {
    it(
      '[SEC-05] 授权结果与参考模型等价：GET /api/assets 与 /api/assets/:id/accounts 的可见资产与账号集合',
      { timeout: 60_000 },
      async (t) => {
        t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
        let nonEmptyVisibility = 0;
        let unauthenticated = 0;
        await forAll(
          (rng) => {
            const topology = generateTopology(rng, FIXED_NOW);
            return { topology, randomAssetId: randomId(rng, rng.pick(['asset_', ''])) };
          },
          async ({ topology, randomAssetId }) => {
            await withContext(async (ctx) => {
              const seeded = await seedTopology(ctx, topology);
              const where = `拓扑=${describeTopology(topology)}`;
              for (const userKey of [...topology.users.map((u) => u.key), null]) {
                const who = userKey ?? '匿名';
                const expected = oracleVisibleAssets(topology, userKey, FIXED_NOW);
                const expectedStatus = expected === null ? 401 : 200;

                // §30: GET /api/assets lists exactly the authorized assets and accounts.
                const { result, visibility } = await getVisibleAssets(ctx, seeded, userKey);
                assert.equal(
                  result.status,
                  expectedStatus,
                  `[判定] GET /api/assets 状态码与参考模型不一致：[SEC-05] ${who}（期望 ${expectedStatus}，实际 ${result.status}${result.threw ? '，处理器抛出未捕获异常' : ''}）；${where}`,
                );
                if (expected === null) {
                  unauthenticated++;
                } else {
                  if (expected.size > 0) nonEmptyVisibility++;
                  assert.deepEqual(
                    visibilityToRecord(visibility),
                    visibilityToRecord(expected),
                    `[判定] GET /api/assets 可见资产 / 账号集合与参考模型不一致：[SEC-05] ${who}，期望 ${JSON.stringify(visibilityToRecord(expected))}，实际 ${JSON.stringify(visibilityToRecord(visibility))}；${where}`,
                  );
                }

                // §30 / §84: per-asset account listing; unauthorized and unknown assets list nothing.
                const targets: IdRef[] = [...topology.assets.map((a) => keyRef(a.key)), rawRef(randomAssetId)];
                for (const target of targets) {
                  const assetId = resolveRef(seeded.assetIds, target);
                  const res = await api(ctx, 'GET', `/api/assets/${encodeURIComponent(assetId)}/accounts`, {
                    cookie: cookieFor(seeded, userKey),
                  });
                  const label = `[SEC-05] ${who} → ${refLabel(target)}`;
                  assert.equal(
                    res.status,
                    expectedStatus,
                    `[判定] GET /api/assets/:id/accounts 状态码与参考模型不一致：${label}（期望 ${expectedStatus}，实际 ${res.status}${res.threw ? '，处理器抛出未捕获异常' : ''}）；${where}`,
                  );
                  if (expected === null) continue;
                  const expectedAccounts =
                    target.kind === 'key' ? [...(expected.get(target.key) ?? [])].sort() : [];
                  const actualAccounts = Array.isArray(res.json)
                    ? (res.json as Array<{ id?: unknown }>)
                        .map((account) => {
                          const accountId = String(account?.id);
                          return seeded.accountKeyById.get(accountId) ?? `unknown:${accountId}`;
                        })
                        .sort()
                    : null;
                  assert.deepEqual(
                    actualAccounts,
                    expectedAccounts,
                    `[判定] GET /api/assets/:id/accounts 账号集合与参考模型不一致：${label}，期望 ${JSON.stringify(expectedAccounts)}，实际 ${JSON.stringify(actualAccounts)}；${where}`,
                  );
                }
              }
            });
          },
          { runs: PROPERTY_RUNS, seed: seedFromEnv() },
        );
        // Non-vacuity (D9): the property must have compared non-empty visibility and the 401 branch.
        assert.ok(nonEmptyVisibility > 0, '属性退化：参考模型从未给出非空可见集，可见性比较为空洞通过');
        assert.ok(unauthenticated > 0, '属性退化：未覆盖匿名或非 active 用户的 401 分支');
      },
    );

    it(
      '[SEC-06][SEC-07] 授权结果与参考模型等价：POST /api/sessions 状态码（全部资产 × 账号组合、跨资产与篡改组合）',
      { timeout: 60_000 },
      async (t) => {
        t.mock.timers.enable({ apis: ['Date'], now: FIXED_NOW });
        const observed: Record<ExpectedSessionStatus, number> = { 201: 0, 401: 0, 403: 0 };
        let probeCount = 0;
        await forAll(
          (rng) => {
            const topology = generateTopology(rng, FIXED_NOW);
            const probes: SessionProbe[] = [];
            for (const userKey of [...topology.users.map((u) => u.key), null]) {
              probes.push(...pairProbes(topology, userKey), ...tamperedProbes(rng, topology, userKey, 3));
            }
            return { topology, probes };
          },
          async ({ topology, probes }) => {
            await withContext(async (ctx) => {
              const seeded = await seedTopology(ctx, topology);
              const where = `拓扑=${describeTopology(topology)}`;
              for (const probe of probes) {
                const expected = oracle(topology, probe, FIXED_NOW);
                const res = await postSession(ctx, seeded, probe);
                assert.equal(
                  res.status,
                  expected,
                  `[判定] POST /api/sessions 状态码与参考模型不一致：${probe.label}（期望 ${expected}，实际 ${res.status}${res.threw ? '，处理器抛出未捕获异常' : ''}）；${where}`,
                );
                observed[expected]++;
                probeCount++;
              }
            });
          },
          { runs: PROPERTY_RUNS, seed: seedFromEnv() },
        );
        // Non-vacuity (D9): every outcome of the reference model must actually have been exercised.
        assert.ok(observed[201] > 0, `属性退化：未覆盖 201 分支（共 ${probeCount} 个探针）`);
        assert.ok(observed[403] > 0, `属性退化：未覆盖 403 分支（共 ${probeCount} 个探针）`);
        assert.ok(observed[401] > 0, `属性退化：未覆盖 401 分支（共 ${probeCount} 个探针）`);
      },
    );
  });

  // Feature: v1-compliance-review, Property 3: 连接目标只来自 D1
  //
  // Every iteration seeds a fresh positive-control topology (alice → web → deploy) whose asset gets a random public
  // hostname / port, then sends POST /api/sessions with the valid { assetId, accountId } (L19 field names) plus
  // injected connection fields: hostname, host, port, username, password and, randomly, target / address and the
  // /init-shaped nested objects asset { hostname, port } and credential { plaintext } (mass-assignment attempt).
  // Injected hosts include 127.0.0.1 and 169.254.169.254 (both guaranteed across the runs), IPv6 loopback,
  // localhost, a metadata hostname, RFC1918 addresses and random attacker hostnames; injected ports always differ
  // from the D1 port; passwords are `EJ-INJECT-<hex>`.
  //
  // Observed:
  //   - the Worker → SSHSessionDO `/init` body recorded by the mock namespace, plus the ticket payload it carries;
  //   - ctx.network.attempts after the DO that received `/init` is driven through /ticket + /connect?ticket= with
  //     `Upgrade: websocket` directly on the instance. `/init` alone never opens a socket; the direct upgrade
  //     exercises the DO connection path so the network half of the property cannot hold vacuously.
  // The client IP is pinned with CF-Connecting-IP: otherwise the router falls back to '127.0.0.1'
  // (src/api/router.ts:121-127), which `/init` carries as `clientIp` (the client address, not a connection target)
  // and which would collide with the injected loopback value.
  // Failure messages name injected keys and body paths only, never the injected or stored values.
  describe('Property 3: 连接目标只来自 D1（§36、§37、§69）', () => {
    /** Base URL for direct Durable Object calls (the host is ignored by the DO). */
    const DO_BASE_URL = 'https://session.internal';
    /** Pinned client address (public, distinct from every injected and every asset host). */
    const P3_CLIENT_IP = '9.9.9.10';
    const MUST_INJECT_HOSTS: readonly string[] = ['127.0.0.1', '169.254.169.254'];
    const ATTACK_PORTS: readonly number[] = [22, 23, 25, 80, 443, 2375, 3306, 5432, 6379, 8080, 11211];

    /**
     * substring: the value must not occur inside any observed string (values carry random hex or are IP / host
     * literals whose '.' / ':' cannot occur in ids, names or base64url tickets);
     * exact: the value must not equal any observed leaf (ports and common usernames like `root`).
     */
    interface InjectedField {
      /** Request-body path of the injected value, e.g. `hostname`, `asset.port`. */
      key: string;
      value: string | number;
      match: 'substring' | 'exact';
    }

    interface Property3Case {
      assetHostname: string;
      assetPort: number;
      /** Injected request-body fields (merged with the valid assetId / accountId at request time). */
      extra: Record<string, unknown>;
      injected: InjectedField[];
      injectedHosts: string[];
    }

    interface Leaf {
      path: string;
      value: string | number | boolean | null;
    }

    interface InitBody {
      assetId?: string; accountId?: string; host?: string; port?: number; username?: string;
      sessionId?: unknown;
      asset?: { id?: unknown; hostname?: unknown; port?: unknown };
      account?: { id?: unknown; username?: unknown };
      ticket?: unknown;
    }

    function genInjectedHost(rng: Rng): string {
      switch (rng.int(0, 5)) {
        case 0:
          return '127.0.0.1';
        case 1:
          return '169.254.169.254';
        case 2:
          return rng.pick(['::1', '[::1]', 'localhost', 'metadata.google.internal', '0.0.0.0']);
        case 3:
          return `10.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`;
        case 4:
          return `192.168.${rng.int(0, 255)}.${rng.int(1, 254)}`;
        default:
          return `evil-${rng.hex(4)}.example`;
      }
    }

    function genInjectedPort(rng: Rng, assetPort: number): number {
      for (;;) {
        const port = rng.bool(0.5) ? rng.pick(ATTACK_PORTS) : rng.int(1, 65535);
        if (port !== assetPort) return port;
      }
    }

    function genProperty3Case(rng: Rng, run: number): Property3Case {
      const assetHostname = rng.pick(PUBLIC_HOSTS);
      const assetPort = rng.bool(0.5) ? 22 : rng.int(1024, 65535);
      const injected: InjectedField[] = [];
      const injectedHosts: string[] = [];
      const extra: Record<string, unknown> = {};
      const host = (): string => {
        const value = genInjectedHost(rng);
        injectedHosts.push(value);
        return value;
      };
      const port = (): number => genInjectedPort(rng, assetPort);
      const portForm = (value: number): number | string => (rng.bool(0.5) ? value : String(value));
      const put = (key: string, value: string | number, match: InjectedField['match']): void => {
        injected.push({ key, value, match });
      };

      // Guarantee both mandatory hosts over the runs: even runs inject 127.0.0.1 as `hostname`, odd runs
      // inject 169.254.169.254 as `host`; the other key gets a random value.
      const hostname = run % 2 === 0 ? MUST_INJECT_HOSTS[0] : host();
      const hostField = run % 2 === 1 ? MUST_INJECT_HOSTS[1] : host();
      if (run % 2 === 0) injectedHosts.push(hostname);
      else injectedHosts.push(hostField);
      extra.hostname = hostname;
      put('hostname', hostname, 'substring');
      extra.host = hostField;
      put('host', hostField, 'substring');

      const portValue = port();
      extra.port = portForm(portValue);
      put('port', portValue, 'exact');

      const username = rng.pick(['root', 'admin', `ej-inj-${rng.hex(4)}`]);
      extra.username = username;
      put('username', username, username.startsWith('ej-inj-') ? 'substring' : 'exact');

      const password = `EJ-INJECT-${rng.hex(8)}`;
      extra.password = password;
      put('password', password, 'substring');

      if (rng.bool(0.5)) {
        const targetHost = host();
        const targetPort = port();
        const target = `${targetHost}:${targetPort}`;
        extra.target = target;
        put('target', target, 'substring');
        put('target(port)', targetPort, 'exact');
      }
      if (rng.bool(0.5)) {
        const address = host();
        extra.address = address;
        put('address', address, 'substring');
      }
      if (rng.bool(0.5)) {
        const nestedHost = host();
        const nestedPort = port();
        extra.asset = { hostname: nestedHost, port: portForm(nestedPort) };
        put('asset.hostname', nestedHost, 'substring');
        put('asset.port', nestedPort, 'exact');
      }
      if (rng.bool(0.5)) {
        const nestedPassword = `EJ-INJECT-${rng.hex(8)}`;
        extra.credential = { type: 'password', plaintext: nestedPassword };
        put('credential.plaintext', nestedPassword, 'substring');
      }
      return { assetHostname, assetPort, extra, injected, injectedHosts };
    }

    function collectLeaves(value: unknown, path: string, out: Leaf[]): Leaf[] {
      if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        out.push({ path, value });
      } else if (Array.isArray(value)) {
        value.forEach((item, index) => collectLeaves(item, `${path}[${index}]`, out));
      } else if (typeof value === 'object') {
        for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
          collectLeaves(item, `${path}.${key}`, out);
        }
      }
      return out;
    }

    /** Socket targets are "<hostname>:<port>"; fetch targets are URLs. Host and port parts become separate leaves. */
    function networkLeaves(attempts: readonly NetworkAttempt[]): Leaf[] {
      const leaves: Leaf[] = [];
      attempts.forEach((attempt, index) => {
        const base = `network[${index}](${attempt.kind})`;
        leaves.push({ path: `${base}.target`, value: attempt.target });
        if (attempt.kind === 'socket') {
          const cut = attempt.target.lastIndexOf(':');
          leaves.push({ path: `${base}.host`, value: cut < 0 ? attempt.target : attempt.target.slice(0, cut) });
          if (cut >= 0) leaves.push({ path: `${base}.port`, value: attempt.target.slice(cut + 1) });
        } else {
          try {
            const url = new URL(attempt.target);
            leaves.push(
              { path: `${base}.hostname`, value: url.hostname },
              { path: `${base}.port`, value: url.port },
              { path: `${base}.username`, value: url.username },
              { path: `${base}.password`, value: url.password },
            );
          } catch {
            // Not a URL: the full target leaf above is still scanned.
          }
        }
      });
      return leaves;
    }

    /** Returns `<injected key> → <observed path>` for every hit; never includes the values themselves. */
    function findInjectionHits(leaves: readonly Leaf[], injected: readonly InjectedField[]): string[] {
      const hits: string[] = [];
      for (const field of injected) {
        const needle = String(field.value);
        for (const leaf of leaves) {
          const hit =
            field.match === 'exact'
              ? leaf.value !== null && String(leaf.value) === needle
              : typeof leaf.value === 'string' && leaf.value.includes(needle);
          if (hit) hits.push(`${field.key} → ${leaf.path}`);
        }
      }
      return hits;
    }

    /** Secret-free category of a socket target, for the observation diagnostic. */
    function targetShape(attempt: NetworkAttempt, d1Target: string): string {
      if (attempt.target === d1Target) return `${attempt.kind}: D1 资产 hostname:port`;
      if (attempt.target === 'undefined:undefined') return `${attempt.kind}: undefined:undefined`;
      return `${attempt.kind}: 其它目标`;
    }

    it(
      '[SEC-07][SEC-18] 连接目标只来自 D1：请求体注入 host/port/username/password 不影响 /init 与网络目标',
      { timeout: 60_000 },
      async (t) => {
        const seenHosts = new Set<string>();
        const shapes = new Map<string, number>();
        let socketAttempts = 0;
        await forAll(
          (rng, run) => genProperty3Case(rng, run),
          async (c) => {
            for (const value of c.injectedHosts) seenHosts.add(value);
            await withContext(async (ctx) => {
              // Swallows the DO's "[SSHSessionDO] SSH connection failed" line; cleanup() restores console.
              captureConsole();
              const topology = positiveControlTopology(Date.now());
              topology.assets = topology.assets.map((asset) =>
                asset.key === 'web' ? { ...asset, hostname: c.assetHostname, port: c.assetPort } : asset,
              );
              const seeded = await seedTopology(ctx, topology);
              const assetId = idOf(seeded.assetIds, 'web');
              const accountId = idOf(seeded.accountIds, 'web.deploy');
              const injectedKeys = c.injected.map((field) => field.key).join(', ');

              // Positive control (D9): the injected request is still a valid, authorized session request.
              const res = await api(ctx, 'POST', '/api/sessions', {
                cookie: cookieFor(seeded, 'alice'),
                body: { ...c.extra, assetId, accountId },
                headers: { 'CF-Connecting-IP': P3_CLIENT_IP },
              });
              assert.equal(
                res.status,
                201,
                `正向对照失败：带注入字段（${injectedKeys}）的授权请求 POST /api/sessions 返回 ${res.status}${res.threw ? '（处理器抛出未捕获异常）' : ''}`,
              );
              const sessionId: unknown = res.json?.sessionId;
              assert.ok(typeof sessionId === 'string' && sessionId !== '', '正向对照失败：响应缺少 sessionId');
              await flushAsync();

              const initCalls = ctx.sessions.calls.filter((call) => call.path === '/init');
              assert.equal(initCalls.length, 1, '正向对照失败：SSHSessionDO 应恰好收到一次 /init');
              const initCall = initCalls[0];
              const init = (initCall.body ?? {}) as InitBody;
              assert.equal(init.sessionId, sessionId, '正向对照失败：/init 的 sessionId 与创建响应不一致');

              const assetRow = await ctx.db
                .prepare('SELECT hostname, port FROM assets WHERE id = ?')
                .bind(assetId)
                .first<{ hostname: string; port: number }>();
              const accountRow = await ctx.db
                .prepare('SELECT username FROM asset_accounts WHERE id = ?')
                .bind(accountId)
                .first<{ username: string }>();
              assert.ok(assetRow && accountRow, 'fixture: D1 资产与账号记录存在');
              assert.equal(assetRow.hostname, c.assetHostname, 'fixture: D1 资产 hostname 与生成值一致');
              assert.equal(Number(assetRow.port), c.assetPort, 'fixture: D1 资产 port 与生成值一致');

              // [判定] /init target = the D1 asset record (§36: the Worker takes the real target from D1).
              assert.equal(init.assetId, assetId, '[判定] /init 的资产 ID 与请求的 assetId 不一致（§36）');
              assert.equal(init.host, assetRow.hostname, '[判定] /init 目标主机不等于 D1 资产记录（§36）');
              assert.equal(Number(init.port), Number(assetRow.port), '[判定] /init 目标端口不等于 D1 资产记录（§36）');
              assert.equal(init.accountId, accountId, '[判定] /init 的账号 ID 与请求的 accountId 不一致（§36）');
              assert.equal(init.username, accountRow.username, '[判定] /init 的 SSH 用户名不等于 D1 账号记录（§36）');

              // Drive the DO that received /init so its background SSH connect reaches the (blocked) network.
              const instance = ctx.sessions.instances.get(initCall.id);
              assert.ok(instance !== undefined, '前置失败：模拟命名空间中没有收到 /init 的 SSHSessionDO 实例');
              const ticketRes = await instance.fetch(new Request(`${DO_BASE_URL}/ticket`, { method: 'POST', headers: { 'x-user-id': (instance as any).config.userId } }));
              const issued = (await ticketRes.json()) as { ticket?: unknown };
              assert.ok(typeof issued.ticket === 'string' && issued.ticket !== '', '前置失败：DO /ticket 未签发票据');
              const upgrade = await instance.fetch(
                new Request(`${DO_BASE_URL}/connect?ticket=${encodeURIComponent(issued.ticket)}`, {
                  method: 'GET',
                  headers: { Upgrade: 'websocket', 'x-user-id': (instance as any).config.userId },
                }),
              );
              assert.equal(upgrade.status, 101, '前置失败：DO /connect 未完成升级（101）');
              for (let round = 0; round < 20 && instance.getStatus() === 'connecting'; round++) await flushAsync(1);
              await flushAsync();

              const attempts = ctx.network.attempts;
              const sockets = attempts.filter((attempt) => attempt.kind === 'socket');
              assert.ok(sockets.length > 0, '前置失败：DO 未发起 TCP 连接，网络目标断言将空洞通过');
              socketAttempts += sockets.length;
              const d1Target = `${assetRow.hostname}:${Number(assetRow.port)}`;
              for (const attempt of attempts) {
                const shape = targetShape(attempt, d1Target);
                shapes.set(shape, (shapes.get(shape) ?? 0) + 1);
              }

              // [判定] neither the /init body (nor the ticket it carries) nor any network target contains an injected value.
              const initLeaves = collectLeaves(initCall.body, '/init', []);
              const ticketPayload = typeof init.ticket === 'string' ? decodeTicket(init.ticket) : null;
              if (ticketPayload) collectLeaves(ticketPayload, '/init.ticket(payload)', initLeaves);
              // Scanner self-check (non-vacuity): the same scan must find the D1 values the body does carry.
              const scannerProbe = findInjectionHits(initLeaves, [
                { key: 'd1.hostname', value: assetRow.hostname, match: 'substring' },
                { key: 'd1.port', value: Number(assetRow.port), match: 'exact' },
                { key: 'd1.username', value: accountRow.username, match: 'exact' },
              ]);
              assert.ok(
                ['d1.hostname', 'd1.port', 'd1.username'].every((key) => scannerProbe.some((hit) => hit.startsWith(`${key} →`))),
                'fixture: 注入扫描器未能在 /init 叶子中识别 D1 的 hostname / port / username（扫描将空洞通过）',
              );
              const initHits = findInjectionHits(initLeaves, c.injected);
              assert.deepEqual(
                initHits,
                [],
                `[判定] /init 请求体包含请求体注入值（§36、§69；注入键 → 命中路径）：${initHits.join('；')}`,
              );
              const netHits = findInjectionHits(networkLeaves(attempts), c.injected);
              assert.deepEqual(
                netHits,
                [],
                `[判定] 网络连接目标包含请求体注入值（§36、§37；注入键 → 命中路径）：${netHits.join('；')}`,
              );
            });
          },
          { runs: PROPERTY_RUNS, seed: seedFromEnv() },
        );
        // Non-vacuity (D9): both mandatory injection targets were exercised and sockets were actually attempted.
        for (const value of MUST_INJECT_HOSTS) {
          assert.ok(seenHosts.has(value), `属性退化：未注入必测目标主机（${value === '127.0.0.1' ? 'loopback' : 'metadata'}）`);
        }
        assert.ok(socketAttempts > 0, '属性退化：未观察到任何 TCP 连接尝试');
        t.diagnostic(
          `观察 被阻断的网络尝试目标（脱敏，共 ${socketAttempts} 次 socket）：${[...shapes].map(([shape, n]) => `${shape} × ${n}`).join('；')}`,
        );
        t.diagnostic(
          '观察：Worker→DO /init 使用顶层 host / port / username，实际 TCP 连接使用 D1 目标解析并校验后的公网 IP',
        );
      },
    );
  });

  // Feature: v1-compliance-review, Property 4: 会话资源归属
  //
  // Every iteration seeds the §93 demo topology (seedDemoTopology) into a fresh context; Alice (User, Developers →
  // Production/Web → deploy) creates a session through POST /api/sessions with a pinned CF-Connecting-IP and a random
  // User-Agent, and the session row is then moved to a random status (creating … timeout; ended states also get
  // ended_at / disconnect_reason / terminated_by). The other user B only holds the User role and is, by run index:
  //   bob                     — no group, no authorization (seedDemoTopology's bob)
  //   bob-same-authorization  — bob joins Developers, i.e. holds exactly Alice's asset / account authorization
  //   bob-own-authorization   — bob gets his own rule Ops → prod-db-01 → dba
  //   fresh-user              — a freshly inserted User-role account
  // and, when authorized, randomly owns a session of his own. B's login cookie is checked with GET /api/me first so
  // that a denial cannot come from an invalid login session; same-origin requests make sure a 403 is not the CSRF check.
  //
  // Observed after B's requests (all relative to a baseline taken right before them):
  //   - the full ssh_sessions row of Alice's session (every column);
  //   - SESSION_TERMINATED audit events with actor = B (any resource) and for Alice's session (any actor);
  //   - Worker → SSHSessionDO calls recorded by the mock namespace.
  // Denial responses must not carry session details (snapshot values of the row) nor fields other than error/details.
  // `/api/sessions/:id/ws` is not asserted here: its user binding is checked by the ticket tests (task 10.2).
  // Failure messages carry route labels, variants, status codes and column names only, never stored values.
  describe('Property 4: 会话资源归属（§84、§92 第 7 条）', () => {
    type OtherUserVariant = 'bob' | 'bob-same-authorization' | 'bob-own-authorization' | 'fresh-user';
    const OTHER_USER_VARIANTS: readonly OtherUserVariant[] = [
      'bob',
      'bob-same-authorization',
      'bob-own-authorization',
      'fresh-user',
    ];

    const SESSION_STATES = ['creating', 'connecting', 'active', 'closing', 'closed', 'failed', 'terminated', 'timeout'] as const;
    type SessionState = (typeof SESSION_STATES)[number];
    const LIVE_SESSION_STATES: readonly SessionState[] = ['creating', 'connecting', 'active'];
    const ENDED_SESSION_STATES: readonly SessionState[] = ['closed', 'failed', 'terminated', 'timeout'];

    type BodyKind = 'none' | 'empty' | 'reason' | 'claim-owner' | 'status';

    interface AdminSessionRequest {
      method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
      /** Suffix after /api/admin/sessions/:id. */
      suffix: string;
      upgrade: boolean;
      /** Permission guard in src/api/router.ts (null: no handler for this method, falls through to 404). */
      guard: string | null;
    }

    /** `/api/admin/sessions/:id/*` (design C6.6) plus method / sub-path variants without a handler. */
    const ADMIN_SESSION_REQUESTS: readonly AdminSessionRequest[] = [
      { method: 'GET', suffix: '', upgrade: false, guard: 'session.view_all' },
      { method: 'GET', suffix: '/commands', upgrade: false, guard: 'audit.read | session.view_all' },
      { method: 'GET', suffix: '/recording', upgrade: false, guard: 'audit.read | session.view_all' },
      { method: 'GET', suffix: '/monitor', upgrade: false, guard: 'session.monitor' },
      { method: 'GET', suffix: '/monitor', upgrade: true, guard: 'session.monitor' },
      { method: 'POST', suffix: '/terminate', upgrade: false, guard: 'session.terminate' },
      { method: 'DELETE', suffix: '', upgrade: false, guard: null },
      { method: 'PATCH', suffix: '', upgrade: false, guard: null },
      { method: 'POST', suffix: '/disconnect', upgrade: false, guard: null },
      { method: 'POST', suffix: '/recording', upgrade: false, guard: null },
    ];

    interface Property4Case {
      variant: OtherUserVariant;
      /** B also owns a session (only effective for the authorized variants). */
      otherOwnSession: boolean;
      state: SessionState;
      clientIp: string;
      userAgent: string;
      secret: string;
      otherName: string;
      reasonTag: string;
      disconnectBody: BodyKind;
      adminRequests: Array<{ request: AdminSessionRequest; body: BodyKind }>;
    }

    interface Property4Setup {
      topo: DemoTopology;
      other: SeededUser;
      sessionId: string;
      /** Distinctive values of Alice's session row; a denial response must contain none of them. */
      leakNeedles: Array<{ field: string; value: string }>;
    }

    interface Property4Baseline {
      row: Record<string, unknown> | null;
      terminatedForSession: number;
      callMark: number;
    }

    function genProperty4Case(rng: Rng, run: number, states: readonly SessionState[]): Property4Case {
      const pickBody = (method: AdminSessionRequest['method']): BodyKind =>
        method === 'GET' || method === 'DELETE' ? 'none' : rng.pick(['none', 'empty', 'reason', 'claim-owner', 'status'] as const);
      return {
        // run-indexed variant and state guarantee coverage of every combination class over PROPERTY_RUNS.
        variant: OTHER_USER_VARIANTS[run % OTHER_USER_VARIANTS.length],
        otherOwnSession: rng.bool(0.5),
        state: states[Math.floor(run / OTHER_USER_VARIANTS.length) % states.length],
        clientIp: `9.${rng.int(1, 254)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
        userAgent: `EJ-P4-UA-${rng.hex(6)}`,
        secret: `EJ-SECRET-${rng.hex(16)}`,
        otherName: `p4-other-${rng.hex(4)}`,
        reasonTag: `EJ-P4-REASON-${rng.hex(4)}`,
        disconnectBody: rng.pick(['none', 'empty', 'reason', 'claim-owner'] as const),
        adminRequests: shuffled(rng, ADMIN_SESSION_REQUESTS).map((request) => ({ request, body: pickBody(request.method) })),
      };
    }

    function requestBody(kind: BodyKind, c: Property4Case, s: Property4Setup): unknown {
      switch (kind) {
        case 'none':
          return undefined;
        case 'empty':
          return {};
        case 'reason':
          return { reason: c.reasonTag };
        case 'claim-owner':
          // Attempt to claim ownership through the body (the server must use the login session, §84).
          return { userId: s.topo.alice.id, ownerId: s.topo.alice.id, terminatedBy: s.topo.alice.id };
        case 'status':
          return { status: 'active', endedAt: null };
      }
    }

    async function insertGroupMember(db: D1Database, groupId: string, userId: string): Promise<void> {
      await db
        .prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)')
        .bind(groupId, userId, Date.now())
        .run();
    }

    async function applySessionState(db: D1Database, sessionId: string, state: SessionState, adminId: string): Promise<void> {
      if (state === 'creating') return; // status written by createSession
      const ended = ENDED_SESSION_STATES.includes(state);
      await db
        .prepare('UPDATE ssh_sessions SET status = ?, ended_at = ?, disconnect_reason = ?, terminated_by = ? WHERE id = ?')
        .bind(state, ended ? Date.now() : null, ended ? `p4-prior-${state}` : null, state === 'terminated' ? adminId : null, sessionId)
        .run();
    }

    async function setupProperty4(ctx: ComplianceContext, c: Property4Case): Promise<Property4Setup> {
      const db = ctx.db;
      const topo = await seedDemoTopology(ctx, c.secret);

      let other: SeededUser = topo.bob;
      let otherTarget: { assetId: string; accountId: string } | null = null;
      if (c.variant === 'bob-same-authorization') {
        await insertGroupMember(db, topo.developers.id, topo.bob.id);
        otherTarget = { assetId: topo.prodWeb01.id, accountId: topo.deploy.id };
      } else if (c.variant === 'bob-own-authorization') {
        const ops = await createGroup({ name: 'Ops' }, topo.admin.id, db);
        await insertGroupMember(db, ops.id, topo.bob.id);
        await createAuthorizationRule(
          {
            name: 'Ops -> prod-db-01 -> dba',
            groupIds: [ops.id],
            assetIds: [topo.prodDb01.id],
            accountIds: [topo.dba.id],
            actions: ['connect'],
          },
          topo.admin.id,
          db,
        );
        otherTarget = { assetId: topo.prodDb01.id, accountId: topo.dba.id };
      } else if (c.variant === 'fresh-user') {
        const row = await insertUser(db, { username: c.otherName, roles: ['User'] });
        other = { ...row, cookie: await issueCookie(db, row.id) };
      }

      const created = await api(ctx, 'POST', '/api/sessions', {
        cookie: topo.alice.cookie,
        body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id },
        headers: { 'CF-Connecting-IP': c.clientIp, 'User-Agent': c.userAgent },
      });
      assert.equal(created.status, 201, `前置失败：Alice 创建会话 POST /api/sessions 返回 ${created.status}`);
      const sessionId: unknown = created.json?.sessionId;
      assert.ok(typeof sessionId === 'string' && sessionId !== '', '前置失败：创建会话响应缺少 sessionId');

      if (c.otherOwnSession && otherTarget !== null) {
        const own = await api(ctx, 'POST', '/api/sessions', { cookie: other.cookie, body: otherTarget });
        assert.equal(own.status, 201, `前置失败：${c.variant} 创建本人会话返回 ${own.status}`);
      }

      await applySessionState(db, sessionId, c.state, topo.admin.id);

      const me = await api(ctx, 'GET', '/api/me', { cookie: other.cookie });
      assert.equal(me.status, 200, `前置失败：${c.variant} 的登录会话无效（GET /api/me 返回 ${me.status}）`);
      await flushAsync();

      return {
        topo,
        other,
        sessionId,
        leakNeedles: [
          { field: 'user_id', value: topo.alice.id },
          { field: 'username_snapshot', value: topo.alice.username },
          { field: 'asset_id', value: topo.prodWeb01.id },
          { field: 'asset_name_snapshot', value: topo.prodWeb01.name },
          { field: 'account_id', value: topo.deploy.id },
          { field: 'source_ip', value: c.clientIp },
          { field: 'user_agent', value: c.userAgent },
        ],
      };
    }

    async function sessionRow(db: D1Database, sessionId: string): Promise<Record<string, unknown> | null> {
      return (await db.prepare('SELECT * FROM ssh_sessions WHERE id = ?').bind(sessionId).first<Record<string, unknown>>()) ?? null;
    }

    function changedColumns(before: Record<string, unknown> | null, after: Record<string, unknown> | null): string[] {
      if (before === null || after === null) return before === after ? [] : ['<row presence>'];
      const columns = new Set([...Object.keys(before), ...Object.keys(after)]);
      return [...columns].filter((column) => before[column] !== after[column]).sort();
    }

    async function countTerminatedEvents(
      db: D1Database,
      filter: { actorUserId?: string; resourceId?: string },
    ): Promise<number> {
      const clauses = ["action = 'SESSION_TERMINATED'"];
      const params: string[] = [];
      if (filter.actorUserId !== undefined) {
        clauses.push('actor_user_id = ?');
        params.push(filter.actorUserId);
      }
      if (filter.resourceId !== undefined) {
        clauses.push('resource_id = ?');
        params.push(filter.resourceId);
      }
      const row = await db
        .prepare(`SELECT COUNT(*) AS n FROM audit_events WHERE ${clauses.join(' AND ')}`)
        .bind(...params)
        .first<{ n: number }>();
      return Number(row?.n ?? 0);
    }

    async function takeBaseline(ctx: ComplianceContext, s: Property4Setup): Promise<Property4Baseline> {
      return {
        row: await sessionRow(ctx.db, s.sessionId),
        terminatedForSession: await countTerminatedEvents(ctx.db, { resourceId: s.sessionId }),
        callMark: ctx.sessions.calls.length,
      };
    }

    /** Field names (never values) of Alice's session found in a response body. */
    function leakedFields(text: string, needles: Property4Setup['leakNeedles']): string[] {
      return needles.filter((needle) => text.includes(needle.value)).map((needle) => needle.field);
    }

    /** A denial body may only be jsonError's { error, details }. */
    function unexpectedJsonKeys(json: unknown): string[] {
      if (json === null || json === undefined) return [];
      if (Array.isArray(json)) return ['<array>'];
      if (typeof json !== 'object') return ['<non-object>'];
      return Object.keys(json as Record<string, unknown>).filter((key) => key !== 'error' && key !== 'details');
    }

    function isCsrfDenial(res: ApiResult): boolean {
      return typeof res.json?.error === 'string' && res.json.error.startsWith('CSRF protection');
    }

    /** P4 invariants on Alice's session after B's requests. `doScope` = which new DO calls count as a violation. */
    async function assertSessionUntouched(
      ctx: ComplianceContext,
      s: Property4Setup,
      baseline: Property4Baseline,
      doScope: 'terminate' | 'any',
      label: string,
    ): Promise<void> {
      const changed = changedColumns(baseline.row, await sessionRow(ctx.db, s.sessionId));
      assert.deepEqual(changed, [], `[判定] 其他 User 的请求改变了他人会话的 ssh_sessions 记录：${label}（变化列：${changed.join(', ')}）`);
      const byOther = await countTerminatedEvents(ctx.db, { actorUserId: s.other.id });
      assert.equal(byOther, 0, `[判定] 产生了以其他 User 为 actor 的 SESSION_TERMINATED 审计事件：${label}（${byOther} 条）`);
      const forSession = (await countTerminatedEvents(ctx.db, { resourceId: s.sessionId })) - baseline.terminatedForSession;
      assert.equal(forSession, 0, `[判定] 他人会话新增了 SESSION_TERMINATED 审计事件：${label}（${forSession} 条）`);
      const doCalls = ctx.sessions.calls
        .slice(baseline.callMark)
        .filter((call) => doScope === 'any' || call.path === '/terminate')
        .map((call) => `${call.method} ${call.path}`);
      assert.deepEqual(doCalls, [], `[判定] 其他 User 的请求触发了 SSHSessionDO 调用：${label}（${doCalls.join('，')}）`);
    }

    function sessionPath(sessionId: string, suffix: string): string {
      return `/api/sessions/${encodeURIComponent(sessionId)}${suffix}`;
    }

    function adminSessionPath(sessionId: string, suffix: string): string {
      return `/api/admin/sessions/${encodeURIComponent(sessionId)}${suffix}`;
    }

    it(
      '[SEC-07] 会话资源归属：其他 User 调用 POST /api/sessions/:id/disconnect 被拒绝且会话状态不变',
      {
        timeout: 60_000
      },
      async (t) => {
        // First-failure observation (secret-free categories only), reported even when the [判定] assertion fails.
        let observation: string | null = null;
        try {
          await forAll(
            (rng, run) => genProperty4Case(rng, run, SESSION_STATES),
            async (c) => {
              await withContext(async (ctx) => {
                const s = await setupProperty4(ctx, c);
                const baseline = await takeBaseline(ctx, s);
                const label = `[SEC-07] ${c.variant}${c.otherOwnSession ? '（持有本人会话）' : ''} → POST /api/sessions/:id/disconnect（他人会话状态 ${c.state}，请求体 ${c.disconnectBody}）`;

                const res = await api(ctx, 'POST', sessionPath(s.sessionId, '/disconnect'), {
                  cookie: s.other.cookie,
                  body: requestBody(c.disconnectBody, c, s),
                });
                await flushAsync();

                if (observation === null) {
                  const after = await sessionRow(ctx.db, s.sessionId);
                  const terminatedBy = after?.terminated_by ?? null;
                  const actorOf = (id: unknown): string =>
                    id === s.other.id ? 'B' : id === s.topo.alice.id ? '所有者 Alice' : id === null ? 'null' : '其他';
                  const { results: events } = await ctx.db
                    .prepare("SELECT actor_user_id FROM audit_events WHERE action = 'SESSION_TERMINATED' AND resource_id = ? ORDER BY timestamp")
                    .bind(s.sessionId)
                    .all<{ actor_user_id: string | null }>();
                  const doTerminates = ctx.sessions.calls.slice(baseline.callMark).filter((call) => call.path === '/terminate').length;
                  observation =
                    `观察（首个样本 ${c.variant} / ${c.state}）：B 的响应 ${res.status}；会话状态 ${String(baseline.row?.status)} → ${String(after?.status)}；` +
                    `terminated_by → ${actorOf(terminatedBy)}；变化列 ${changedColumns(baseline.row, after).join(', ') || '无'}；` +
                    `SESSION_TERMINATED actor 序列 [${(events ?? []).map((e) => actorOf(e.actor_user_id)).join(', ')}]；DO /terminate 调用 ${doTerminates} 次`;
                }

                assert.ok(!isCsrfDenial(res), `fixture: ${label} 被 CSRF 检查拒绝（同源请求不应触发），无法证明归属校验`);
                assert.ok(
                  res.status === 403 || res.status === 404,
                  `[判定] 其他 User 断开他人会话未被拒绝（§84）：${label}（期望 403 / 404，实际 ${res.status}${res.threw ? '，处理器抛出未捕获异常' : ''}）`,
                );
                const leaks = leakedFields(res.text, s.leakNeedles);
                assert.deepEqual(leaks, [], `[判定] 拒绝响应泄露他人会话详情：${label}（字段：${leaks.join(', ')}）`);
                await assertSessionUntouched(ctx, s, baseline, 'terminate', label);
              });
            },
            { runs: PROPERTY_RUNS, seed: seedFromEnv() },
          );
        } finally {
          if (observation !== null) t.diagnostic(observation);
        }
      },
    );

    it(
      '[SEC-07] 会话资源归属：其他 User 调用 /api/admin/sessions/:id/* 被拒绝且会话状态不变',
      { timeout: 60_000 },
      async (t) => {
        const variants = new Set<OtherUserVariant>();
        const states = new Set<SessionState>();
        const outcomes = new Map<string, number>();
        let guardedRequests = 0;
        let permissionDenied = 0;
        await forAll(
          (rng, run) => genProperty4Case(rng, run, SESSION_STATES),
          async (c) => {
            variants.add(c.variant);
            states.add(c.state);
            await withContext(async (ctx) => {
              const s = await setupProperty4(ctx, c);
              const baseline = await takeBaseline(ctx, s);
              const who = `${c.variant}${c.otherOwnSession ? '（持有本人会话）' : ''}`;

              for (const { request, body } of c.adminRequests) {
                const route = `${request.method} /api/admin/sessions/:id${request.suffix}${request.upgrade ? '（Upgrade: websocket）' : ''}`;
                const label = `[SEC-07] ${who} → ${route}（他人会话状态 ${c.state}，请求体 ${body}）`;
                const res = await api(ctx, request.method, adminSessionPath(s.sessionId, request.suffix), {
                  cookie: s.other.cookie,
                  body: requestBody(body, c, s),
                  headers: request.upgrade ? { Upgrade: 'websocket' } : undefined,
                });
                assert.ok(!isCsrfDenial(res), `fixture: ${label} 被 CSRF 检查拒绝（同源请求不应触发），无法证明权限校验`);
                assert.ok(
                  res.status === 403 || res.status === 404,
                  `[判定] 其他 User 访问他人会话的管理路由未被拒绝（§84、§12）：${label}（期望 403 / 404，实际 ${res.status}${res.threw ? '，处理器抛出未捕获异常' : ''}）`,
                );
                const leaks = leakedFields(res.text, s.leakNeedles);
                assert.deepEqual(leaks, [], `[判定] 拒绝响应泄露他人会话详情：${label}（字段：${leaks.join(', ')}）`);
                const extraKeys = unexpectedJsonKeys(res.json);
                assert.deepEqual(extraKeys, [], `[判定] 拒绝响应包含错误信息以外的字段：${label}（${extraKeys.join(', ')}）`);

                const outcome = `${route} → ${res.status}`;
                outcomes.set(outcome, (outcomes.get(outcome) ?? 0) + 1);
                if (request.guard !== null) {
                  guardedRequests++;
                  if (res.status === 403 && res.json?.error === 'Permission denied') permissionDenied++;
                }
              }
              await flushAsync();
              await assertSessionUntouched(ctx, s, baseline, 'any', `[SEC-07] ${who} → /api/admin/sessions/:id/*（他人会话状态 ${c.state}）`);

              // Positive control (D9): with session.view_all the same session id resolves to the full row, so B's denial
              // is not an artefact of a wrong id; the leak scanner recognizes every needle in that authorized response.
              const detail = await api(ctx, 'GET', adminSessionPath(s.sessionId, ''), { cookie: s.topo.admin.cookie });
              assert.equal(detail.status, 200, `正向对照失败：Super Admin GET /api/admin/sessions/:id 返回 ${detail.status}`);
              assert.equal(detail.json?.id, s.sessionId, '正向对照失败：Super Admin 读取到的会话 ID 与请求不一致');
              const recognized = leakedFields(detail.text, s.leakNeedles);
              assert.deepEqual(
                recognized,
                s.leakNeedles.map((needle) => needle.field),
                'fixture: 泄露扫描器未能在授权响应中识别全部会话详情字段（扫描将空洞通过）',
              );
            });
          },
          { runs: PROPERTY_RUNS, seed: seedFromEnv() },
        );
        // Non-vacuity (D9): every B variant and session state was exercised, and guarded routes denied via RBAC.
        assert.deepEqual([...variants].sort(), [...OTHER_USER_VARIANTS].sort(), '属性退化：未覆盖全部其他用户变体');
        assert.deepEqual([...states].sort(), [...SESSION_STATES].sort(), '属性退化：未覆盖全部会话状态');
        assert.ok(guardedRequests > 0 && permissionDenied > 0, '属性退化：受权限保护的路由从未经权限检查拒绝');
        t.diagnostic(
          `观察 拒绝结果分布（受保护路由 ${guardedRequests} 次，其中 Permission denied ${permissionDenied} 次）：${[...outcomes]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([outcome, n]) => `${outcome} × ${n}`)
            .join('；')}`,
        );
      },
    );

    it('[SEC-07] 正向对照：会话所有者 Alice 可断开本人会话', { timeout: 60_000 }, async (t) => {
      const terminatedBy = new Map<string, number>();
      const actorSequences = new Map<string, number>();
      await forAll(
        (rng, run) => genProperty4Case(rng, run, LIVE_SESSION_STATES),
        async (c) => {
          await withContext(async (ctx) => {
            const s = await setupProperty4(ctx, c);
            const callMark = ctx.sessions.calls.length;
            const label = `Alice → POST /api/sessions/:id/disconnect（会话状态 ${c.state}，请求体 ${c.disconnectBody}，其他用户变体 ${c.variant}）`;

            const res = await api(ctx, 'POST', sessionPath(s.sessionId, '/disconnect'), {
              cookie: s.topo.alice.cookie,
              body: requestBody(c.disconnectBody, c, s),
            });
            await flushAsync();
            assert.equal(res.status, 200, `正向对照失败：${label} 返回 ${res.status}${res.threw ? '（处理器抛出未捕获异常）' : ''}`);
            assert.equal(res.json?.success, true, `正向对照失败：${label} 响应缺少 success: true`);

            const after = await sessionRow(ctx.db, s.sessionId);
            assert.equal(after?.status, 'closed', `正向对照失败：${label} 后会话状态不是 terminated`);
            assert.ok(after?.ended_at !== null && after?.ended_at !== undefined, `正向对照失败：${label} 后 ended_at 为空`);
            const ownClose = await ctx.db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action = 'SESSION_CLOSED' AND actor_user_id = ? AND resource_id = ?").bind(s.topo.alice.id, s.sessionId).first<{count: number}>();
            assert.ok(ownClose && ownClose.count > 0);
            const doHex = ctx.sessions.idFromName(s.sessionId).toString();
            const terminateCalls = ctx.sessions.calls
              .slice(callMark)
              .filter((call) => call.path === '/terminate' && call.id === doHex);
            assert.equal(terminateCalls.length, 1, `正向对照失败：${label} 未向该会话的 SSHSessionDO 发送 /terminate`);

            const byValue = after?.terminated_by;
            const category = byValue === s.topo.alice.id ? '所有者 Alice' : byValue === null || byValue === undefined ? 'null' : '其他';
            terminatedBy.set(category, (terminatedBy.get(category) ?? 0) + 1);
            const { results: events } = await ctx.db
              .prepare("SELECT actor_user_id FROM audit_events WHERE action = 'SESSION_TERMINATED' AND resource_id = ? ORDER BY timestamp")
              .bind(s.sessionId)
              .all<{ actor_user_id: string | null }>();
            const sequence = (events ?? [])
              .map((e) => (e.actor_user_id === s.topo.alice.id ? 'Alice' : e.actor_user_id === null ? 'null' : '其他'))
              .join(', ');
            actorSequences.set(sequence, (actorSequences.get(sequence) ?? 0) + 1);
          });
        },
        { runs: PROPERTY_RUNS, seed: seedFromEnv() },
      );
      t.diagnostic(
        `观察（非判定）：所有者断开后 ssh_sessions.terminated_by 取值分布：${[...terminatedBy].map(([k, n]) => `${k} × ${n}`).join('；')}；` +
          `SESSION_TERMINATED actor 序列：${[...actorSequences].map(([k, n]) => `[${k}] × ${n}`).join('；')}。` +
          '用户主动断开记录 SESSION_CLOSED，管理员强制终止另记 SESSION_TERMINATED。',
      );
    });
  });

  // Feature: v1-compliance-review, Property 5: RBAC 路由守卫
  //
  // Role × route matrix (design C6.5 / Property 5, AGENTS.md §10–§12), one independent case per (role, route):
  //   - User             → every /api/admin/* route of src/api/router.ts, GET and mutations, including the monitor
  //                        WebSocket upgrade (§10: asset access never implies system administration);
  //   - Security Auditor → mutation routes of users (user groups included, §74 "Admin / Users"), assets (accounts,
  //                        asset groups and the host-key reset included), credentials and authorizations
  //                        (§12: 默认不能修改资产和权限);
  //   - Asset Admin      → routes guarded by user.* and settings.* (the recording-retention cleanup trigger included)
  //                        (§12: 不能 user.* / settings.*).
  // Built-in role permissions come from migrations/0002_initial_roles_permissions.sql (Asset Admin: asset.% /
  // credential.% / authorization.%; Security Auditor: session.view_all / session.monitor / audit.read; User:
  // session.view_own); the matrix self-check below prints them as a diagnostic.
  //
  // Each denial case seeds one fixture (seedDemoTopology plus spare user / group / asset / credential / rule, a second
  // requester per privileged role, a host-key row and an Alice session) and runs PROPERTY_RUNS iterations against it. A
  // rejected request must not change D1, so the fixture is reused and every iteration is compared with the baseline taken
  // after setup; an accepted request (gap) fails that iteration and ends the case.
  // Randomized per iteration: the requester (two users per role), the credential transport (Cookie, Cookie with noise
  // cookies, Authorization: Bearer), Sec-Fetch-Site, User-Agent, CF-Connecting-IP, spoofed identity headers (X-User-Id of
  // the Super Admin, X-Roles, X-Permissions), the path target (fixture ids of the resource kind, the requester itself,
  // random ids, the session's DO hex id), realistic and privilege-escalating bodies, and query strings.
  //
  // [判定] per request: status 403; the body carries only jsonError's { error, details } and none of the fixture's
  // management values (ids, names, hostnames, host-key fingerprint, credential plaintexts, role / permission / setting /
  // audit markers; values the request itself carried are excluded); the D1 fingerprint is unchanged; no Worker →
  // SSHSessionDO call. The D1 fingerprint is a per-table SHA-256 over every row and column (quote()-encoded,
  // order-independent) that excludes only auth_sessions.last_seen_at, which validateSession() refreshes on every
  // authenticated request (src/auth/auth-service.ts:414-418) — so row counts AND in-place UPDATEs are both caught.
  // Positive control (D9): Super Admin is not denied on any route (realistic requests in a fresh fixture; every
  // positive-control write must change the D1 fingerprint, proving the D1 assertion is not vacuous).
  // All cases are required regressions. Failure messages carry role, route template and variant labels only,
  // never request or stored values. Original gap evidence remains in docs/compliance/.
  describe('Property 5: RBAC 路由守卫（§10–§12、§92 第 5 条）', () => {
    type P5Role = 'User' | 'Security Auditor' | 'Asset Admin';
    const P5_ROLES: readonly P5Role[] = ['User', 'Security Auditor', 'Asset Admin'];
    type P5Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    type P5Area = 'users' | 'groups' | 'assets' | 'credentials' | 'authorizations' | 'sessions' | 'settings' | 'audit';

    /** Areas whose mutation routes Security Auditor must not reach (§12). */
    const AUDITOR_DENIED_AREAS: ReadonlySet<P5Area> = new Set<P5Area>(['users', 'groups', 'assets', 'credentials', 'authorizations']);
    /** Areas (user.* / settings.* guarded routes) Asset Admin must not reach at all (§12). */
    const ASSET_ADMIN_DENIED_AREAS: ReadonlySet<P5Area> = new Set<P5Area>(['users', 'settings']);
    /** Columns excluded from the D1 fingerprint (`table.column`). */
    const FINGERPRINT_EXCLUDED_COLUMNS: ReadonlySet<string> = new Set(['auth_sessions.last_seen_at']);
    const SETTING_KEYS: readonly string[] = [
      'session_idle_timeout',
      'session_max_duration',
      'terminate_active_sessions_on_disable',
      'require_mfa_for_all',
      'recording_retention_days',
    ];

    interface P5Requester extends SeededUser {
      /** Secret-free label used in failure messages. */
      label: string;
    }

    interface D1FingerprintProbe {
      tables: string[];
      /** table -> SHA-256 of its rows (order-independent). */
      take(): Promise<Map<string, string>>;
    }

    interface P5Fixture {
      ctx: ComplianceContext;
      topo: DemoTopology;
      requesters: Record<P5Role, P5Requester[]>;
      spareUser: { id: string; username: string };
      spareGroup: { id: string; name: string };
      spareAsset: { id: string; name: string };
      spareCredential: { id: string; name: string };
      spareRule: { id: string; name: string };
      sessionId: string;
      /** Hex id the mock namespace derived for the session's DO (a valid idFromString() input). */
      doHexId: string;
      /** Management values a denial response must not contain (field labels are secret-free). */
      needles: Array<{ field: string; value: string }>;
      fingerprint: D1FingerprintProbe;
    }

    interface P5Request {
      path: string;
      body?: unknown;
      /** Secret-free description of the generated variant. */
      variant: string;
    }

    interface P5Positive extends P5Request {
      /** '2xx', or the exact status a reachable-but-unusable route returns after the guard passed. */
      expect: '2xx' | number;
      note?: string;
    }

    interface P5Route {
      method: P5Method;
      /** Path template with `:id` placeholders as in design C6.6. */
      template: string;
      area: P5Area;
      /** Permission guard of the handler in src/api/router.ts (null = no permission check). */
      guard: string | null;
      upgrade?: boolean;
      /** The Super Admin positive-control request writes to D1. */
      writes: boolean;
      /** Random request for the denial property. */
      gen(rng: Rng, f: P5Fixture, self: P5Requester): P5Request;
      /** Realistic request for the Super Admin positive control (fresh fixture). */
      positive(f: P5Fixture): P5Positive;
    }

    interface P5Transport {
      cookie: string | null;
      headers: Record<string, string>;
      label: string;
    }

    type Choice = readonly [label: string, id: string];

    function quoteSqlIdentifier(name: string): string {
      return `"${name.replace(/"/g, '""')}"`;
    }

    /** One compound query over every user table; returns per-table digests (never cell values). */
    async function createFingerprintProbe(db: D1Database): Promise<D1FingerprintProbe> {
      const { results } = await db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .all<{ name: string }>();
      const tables = (results ?? []).map((row) => row.name);
      assert.ok(tables.length > 0, 'fixture: 测试数据库应包含数据表');
      const selects: string[] = [];
      for (const [index, table] of tables.entries()) {
        const { results: columnRows } = await db
          .prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid')
          .bind(table)
          .all<{ name: string }>();
        const columns = (columnRows ?? [])
          .map((row) => row.name)
          .filter((column) => !FINGERPRINT_EXCLUDED_COLUMNS.has(`${table}.${column}`));
        assert.ok(columns.length > 0, `fixture: 数据表 ${table} 没有可比较的列`);
        const rowExpr = columns.map((column) => `quote(${quoteSqlIdentifier(column)})`).join(' || char(31) || ');
        selects.push(`(SELECT group_concat(r, char(30)) FROM (SELECT ${rowExpr} AS r FROM ${quoteSqlIdentifier(table)})) AS f${index}`);
      }
      const sql = `SELECT ${selects.join(', ')}`;
      return {
        tables,
        async take(): Promise<Map<string, string>> {
          const row = await db.prepare(sql).first<Record<string, unknown>>();
          assert.ok(row, 'fixture: D1 指纹查询应返回一行');
          const digests = new Map<string, string>();
          tables.forEach((table, index) => {
            const raw = row[`f${index}`];
            const rows = raw === null || raw === undefined ? [] : String(raw).split('\u001e').sort();
            digests.set(table, createHash('sha256').update(rows.join('\u001e'), 'utf8').digest('hex'));
          });
          return digests;
        },
      };
    }

    /** Names of the tables whose digest differs (never values). */
    function changedTables(before: Map<string, string>, after: Map<string, string>): string[] {
      const names = new Set([...before.keys(), ...after.keys()]);
      return [...names].filter((table) => before.get(table) !== after.get(table)).sort();
    }

    async function seedP5User(db: D1Database, username: string, role: 'Security Auditor' | 'Asset Admin'): Promise<SeededUser> {
      const row = await insertUser(db, { username, roles: [role] });
      return { ...row, cookie: await issueCookie(db, row.id) };
    }

    function requester(user: SeededUser, label: string): P5Requester {
      return { ...user, label };
    }

    async function setupP5Fixture(ctx: ComplianceContext): Promise<P5Fixture> {
      const db = ctx.db;
      const topo = await seedDemoTopology(ctx, `EJ-SECRET-${randomUUID()}`);
      const auditor2 = await seedP5User(db, 'p5-auditor-2', 'Security Auditor');
      const assetAdmin2 = await seedP5User(db, 'p5-asset-admin-2', 'Asset Admin');
      const spareUser = await insertUser(db, { username: 'p5-spare-user', roles: ['User'] });
      const spareGroup = await createGroup({ name: 'P5-Spare-Group' }, topo.admin.id, db);
      const spareAsset = await createAsset(
        { name: 'p5-spare-asset', hostname: '9.9.9.9', port: 2222, platform: 'linux', environment: 'staging' },
        topo.admin.id,
        db,
      );
      const spareSecret = `EJ-P5-SPARE-${randomUUID()}`;
      const spareCredential = await createCredential({ name: 'p5-spare-cred', type: 'password', secret: spareSecret }, ctx.kek, db);
      const spareRule = await createAuthorizationRule(
        {
          name: 'P5 spare rule',
          userIds: [topo.bob.id],
          assetIds: [topo.prodDb01.id],
          accountIds: [topo.dba.id],
          actions: ['connect'],
          enabled: false,
        },
        topo.admin.id,
        db,
      );
      const hostKeyFingerprint = `SHA256:p5-${randomUUID()}`;
      const now = Date.now();
      await db
        .prepare(
          `INSERT INTO ssh_host_keys (id, asset_id, algorithm, fingerprint, public_key, verified_at, verified_by, status, created_at)
           VALUES (?, ?, 'ssh-ed25519', ?, ?, ?, 'system-tofu', 'verified', ?)`
        )
        .bind(`hk_${randomUUID()}`, topo.prodWeb01.id, hostKeyFingerprint, `AAAAC3NzaC1lZDI1NTE5-p5-${randomUUID()}`, now, now)
        .run();

      const created = await api(ctx, 'POST', '/api/sessions', {
        cookie: topo.alice.cookie,
        body: { assetId: topo.prodWeb01.id, accountId: topo.deploy.id },
      });
      assert.equal(created.status, 201, `前置失败：Alice 创建会话 POST /api/sessions 返回 ${created.status}`);
      const sessionId: unknown = created.json?.sessionId;
      assert.ok(typeof sessionId === 'string' && sessionId !== '', '前置失败：创建会话响应缺少 sessionId');
      await flushAsync();

      const needles: Array<{ field: string; value: string }> = [
        { field: 'admin.id', value: topo.admin.id },
        { field: 'assetAdmin.id', value: topo.assetAdmin.id },
        { field: 'auditor.id', value: topo.auditor.id },
        { field: 'alice.id', value: topo.alice.id },
        { field: 'bob.id', value: topo.bob.id },
        { field: 'auditor2.id', value: auditor2.id },
        { field: 'assetAdmin2.id', value: assetAdmin2.id },
        { field: 'spareUser.id', value: spareUser.id },
        { field: 'username(asset-admin)', value: topo.assetAdmin.username },
        { field: 'username(auditor)', value: topo.auditor.username },
        { field: 'username(alice)', value: topo.alice.username },
        { field: 'username(spare)', value: spareUser.username },
        { field: 'developers.id', value: topo.developers.id },
        { field: 'developers.name', value: topo.developers.name },
        { field: 'spareGroup.id', value: spareGroup.id },
        { field: 'spareGroup.name', value: spareGroup.name },
        { field: 'production.id', value: topo.production.id },
        { field: 'production.name', value: topo.production.name },
        { field: 'web.id', value: topo.web.id },
        { field: 'prodWeb01.id', value: topo.prodWeb01.id },
        { field: 'prodWeb01.name', value: topo.prodWeb01.name },
        { field: 'prodWeb01.hostname', value: topo.prodWeb01.hostname },
        { field: 'prodDb01.id', value: topo.prodDb01.id },
        { field: 'prodDb01.name', value: topo.prodDb01.name },
        { field: 'prodDb01.hostname', value: topo.prodDb01.hostname },
        { field: 'spareAsset.id', value: spareAsset.id },
        { field: 'spareAsset.name', value: spareAsset.name },
        { field: 'spareAsset.hostname', value: spareAsset.hostname },
        { field: 'deploy.id', value: topo.deploy.id },
        { field: 'root.id', value: topo.root.id },
        { field: 'dba.id', value: topo.dba.id },
        { field: 'deployKey.id', value: topo.deployKey.id },
        { field: 'deployKey.name', value: topo.deployKey.name },
        { field: 'rootPassword.id', value: topo.rootPassword.id },
        { field: 'rootPassword.name', value: topo.rootPassword.name },
        { field: 'spareCredential.id', value: spareCredential.id },
        { field: 'spareCredential.name', value: spareCredential.name },
        { field: 'secret(deployKey)', value: topo.secrets.deployKey },
        { field: 'secret(rootPassword)', value: topo.secrets.rootPassword },
        { field: 'secret(spare)', value: spareSecret },
        { field: 'rule.id', value: topo.rule.id },
        { field: 'rule.name', value: topo.rule.name },
        { field: 'spareRule.id', value: spareRule.id },
        { field: 'session.id', value: sessionId },
        { field: 'hostKey.fingerprint', value: hostKeyFingerprint },
        { field: 'role(Super Admin)', value: 'Super Admin' },
        { field: 'role(Security Auditor)', value: 'Security Auditor' },
        { field: 'permission(user.read)', value: 'user.read' },
        { field: 'setting(session_idle_timeout)', value: 'session_idle_timeout' },
        { field: 'audit(GROUP_CREATED)', value: 'GROUP_CREATED' },
      ];

      return {
        ctx,
        topo,
        requesters: {
          User: [requester(topo.alice, 'alice'), requester(topo.bob, 'bob')],
          'Security Auditor': [requester(topo.auditor, 'auditor'), requester(auditor2, 'auditor-2')],
          'Asset Admin': [requester(topo.assetAdmin, 'asset-admin'), requester(assetAdmin2, 'asset-admin-2')],
        },
        spareUser,
        spareGroup: { id: spareGroup.id, name: spareGroup.name },
        spareAsset: { id: spareAsset.id, name: spareAsset.name },
        spareCredential: { id: spareCredential.id, name: spareCredential.name },
        spareRule: { id: spareRule.id, name: spareRule.name },
        sessionId,
        doHexId: ctx.sessions.idFromName(sessionId).toString(),
        needles,
        fingerprint: await createFingerprintProbe(db),
      };
    }

    // --- request building blocks ---

    function fill(template: string, id: string): string {
      return template.replace(':id', encodeURIComponent(id));
    }

    function junkQuery(rng: Rng): string {
      return rng.bool(0.3) ? `?_=${rng.hex(3)}` : '';
    }

    function choose(rng: Rng, choices: readonly Choice[]): { label: string; id: string } {
      const [label, id] = rng.pick(choices);
      return { label, id };
    }

    function userTargets(rng: Rng, f: P5Fixture, self: P5Requester): Choice[] {
      return [
        ['请求者本人', self.id],
        ['alice', f.topo.alice.id],
        ['bob', f.topo.bob.id],
        ['Super Admin', f.topo.admin.id],
        ['spare-user', f.spareUser.id],
        ['随机ID', randomId(rng, 'usr_')],
      ];
    }

    function groupTargets(rng: Rng, f: P5Fixture): Choice[] {
      return [
        ['Developers', f.topo.developers.id],
        ['spare-group', f.spareGroup.id],
        ['随机ID', randomId(rng, 'grp_')],
      ];
    }

    function assetTargets(rng: Rng, f: P5Fixture): Choice[] {
      return [
        ['prod-web-01', f.topo.prodWeb01.id],
        ['prod-db-01', f.topo.prodDb01.id],
        ['spare-asset', f.spareAsset.id],
        ['随机ID', randomId(rng, 'asset_')],
      ];
    }

    function credentialTargets(rng: Rng, f: P5Fixture): Choice[] {
      return [
        ['prod-deploy-key', f.topo.deployKey.id],
        ['prod-root-password', f.topo.rootPassword.id],
        ['spare-cred', f.spareCredential.id],
        ['随机ID', randomId(rng, 'cred_')],
      ];
    }

    function ruleTargets(rng: Rng, f: P5Fixture): Choice[] {
      return [
        ['Developers 规则', f.topo.rule.id],
        ['spare-rule', f.spareRule.id],
        ['随机ID', randomId(rng, 'rule_')],
      ];
    }

    function sessionTargets(rng: Rng, f: P5Fixture): Choice[] {
      return [
        ['alice 会话', f.sessionId],
        ['会话 DO hex ID', f.doHexId],
        ['随机ID', randomId(rng, 'sess_')],
      ];
    }

    /** No body, an empty object or a reason, for action routes that take no meaningful body. */
    function actionBody(rng: Rng): { body: unknown; label: string } {
      return rng.pick([
        { body: undefined, label: '无请求体' },
        { body: {}, label: '空对象' },
        { body: { reason: `p5-${rng.hex(2)}` }, label: 'reason' },
      ]);
    }

    function targeted(
      template: string,
      target: { label: string; id: string },
      body: unknown,
      bodyLabel: string,
    ): P5Request {
      return { path: fill(template, target.id), body, variant: `目标 ${target.label}，请求体 ${bodyLabel}` };
    }

    /** GET route without path parameters. */
    function listRoute(
      template: string,
      area: P5Area,
      guard: string | null,
      query: (rng: Rng) => string = junkQuery,
      positiveQuery: string = '',
    ): P5Route {
      return {
        method: 'GET',
        template,
        area,
        guard,
        writes: false,
        gen: (rng) => {
          const q = query(rng);
          return { path: `${template}${q}`, variant: `查询串 ${q || '无'}` };
        },
        positive: () => ({ path: `${template}${positiveQuery}`, variant: '读取', expect: '2xx' }),
      };
    }

    // --- route table: every /api/admin/* handler of src/api/router.ts, in router order ---

    const P5_ROUTES: readonly P5Route[] = [
      // Users (user.*), §70
      listRoute('/api/admin/users', 'users', 'user.read'),
      {
        method: 'POST',
        template: '/api/admin/users',
        area: 'users',
        guard: 'user.create',
        writes: true,
        gen: (rng) => {
          const username = `p5-new-${rng.hex(3)}`;
          const password = `P5-Pass-${rng.hex(6)}`;
          const [label, body] = rng.pick([
            ['普通用户', { username, password, roles: ['User'] }],
            ['提权 roles=Super Admin', { username, password, roles: ['Super Admin'] }],
            ['提权 多角色 + Developers', { username, password, roles: ['Asset Admin', 'Security Auditor'], groups: ['Developers'] }],
          ] as const);
          return { path: '/api/admin/users', body, variant: `请求体 ${label}` };
        },
        positive: () => ({
          path: '/api/admin/users',
          body: { username: 'p5-created-user', password: 'P5-Positive-Pass-1', roles: ['User'] },
          variant: '创建 User 用户',
          expect: '2xx',
        }),
      },
      {
        method: 'PATCH',
        template: '/api/admin/users/:id',
        area: 'users',
        guard: 'user.update',
        writes: true,
        gen: (rng, f, self) => {
          const target = choose(rng, userTargets(rng, f, self));
          const [label, body] = rng.pick([
            ['displayName', { displayName: `P5 ${rng.hex(3)}` }],
            ['提权 roles=Super Admin', { roles: ['Super Admin'] }],
            ['加入 Developers', { groups: ['Developers'] }],
            ['email', { email: `p5-${rng.hex(3)}@example.invalid` }],
          ] as const);
          return targeted('/api/admin/users/:id', target, body, label);
        },
        positive: (f) => ({
          path: fill('/api/admin/users/:id', f.spareUser.id),
          body: { displayName: 'P5 Renamed' },
          variant: '修改 spare-user 显示名',
          expect: '2xx',
        }),
      },
      {
        method: 'POST',
        template: '/api/admin/users/:id/disable',
        area: 'users',
        guard: 'user.disable',
        writes: true,
        gen: (rng, f, self) => {
          const { body, label } = actionBody(rng);
          return targeted('/api/admin/users/:id/disable', choose(rng, userTargets(rng, f, self)), body, label);
        },
        positive: (f) => ({ path: fill('/api/admin/users/:id/disable', f.spareUser.id), variant: '禁用 spare-user', expect: '2xx' }),
      },
      {
        method: 'POST',
        template: '/api/admin/users/:id/enable',
        area: 'users',
        guard: 'user.disable | user.update',
        writes: true,
        gen: (rng, f, self) => {
          const { body, label } = actionBody(rng);
          return targeted('/api/admin/users/:id/enable', choose(rng, userTargets(rng, f, self)), body, label);
        },
        positive: (f) => ({ path: fill('/api/admin/users/:id/enable', f.spareUser.id), variant: '启用 spare-user', expect: '2xx' }),
      },
      {
        method: 'POST',
        template: '/api/admin/users/:id/reset-password',
        area: 'users',
        guard: 'user.update',
        writes: true,
        gen: (rng, f, self) =>
          targeted(
            '/api/admin/users/:id/reset-password',
            choose(rng, userTargets(rng, f, self)),
            { password: `P5-Reset-${rng.hex(6)}` },
            '新密码',
          ),
        positive: (f) => ({
          path: fill('/api/admin/users/:id/reset-password', f.spareUser.id),
          body: { password: 'P5-Positive-Reset-1' },
          variant: '重置 spare-user 密码',
          expect: '2xx',
        }),
      },
      // User groups (group.*), §13
      listRoute('/api/admin/groups', 'groups', 'group.read'),
      {
        method: 'POST',
        template: '/api/admin/groups',
        area: 'groups',
        guard: 'group.write',
        writes: true,
        gen: (rng) => {
          const body = rng.bool(0.5) ? { name: `P5-${rng.hex(3)}` } : { name: `P5-${rng.hex(3)}`, description: `p5 ${rng.hex(2)}` };
          return { path: '/api/admin/groups', body, variant: `请求体 ${'description' in body ? 'name + description' : 'name'}` };
        },
        positive: () => ({ path: '/api/admin/groups', body: { name: 'P5-Created-Group' }, variant: '创建用户组', expect: '2xx' }),
      },
      {
        method: 'PATCH',
        template: '/api/admin/groups/:id',
        area: 'groups',
        guard: 'group.write',
        writes: true,
        gen: (rng, f, self) => {
          const [label, body] = rng.pick([
            ['改名', { name: `P5-${rng.hex(3)}` }],
            ['把请求者加入成员', { members: [self.id] }],
            ['清空成员', { members: [] as string[] }],
          ] as const);
          return targeted('/api/admin/groups/:id', choose(rng, groupTargets(rng, f)), body, label);
        },
        positive: (f) => ({
          path: fill('/api/admin/groups/:id', f.spareGroup.id),
          body: { name: 'P5-Spare-Group-Renamed' },
          variant: '修改 spare-group 名称',
          expect: '2xx',
        }),
      },
      {
        method: 'DELETE',
        template: '/api/admin/groups/:id',
        area: 'groups',
        guard: 'group.write',
        writes: true,
        gen: (rng, f) => targeted('/api/admin/groups/:id', choose(rng, groupTargets(rng, f)), undefined, '无'),
        positive: (f) => ({ path: fill('/api/admin/groups/:id', f.spareGroup.id), variant: '删除 spare-group', expect: '2xx' }),
      },
      // Roles list (guarded by user.read)
      listRoute('/api/admin/roles', 'users', 'user.read'),
      // Assets (asset.*), §14
      listRoute('/api/admin/assets', 'assets', 'asset.read'),
      {
        method: 'POST',
        template: '/api/admin/assets',
        area: 'assets',
        guard: 'asset.create',
        writes: true,
        gen: (rng, f) => {
          const body: Record<string, unknown> = {
            name: `p5-asset-${rng.hex(3)}`,
            hostname: rng.pick(PUBLIC_HOSTS),
            port: rng.bool(0.5) ? 22 : rng.int(1024, 65535),
            platform: 'linux',
            environment: rng.pick(['production', 'staging']),
          };
          const inGroup = rng.bool(0.5);
          if (inGroup) body.groupIds = [f.topo.web.id];
          return { path: '/api/admin/assets', body, variant: `请求体 资产${inGroup ? ' + 资产组' : ''}` };
        },
        positive: () => ({
          path: '/api/admin/assets',
          body: { name: 'p5-created-asset', hostname: '9.9.9.9', port: 22, platform: 'linux', environment: 'staging' },
          variant: '创建资产',
          expect: '2xx',
        }),
      },
      {
        method: 'PATCH',
        template: '/api/admin/assets/:id',
        area: 'assets',
        guard: 'asset.update',
        writes: true,
        gen: (rng, f) => {
          const [label, body] = rng.pick([
            ['改名', { name: `p5-${rng.hex(3)}` }],
            ['改连接目标', { hostname: rng.pick(PUBLIC_HOSTS), port: rng.int(1, 65535) }],
            ['停用', { enabled: false }],
            ['改资产组', { groupIds: [f.topo.production.id] }],
          ] as const);
          return targeted('/api/admin/assets/:id', choose(rng, assetTargets(rng, f)), body, label);
        },
        positive: (f) => ({
          path: fill('/api/admin/assets/:id', f.spareAsset.id),
          body: { name: 'p5-spare-asset-renamed' },
          variant: '修改 spare-asset 名称',
          expect: '2xx',
        }),
      },
      {
        method: 'DELETE',
        template: '/api/admin/assets/:id',
        area: 'assets',
        guard: 'asset.delete',
        writes: true,
        gen: (rng, f) => targeted('/api/admin/assets/:id', choose(rng, assetTargets(rng, f)), undefined, '无'),
        positive: (f) => ({ path: fill('/api/admin/assets/:id', f.spareAsset.id), variant: '删除 spare-asset', expect: '2xx' }),
      },
      {
        method: 'GET',
        template: '/api/admin/assets/:id/accounts',
        area: 'assets',
        guard: 'asset.read',
        writes: false,
        gen: (rng, f) => {
          const target = choose(rng, assetTargets(rng, f));
          return { path: `${fill('/api/admin/assets/:id/accounts', target.id)}${junkQuery(rng)}`, variant: `目标 ${target.label}` };
        },
        positive: (f) => ({ path: fill('/api/admin/assets/:id/accounts', f.topo.prodWeb01.id), variant: '读取 prod-web-01 账号', expect: '2xx' }),
      },
      {
        method: 'POST',
        template: '/api/admin/assets/:id/accounts',
        area: 'assets',
        guard: 'credential.create',
        writes: true,
        gen: (rng, f) =>
          targeted(
            '/api/admin/assets/:id/accounts',
            choose(rng, assetTargets(rng, f)),
            { username: rng.pick(['root', 'ops', `p5-${rng.hex(2)}`]), credentialId: choose(rng, credentialTargets(rng, f)).id },
            'username + credentialId',
          ),
        positive: (f) => ({
          path: fill('/api/admin/assets/:id/accounts', f.spareAsset.id),
          body: { username: 'ops', credentialId: f.spareCredential.id },
          variant: '为 spare-asset 创建账号',
          expect: '2xx',
        }),
      },
      // Asset groups, §15
      listRoute('/api/admin/asset-groups', 'assets', null),
      {
        method: 'POST',
        template: '/api/admin/asset-groups',
        area: 'assets',
        guard: 'asset.create',
        writes: true,
        gen: (rng, f) => {
          const [label, parentId] = rng.pick([
            ['顶层', null],
            ['Production 子组', f.topo.production.id],
            ['Web 子组', f.topo.web.id],
          ] as const);
          return { path: '/api/admin/asset-groups', body: { name: `P5-AG-${rng.hex(3)}`, parentId }, variant: `请求体 ${label}` };
        },
        positive: (f) => ({
          path: '/api/admin/asset-groups',
          body: { name: 'P5-Created-AG', parentId: f.topo.production.id },
          variant: '创建资产组',
          expect: '2xx',
        }),
      },
      // Credentials (credential.*), §18, §71
      listRoute('/api/admin/credentials', 'credentials', 'credential.create'),
      {
        method: 'POST',
        template: '/api/admin/credentials',
        area: 'credentials',
        guard: 'credential.create',
        writes: true,
        gen: (rng) => {
          const type = rng.pick(['password', 'private_key'] as const);
          return {
            path: '/api/admin/credentials',
            body: { name: `p5-cred-${rng.hex(3)}`, type, secret: `EJ-P5-SECRET-${rng.hex(8)}` },
            variant: `请求体 ${type}`,
          };
        },
        positive: () => ({
          path: '/api/admin/credentials',
          body: { name: 'p5-created-cred', type: 'password', secret: `EJ-P5-POSITIVE-${randomUUID()}` },
          variant: '创建凭证',
          expect: '2xx',
        }),
      },
      {
        method: 'PUT',
        template: '/api/admin/credentials/:id',
        area: 'credentials',
        guard: 'credential.replace',
        writes: true,
        gen: (rng, f) =>
          targeted('/api/admin/credentials/:id', choose(rng, credentialTargets(rng, f)), { secret: `EJ-P5-SECRET-${rng.hex(8)}` }, 'secret'),
        positive: (f) => ({
          path: fill('/api/admin/credentials/:id', f.spareCredential.id),
          body: { secret: `EJ-P5-POSITIVE-${randomUUID()}` },
          variant: '替换 spare-cred',
          expect: '2xx',
        }),
      },
      {
        method: 'DELETE',
        template: '/api/admin/credentials/:id',
        area: 'credentials',
        guard: 'credential.delete',
        writes: true,
        gen: (rng, f) => targeted('/api/admin/credentials/:id', choose(rng, credentialTargets(rng, f)), undefined, '无'),
        positive: (f) => ({ path: fill('/api/admin/credentials/:id', f.spareCredential.id), variant: '删除 spare-cred', expect: '2xx' }),
      },
      // Authorization rules (authorization.*), §23–§29, §72
      listRoute('/api/admin/authorizations', 'authorizations', 'authorization.read'),
      {
        method: 'POST',
        template: '/api/admin/authorizations',
        area: 'authorizations',
        guard: 'authorization.write',
        writes: true,
        gen: (rng, f, self) => {
          const allAccounts = rng.bool(0.3);
          const actions = rng.pick([['connect'], ['connect', 'port_forward'], []] as const);
          return {
            path: '/api/admin/authorizations',
            body: {
              name: `P5 rule ${rng.hex(3)}`,
              userIds: [self.id],
              assetIds: [rng.pick([f.topo.prodWeb01.id, f.topo.prodDb01.id])],
              accountIds: allAccounts ? [] : [rng.pick([f.topo.root.id, f.topo.dba.id, f.topo.deploy.id])],
              allAccounts,
              actions,
            },
            variant: `请求体 授权请求者本人${allAccounts ? '（@ALL）' : ''}，动作 [${actions.join(', ')}]`,
          };
        },
        positive: (f) => ({
          path: '/api/admin/authorizations',
          body: {
            name: 'P5 created rule',
            userIds: [f.topo.bob.id],
            assetIds: [f.topo.prodDb01.id],
            accountIds: [f.topo.dba.id],
            actions: ['connect'],
          },
          variant: '创建授权规则',
          expect: '2xx',
        }),
      },
      {
        method: 'PATCH',
        template: '/api/admin/authorizations/:id',
        area: 'authorizations',
        guard: 'authorization.write',
        writes: true,
        gen: (rng, f, self) => {
          const [label, body] = rng.pick([
            ['把请求者加入主体', { userIds: [self.id] }],
            ['@ALL 账号', { allAccounts: true }],
            ['启用', { enabled: true }],
            ['取消有效期', { validFrom: null, validUntil: null }],
          ] as const);
          return targeted('/api/admin/authorizations/:id', choose(rng, ruleTargets(rng, f)), body, label);
        },
        positive: (f) => ({
          path: fill('/api/admin/authorizations/:id', f.spareRule.id),
          body: { enabled: true },
          variant: '启用 spare-rule',
          expect: '2xx',
        }),
      },
      {
        method: 'DELETE',
        template: '/api/admin/authorizations/:id',
        area: 'authorizations',
        guard: 'authorization.write',
        writes: true,
        gen: (rng, f) => targeted('/api/admin/authorizations/:id', choose(rng, ruleTargets(rng, f)), undefined, '无'),
        positive: (f) => ({ path: fill('/api/admin/authorizations/:id', f.spareRule.id), variant: '删除 spare-rule', expect: '2xx' }),
      },
      // Sessions (session.*), §47–§49, §73
      listRoute(
        '/api/admin/sessions',
        'sessions',
        'session.view_all',
        (rng) => rng.pick(['', '?type=online', '?type=historical', `?type=${rng.hex(2)}`]),
        '?type=online',
      ),
      {
        method: 'POST',
        template: '/api/admin/sessions/:id/terminate',
        area: 'sessions',
        guard: 'session.terminate',
        writes: true,
        gen: (rng, f) => {
          const { body, label } = actionBody(rng);
          return targeted('/api/admin/sessions/:id/terminate', choose(rng, sessionTargets(rng, f)), body, label);
        },
        positive: (f) => ({ path: fill('/api/admin/sessions/:id/terminate', f.sessionId), variant: '终止 alice 会话', expect: '2xx' }),
      },
      {
        method: 'GET',
        template: '/api/admin/sessions/:id/monitor',
        area: 'sessions',
        guard: 'session.monitor',
        upgrade: true,
        writes: false,
        gen: (rng, f) => {
          const target = choose(rng, sessionTargets(rng, f));
          return { path: fill('/api/admin/sessions/:id/monitor', target.id), variant: `目标 ${target.label}` };
        },
        positive: (f) => ({
          path: fill('/api/admin/sessions/:id/monitor', f.sessionId),
          variant: '监控 alice 会话',
          expect: 101,
        }),
      },
      // Host keys (asset.read / asset.update), §39–§42
      {
        method: 'GET',
        template: '/api/admin/assets/:id/host-key',
        area: 'assets',
        guard: 'asset.read',
        writes: false,
        gen: (rng, f) => {
          const target = choose(rng, assetTargets(rng, f));
          return { path: `${fill('/api/admin/assets/:id/host-key', target.id)}${junkQuery(rng)}`, variant: `目标 ${target.label}` };
        },
        positive: (f) => ({ path: fill('/api/admin/assets/:id/host-key', f.topo.prodWeb01.id), variant: '读取 prod-web-01 Host Key', expect: '2xx' }),
      },
      {
        method: 'POST',
        template: '/api/admin/assets/:id/host-key/reset',
        area: 'assets',
        guard: 'asset.update',
        writes: true,
        gen: (rng, f) => {
          const { body, label } = actionBody(rng);
          return targeted('/api/admin/assets/:id/host-key/reset', choose(rng, assetTargets(rng, f)), body, label);
        },
        positive: (f) => ({
          path: fill('/api/admin/assets/:id/host-key/reset', f.topo.prodWeb01.id),
          variant: '重置 prod-web-01 Host Key',
          expect: '2xx',
        }),
      },
      {
        method: 'GET',
        template: '/api/admin/sessions/:id',
        area: 'sessions',
        guard: 'session.view_all',
        writes: false,
        gen: (rng, f) => {
          const target = choose(rng, sessionTargets(rng, f));
          return { path: `${fill('/api/admin/sessions/:id', target.id)}${junkQuery(rng)}`, variant: `目标 ${target.label}` };
        },
        positive: (f) => ({ path: fill('/api/admin/sessions/:id', f.sessionId), variant: '读取 alice 会话', expect: '2xx' }),
      },
      {
        method: 'GET',
        template: '/api/admin/sessions/:id/commands',
        area: 'sessions',
        guard: 'audit.read | session.view_all',
        writes: false,
        gen: (rng, f) => {
          const target = choose(rng, sessionTargets(rng, f));
          return { path: `${fill('/api/admin/sessions/:id/commands', target.id)}${junkQuery(rng)}`, variant: `目标 ${target.label}` };
        },
        positive: (f) => ({ path: fill('/api/admin/sessions/:id/commands', f.sessionId), variant: '读取 alice 会话命令', expect: '2xx' }),
      },
      {
        method: 'GET',
        template: '/api/admin/sessions/:id/recording',
        area: 'sessions',
        guard: 'audit.read | session.view_all',
        writes: false,
        gen: (rng, f) => {
          const target = choose(rng, sessionTargets(rng, f));
          return { path: `${fill('/api/admin/sessions/:id/recording', target.id)}${junkQuery(rng)}`, variant: `目标 ${target.label}` };
        },
        positive: (f) => ({
          path: fill('/api/admin/sessions/:id/recording', f.sessionId),
          variant: '读取 alice 会话录像',
          expect: 404,
          note: '权限检查通过后，因测试环境未配置录像存储返回 404（§4 R2 可选）',
        }),
      },
      // System settings (settings.*), §45, §60, §61
      listRoute('/api/admin/settings', 'settings', 'settings.read'),
      {
        method: 'PATCH',
        template: '/api/admin/settings',
        area: 'settings',
        guard: 'settings.write',
        writes: true,
        gen: (rng) => {
          const key = rng.pick(SETTING_KEYS);
          return {
            path: '/api/admin/settings',
            body: { key, value: rng.pick(['0', 'false', 'true', String(rng.int(1, 99_999))]) },
            variant: `请求体 key=${key}`,
          };
        },
        positive: () => ({
          path: '/api/admin/settings',
          body: { key: 'session_idle_timeout', value: '1200' },
          variant: '修改 session_idle_timeout',
          expect: '2xx',
        }),
      },
      {
        method: 'POST',
        template: '/api/admin/recordings/cleanup',
        area: 'settings',
        guard: 'settings.write | audit.read',
        writes: false,
        gen: (rng) => {
          const { body, label } = actionBody(rng);
          return { path: '/api/admin/recordings/cleanup', body, variant: `请求体 ${label}` };
        },
        positive: () => ({ path: '/api/admin/recordings/cleanup', variant: '手动触发录像清理（无过期录像，不写 D1）', expect: '2xx' }),
      },
      // Audit log (audit.read), §57–§59
      listRoute('/api/admin/audit', 'audit', 'audit.read', (rng) => (rng.bool(0.5) ? `?limit=${rng.int(1, 500)}` : junkQuery(rng))),
    ];

    function routeKey(route: P5Route): string {
      return `${route.method} ${route.template}`;
    }

    function routeLabel(route: P5Route): string {
      return `${routeKey(route)}${route.upgrade ? '（Upgrade: websocket）' : ''}`;
    }

    function inMatrix(role: P5Role, route: P5Route): boolean {
      switch (role) {
        case 'User':
          return true;
        case 'Security Auditor':
          return route.method !== 'GET' && AUDITOR_DENIED_AREAS.has(route.area);
        case 'Asset Admin':
          return ASSET_ADMIN_DENIED_AREAS.has(route.area);
      }
    }

    function genTransport(rng: Rng, f: P5Fixture, self: P5Requester, upgrade: boolean): P5Transport {
      const headers: Record<string, string> = {
        'User-Agent': `EJ-P5-UA-${rng.hex(4)}`,
        'CF-Connecting-IP': `9.${rng.int(1, 254)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
      };
      const parts: string[] = [];
      let cookie: string | null = self.cookie;
      const transport = rng.pick(['Cookie', 'Cookie（含噪声 Cookie）', 'Authorization: Bearer'] as const);
      if (transport === 'Authorization: Bearer') {
        headers.Authorization = `Bearer ${self.cookie.slice(self.cookie.indexOf('=') + 1)}`;
        cookie = null;
      } else if (transport === 'Cookie（含噪声 Cookie）') {
        cookie = `ej_p5_${rng.hex(2)}=${rng.hex(4)}; ${self.cookie}; ej_role=${rng.pick(['admin', 'super'])}`;
      }
      parts.push(transport);
      const site = rng.pick(['缺省', 'same-origin', 'none'] as const);
      if (site !== '缺省') headers['Sec-Fetch-Site'] = site;
      parts.push(`Sec-Fetch-Site=${site}`);
      if (rng.bool(0.3)) {
        headers['X-User-Id'] = f.topo.admin.id;
        headers['X-Roles'] = 'Super Admin';
        headers['X-Permissions'] = '*';
        parts.push('伪造身份头');
      }
      if (upgrade) {
        headers.Upgrade = 'websocket';
        headers['Sec-WebSocket-Version'] = '13';
        headers['Sec-WebSocket-Key'] = btoa(rng.hex(8));
      }
      return { cookie, headers, label: parts.join('，') };
    }

    /** A denial body may only be jsonError's { error, details }. */
    function p5UnexpectedKeys(json: unknown): string[] {
      if (json === null || json === undefined) return [];
      if (Array.isArray(json)) return ['<array>'];
      if (typeof json !== 'object') return ['<non-object>'];
      return Object.keys(json as Record<string, unknown>).filter((key) => key !== 'error' && key !== 'details');
    }

    /** Field labels (never values) of fixture management data found in a response the request did not itself carry. */
    function p5LeakedFields(text: string, requestText: string, needles: P5Fixture['needles']): string[] {
      return needles
        .filter((needle) => !requestText.includes(needle.value) && text.includes(needle.value))
        .map((needle) => needle.field);
    }

    function p5IsCsrfDenial(json: unknown): boolean {
      const error = (json as { error?: unknown } | null)?.error;
      return typeof error === 'string' && error.startsWith('CSRF protection');
    }

    it('[SEC-05] RBAC 路由守卫：角色 × 路由矩阵自检', async (t) => {
      const keys = P5_ROUTES.map(routeKey);
      assert.equal(new Set(keys).size, keys.length, 'fixture: 路由表存在重复项');
      assert.equal(P5_ROUTES.length, 39, 'fixture: 路由表应覆盖 src/api/router.ts 中全部 39 个 /api/admin/* 处理分支');
      assert.ok(
        P5_ROUTES.every((route) => route.template.startsWith('/api/admin/')),
        'fixture: 路由表只应包含 /api/admin/* 路由',
      );
      const counts = Object.fromEntries(P5_ROLES.map((role) => [role, P5_ROUTES.filter((route) => inMatrix(role, route)).length]));
      assert.deepEqual(counts, { User: 39, 'Security Auditor': 20, 'Asset Admin': 10 }, 'fixture: 角色 × 路由矩阵规模与设计不一致');

      // Observation (non-judgement): the seeded permissions of each built-in role (migrations/0002).
      const db = await createTestDatabase();
      const { results } = await db
        .prepare(
          `SELECT r.name AS role, p.code AS code FROM roles r
           JOIN role_permissions rp ON rp.role_id = r.id JOIN permissions p ON p.id = rp.permission_id
           WHERE r.is_builtin = 1 ORDER BY r.name, p.code`
        )
        .all<{ role: string; code: string }>();
      const byRole = new Map<string, string[]>();
      for (const row of results ?? []) byRole.set(row.role, [...(byRole.get(row.role) ?? []), row.code]);
      for (const role of P5_ROLES) {
        const codes = byRole.get(role) ?? [];
        const granted = new Set(codes);
        const allowed = (guard: string): boolean =>
          guard.split(' | ').some((code) => granted.has('*') || granted.has(code) || granted.has(`${code.split('.')[0]}.*`));
        const seededGaps = P5_ROUTES.filter((route) => inMatrix(role, route) && route.guard !== null && allowed(route.guard)).map(routeKey);
        assert.ok(
          role !== 'Asset Admin' || codes.every((code) => !code.startsWith('user.') && !code.startsWith('settings.')),
          `[判定] Asset Admin 的内置权限包含 user.* 或 settings.*（§12；migrations/0002_initial_roles_permissions.sql）`,
        );
        t.diagnostic(
          `观察 ${role} 内置权限：${codes.join(', ') || '无'}；矩阵内被内置权限放行的路由：${seededGaps.join('；') || '无'}；` +
            `矩阵内无权限校验的路由：${P5_ROUTES.filter((route) => inMatrix(role, route) && route.guard === null).map(routeKey).join('；') || '无'}`,
        );
      }
    });

    describe('Super Admin 正向对照（D9）', () => {
      for (const route of P5_ROUTES) {
        it(`[SEC-05] 正向对照：Super Admin → ${routeLabel(route)} 未被 RBAC 拒绝`, { timeout: 60_000 }, async () => {
          await withContext(async (ctx) => {
            const f = await setupP5Fixture(ctx);
            const before = await f.fingerprint.take();
            const request = route.positive(f);
            const res = await api(ctx, route.method, request.path, {
              cookie: f.topo.admin.cookie,
              body: request.body,
              headers: route.upgrade ? { Upgrade: 'websocket', 'Sec-WebSocket-Version': '13' } : undefined,
            });
            await flushAsync();
            const where = `正向对照失败：Super Admin → ${routeLabel(route)}（${request.variant}）`;
            assert.ok(!res.threw, `${where} 处理器抛出未捕获异常`);
            assert.notEqual(res.status, 403, `${where} 返回 403`);
            assert.notEqual(res.json?.error, 'Permission denied', `${where} 被权限守卫拒绝`);
            assert.ok(!(res.status === 404 && res.json?.error === 'Not found'), `${where} 落入路由表末尾的 Not found（路由不存在）`);
            if (request.expect === '2xx') {
              assert.ok(res.status >= 200 && res.status < 300, `${where} 期望 2xx，实际 ${res.status}`);
            } else {
              assert.equal(res.status, request.expect, `${where} 期望 ${request.expect}（${request.note ?? ''}），实际 ${res.status}`);
            }
            const changed = changedTables(before, await f.fingerprint.take());
            if (route.writes) {
              assert.ok(changed.length > 0, `fixture: ${where} 写入后 D1 指纹未变化（D1 不变断言将空洞通过）`);
            } else {
              assert.deepEqual(changed, [], `fixture: ${where} 只读请求改变了 D1（${changed.join(', ')}），指纹排除项不足`);
            }
          });
        });
      }
    });

    for (const role of P5_ROLES) {
      describe(`${role} 角色`, () => {
        for (const route of P5_ROUTES.filter((candidate) => inMatrix(role, candidate))) {
          it(
            `[SEC-05] RBAC 路由守卫：${role} → ${routeLabel(route)}`,
            { timeout: 60_000 },
            async () => {
              await withContext(async (ctx) => {
                const f = await setupP5Fixture(ctx);
                const baseline = await f.fingerprint.take();
                const callMark = ctx.sessions.calls.length;
                await forAll(
                  (rng) => {
                    const self = rng.pick(f.requesters[role]);
                    return { self, request: route.gen(rng, f, self), transport: genTransport(rng, f, self, route.upgrade === true) };
                  },
                  async ({ self, request, transport }) => {
                    const label = `[SEC-05] ${role}（${self.label}）→ ${routeLabel(route)}（${request.variant}；${transport.label}）`;
                    const res = await api(ctx, route.method, request.path, {
                      cookie: transport.cookie,
                      body: request.body,
                      headers: transport.headers,
                    });
                    await flushAsync(2);

                    assert.ok(!p5IsCsrfDenial(res.json), `fixture: ${label} 被 CSRF 检查拒绝（同源请求不应触发），无法证明权限校验`);
                    assert.equal(
                      res.status,
                      403,
                      `[判定] 无权限角色访问管理路由未被拒绝（§10–§12）：${label}（期望 403，实际 ${res.status}${res.threw ? '，处理器抛出未捕获异常' : ''}）`,
                    );
                    assert.equal(res.json?.error, 'Permission denied', `fixture: ${label} 的 403 不是由权限守卫产生`);
                    const extraKeys = p5UnexpectedKeys(res.json);
                    assert.deepEqual(extraKeys, [], `[判定] 拒绝响应包含错误信息以外的字段：${label}（${extraKeys.join(', ')}）`);
                    const requestText = [
                      request.path,
                      request.body === undefined ? '' : JSON.stringify(request.body),
                      transport.cookie ?? '',
                      ...Object.values(transport.headers),
                    ].join('\n');
                    const leaks = p5LeakedFields(res.text, requestText, f.needles);
                    assert.deepEqual(leaks, [], `[判定] 拒绝响应包含管理数据：${label}（字段：${leaks.join(', ')}）`);
                    const changed = changedTables(baseline, await f.fingerprint.take());
                    assert.deepEqual(changed, [], `[判定] 被拒绝的请求改变了 D1：${label}（变化的表：${changed.join(', ')}）`);
                    const doCalls = ctx.sessions.calls.slice(callMark).map((call) => `${call.method} ${call.path}`);
                    assert.deepEqual(doCalls, [], `[判定] 被拒绝的请求触发了 SSHSessionDO 调用：${label}（${doCalls.join('，')}）`);
                  },
                  { runs: PROPERTY_RUNS, seed: seedFromEnv() },
                );
              });
            },
          );
        }
      });
    }
  });
});
