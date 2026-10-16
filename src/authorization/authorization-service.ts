import type {
  AuthorizationRuleRow,
  AssetRow,
  AssetAccountRow,
  UserRow,
  CredentialType,
} from '../types.ts';
import type { AuthorizationRuleSummary } from '../shared/types.ts';
import { getAssetGroupAncestors, getAssetGroupDescendants } from '../assets/asset-service.ts';
import { isAssetAdministrator } from '../rbac/administrators.ts';

export interface CreateAuthorizationRuleInput {
  name: string;
  description?: string | null;
  allAccounts?: boolean;
  enabled?: boolean;
  validFrom?: number | null;
  validUntil?: number | null;
  userIds?: string[];
  groupIds?: string[];
  assetIds?: string[];
  assetGroupIds?: string[];
  accountIds?: string[];
  actions?: string[];
}

export interface UpdateAuthorizationRuleInput {
  name?: string;
  description?: string | null;
  allAccounts?: boolean;
  enabled?: boolean;
  validFrom?: number | null;
  validUntil?: number | null;
  userIds?: string[];
  groupIds?: string[];
  assetIds?: string[];
  assetGroupIds?: string[];
  accountIds?: string[];
  actions?: string[];
}

import type { AuthorizedAssetAccount, AuthorizedAsset } from '../shared/types.ts';
export type { AuthorizedAssetAccount, AuthorizedAsset } from '../shared/types.ts';

export interface AccessCheckResult {
  authorized: boolean;
  reason?: string;
  matchedRuleId?: string;
}

// -------------------------------------------------------------
// Authorization Rules CRUD
// -------------------------------------------------------------

export async function createAuthorizationRule(
  input: CreateAuthorizationRuleInput,
  createdBy: string | null,
  db: D1Database
): Promise<AuthorizationRuleSummary> {
  validateRuleInput(input);
  const name = input.name.trim();
  if (!name) throw new Error('Rule name is required');

  const id = `rule_${crypto.randomUUID()}`;
  const now = Date.now();
  const allAccountsInt = input.allAccounts ? 1 : 0;
  const enabledInt = input.enabled ?? true ? 1 : 0;

  await db
    .prepare(
      `INSERT INTO authorization_rules (
        id, name, description, all_accounts, enabled,
        valid_from, valid_until, created_at, updated_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      name,
      input.description ?? null,
      allAccountsInt,
      enabledInt,
      input.validFrom ?? null,
      input.validUntil ?? null,
      now,
      now,
      createdBy
    )
    .run();

  // Insert subjects: users and user groups
  for (const uid of input.userIds ?? []) {
    await db
      .prepare('INSERT OR IGNORE INTO authorization_rule_users (rule_id, user_id) VALUES (?, ?)')
      .bind(id, uid)
      .run();
  }
  for (const gid of input.groupIds ?? []) {
    await db
      .prepare('INSERT OR IGNORE INTO authorization_rule_groups (rule_id, group_id) VALUES (?, ?)')
      .bind(id, gid)
      .run();
  }

  // Insert targets: assets and asset groups
  for (const aid of input.assetIds ?? []) {
    await db
      .prepare('INSERT OR IGNORE INTO authorization_rule_assets (rule_id, asset_id) VALUES (?, ?)')
      .bind(id, aid)
      .run();
  }
  for (const agid of input.assetGroupIds ?? []) {
    await db
      .prepare(
        'INSERT OR IGNORE INTO authorization_rule_asset_groups (rule_id, asset_group_id) VALUES (?, ?)'
      )
      .bind(id, agid)
      .run();
  }

  // Insert accounts (if not allAccounts)
  for (const accId of input.accountIds ?? []) {
    await db
      .prepare('INSERT OR IGNORE INTO authorization_rule_accounts (rule_id, account_id) VALUES (?, ?)')
      .bind(id, accId)
      .run();
  }

  // Insert actions (default 'connect')
  const actions = input.actions && input.actions.length > 0 ? input.actions : ['connect'];
  for (const action of actions) {
    await db
      .prepare('INSERT OR IGNORE INTO authorization_rule_actions (rule_id, action) VALUES (?, ?)')
      .bind(id, action)
      .run();
  }

  return {
    id,
    name,
    description: input.description ?? null,
    allAccounts: allAccountsInt === 1,
    enabled: enabledInt === 1,
    validFrom: input.validFrom ?? null,
    validUntil: input.validUntil ?? null,
    userIds: input.userIds ?? [],
    groupIds: input.groupIds ?? [],
    assetIds: input.assetIds ?? [],
    assetGroupIds: input.assetGroupIds ?? [],
    accountIds: input.accountIds ?? [],
    actions,
  };
}

export async function getAuthorizationRule(
  id: string,
  db: D1Database
): Promise<AuthorizationRuleSummary | null> {
  const rule = await db
    .prepare('SELECT * FROM authorization_rules WHERE id = ?')
    .bind(id)
    .first<AuthorizationRuleRow>();

  if (!rule) return null;

  const [users, groups, assets, assetGroups, accounts, actions] = await Promise.all([
    db
      .prepare('SELECT user_id FROM authorization_rule_users WHERE rule_id = ?')
      .bind(id)
      .all<{ user_id: string }>(),
    db
      .prepare('SELECT group_id FROM authorization_rule_groups WHERE rule_id = ?')
      .bind(id)
      .all<{ group_id: string }>(),
    db
      .prepare('SELECT asset_id FROM authorization_rule_assets WHERE rule_id = ?')
      .bind(id)
      .all<{ asset_id: string }>(),
    db
      .prepare('SELECT asset_group_id FROM authorization_rule_asset_groups WHERE rule_id = ?')
      .bind(id)
      .all<{ asset_group_id: string }>(),
    db
      .prepare('SELECT account_id FROM authorization_rule_accounts WHERE rule_id = ?')
      .bind(id)
      .all<{ account_id: string }>(),
    db
      .prepare('SELECT action FROM authorization_rule_actions WHERE rule_id = ?')
      .bind(id)
      .all<{ action: string }>(),
  ]);

  return {
    id: rule.id,
    name: rule.name,
    description: rule.description,
    allAccounts: rule.all_accounts === 1,
    enabled: rule.enabled === 1,
    validFrom: rule.valid_from,
    validUntil: rule.valid_until,
    userIds: (users.results || []).map((r) => r.user_id),
    groupIds: (groups.results || []).map((r) => r.group_id),
    assetIds: (assets.results || []).map((r) => r.asset_id),
    assetGroupIds: (assetGroups.results || []).map((r) => r.asset_group_id),
    accountIds: (accounts.results || []).map((r) => r.account_id),
    actions: (actions.results || []).map((r) => r.action),
  };
}

export async function updateAuthorizationRule(
  id: string,
  input: UpdateAuthorizationRuleInput,
  db: D1Database
): Promise<AuthorizationRuleSummary> {
  validateRuleInput(input);
  const existing = await getAuthorizationRule(id, db);
  if (!existing) throw new Error(`Authorization rule not found: ${id}`);

  const name = input.name !== undefined ? input.name.trim() : existing.name;
  if (!name) throw new Error('Rule name cannot be empty');

  const description = input.description !== undefined ? input.description : existing.description;
  const allAccountsInt =
    input.allAccounts !== undefined ? (input.allAccounts ? 1 : 0) : existing.allAccounts ? 1 : 0;
  const enabledInt =
    input.enabled !== undefined ? (input.enabled ? 1 : 0) : existing.enabled ? 1 : 0;
  const validFrom = input.validFrom !== undefined ? input.validFrom : existing.validFrom;
  const validUntil = input.validUntil !== undefined ? input.validUntil : existing.validUntil;
  validateRuleInput({ validFrom, validUntil });
  const now = Date.now();

  await db
    .prepare(
      `UPDATE authorization_rules SET
        name = ?, description = ?, all_accounts = ?, enabled = ?,
        valid_from = ?, valid_until = ?, updated_at = ?
      WHERE id = ?`
    )
    .bind(name, description, allAccountsInt, enabledInt, validFrom, validUntil, now, id)
    .run();

  if (input.userIds !== undefined) {
    await db.prepare('DELETE FROM authorization_rule_users WHERE rule_id = ?').bind(id).run();
    for (const uid of input.userIds) {
      await db
        .prepare('INSERT OR IGNORE INTO authorization_rule_users (rule_id, user_id) VALUES (?, ?)')
        .bind(id, uid)
        .run();
    }
  }

  if (input.groupIds !== undefined) {
    await db.prepare('DELETE FROM authorization_rule_groups WHERE rule_id = ?').bind(id).run();
    for (const gid of input.groupIds) {
      await db
        .prepare('INSERT OR IGNORE INTO authorization_rule_groups (rule_id, group_id) VALUES (?, ?)')
        .bind(id, gid)
        .run();
    }
  }

  if (input.assetIds !== undefined) {
    await db.prepare('DELETE FROM authorization_rule_assets WHERE rule_id = ?').bind(id).run();
    for (const aid of input.assetIds) {
      await db
        .prepare('INSERT OR IGNORE INTO authorization_rule_assets (rule_id, asset_id) VALUES (?, ?)')
        .bind(id, aid)
        .run();
    }
  }

  if (input.assetGroupIds !== undefined) {
    await db.prepare('DELETE FROM authorization_rule_asset_groups WHERE rule_id = ?').bind(id).run();
    for (const agid of input.assetGroupIds) {
      await db
        .prepare(
          'INSERT OR IGNORE INTO authorization_rule_asset_groups (rule_id, asset_group_id) VALUES (?, ?)'
        )
        .bind(id, agid)
        .run();
    }
  }

  if (input.accountIds !== undefined) {
    await db.prepare('DELETE FROM authorization_rule_accounts WHERE rule_id = ?').bind(id).run();
    for (const accId of input.accountIds) {
      await db
        .prepare('INSERT OR IGNORE INTO authorization_rule_accounts (rule_id, account_id) VALUES (?, ?)')
        .bind(id, accId)
        .run();
    }
  }

  if (input.actions !== undefined) {
    await db.prepare('DELETE FROM authorization_rule_actions WHERE rule_id = ?').bind(id).run();
    for (const action of input.actions) {
      await db
        .prepare('INSERT OR IGNORE INTO authorization_rule_actions (rule_id, action) VALUES (?, ?)')
        .bind(id, action)
        .run();
    }
  }

  return (await getAuthorizationRule(id, db))!;
}

export async function deleteAuthorizationRule(id: string, db: D1Database): Promise<void> {
  await db.prepare('DELETE FROM authorization_rules WHERE id = ?').bind(id).run();
}

export async function listAuthorizationRules(db: D1Database): Promise<AuthorizationRuleSummary[]> {
  const { results: rules } = await db
    .prepare('SELECT id FROM authorization_rules ORDER BY created_at DESC')
    .all<{ id: string }>();

  if (!rules || rules.length === 0) return [];

  const summaries: AuthorizationRuleSummary[] = [];
  for (const r of rules) {
    const s = await getAuthorizationRule(r.id, db);
    if (s) summaries.push(s);
  }
  return summaries;
}

// -------------------------------------------------------------
// JumpServer Model Authorization Resolution
// -------------------------------------------------------------

/**
 * Evaluates whether a user has permission to connect to a specific account on an asset.
 *
 * Subject: user_id OR member of user group
 * Target: asset_id OR member of asset group (including tree inheritance)
 * Account: specific account_id OR all_accounts = 1 (@ALL)
 * Action: 'connect' (default)
 * Time: valid_from <= now <= valid_until
 * Default: DENY
 */
export async function checkUserAssetAccountAccess(
  userId: string,
  assetId: string,
  accountId: string,
  action: string = 'connect',
  db: D1Database,
  now: number = Date.now()
): Promise<AccessCheckResult> {
  // 1. Validate user is active
  const user = await db
    .prepare('SELECT id, status FROM users WHERE id = ?')
    .bind(userId)
    .first<UserRow>();

  if (!user) {
    return { authorized: false, reason: 'User not found' };
  }
  if (user.status !== 'active') {
    return { authorized: false, reason: `User account is ${user.status}` };
  }

  // 2. Validate asset is enabled
  const asset = await db
    .prepare('SELECT id, enabled FROM assets WHERE id = ?')
    .bind(assetId)
    .first<AssetRow>();

  if (!asset) {
    return { authorized: false, reason: 'Asset not found' };
  }
  if (asset.enabled !== 1) {
    return { authorized: false, reason: 'Asset is disabled' };
  }

  // 3. Validate account is enabled and bound to asset
  const account = await db
    .prepare('SELECT id, asset_id, enabled FROM asset_accounts WHERE id = ?')
    .bind(accountId)
    .first<AssetAccountRow>();

  if (!account) {
    return { authorized: false, reason: 'Account not found' };
  }
  if (account.asset_id !== assetId) {
    return { authorized: false, reason: 'Account does not belong to specified asset' };
  }
  if (account.enabled !== 1) {
    return { authorized: false, reason: 'Account is disabled' };
  }

  if (action === 'connect' && await isAssetAdministrator(userId, db)) {
    return { authorized: true };
  }

  // 4. Resolve user's user group memberships
  const { results: userGroupRows } = await db
    .prepare('SELECT group_id FROM group_members WHERE user_id = ?')
    .bind(userId)
    .all<{ group_id: string }>();

  const userGroupIds = new Set<string>((userGroupRows || []).map((r) => r.group_id));

  // 5. Resolve asset's asset groups (including all ancestor groups via tree inheritance)
  const { results: directAssetGroups } = await db
    .prepare('SELECT group_id FROM asset_group_members WHERE asset_id = ?')
    .bind(assetId)
    .all<{ group_id: string }>();

  const effectiveAssetGroupIds = new Set<string>();
  for (const ag of directAssetGroups || []) {
    const ancestors = await getAssetGroupAncestors(ag.group_id, db);
    for (const ancId of ancestors) {
      effectiveAssetGroupIds.add(ancId);
    }
  }

  // 6. Query all enabled rules within the valid time window
  const { results: candidateRules } = await db
    .prepare(
      `SELECT * FROM authorization_rules
       WHERE enabled = 1
         AND (valid_from IS NULL OR valid_from <= ?)
         AND (valid_until IS NULL OR valid_until >= ?)`
    )
    .bind(now, now)
    .all<AuthorizationRuleRow>();

  if (!candidateRules || candidateRules.length === 0) {
    return { authorized: false, reason: 'Default Deny: No active authorization rules found' };
  }

  // 7. Evaluate each candidate rule
  for (const rule of candidateRules) {
    // Check Action
    const { results: actionRows } = await db
      .prepare('SELECT action FROM authorization_rule_actions WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ action: string }>();

    const ruleActions = (actionRows || []).map((r) => r.action);
    if (!ruleActions.includes(action)) {
      continue;
    }

    // Check Subject: User or User Group
    const { results: ruleUserRows } = await db
      .prepare('SELECT user_id FROM authorization_rule_users WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ user_id: string }>();

    const userMatch = (ruleUserRows || []).some((u) => u.user_id === userId);

    let groupMatch = false;
    if (!userMatch && userGroupIds.size > 0) {
      const { results: ruleGroupRows } = await db
        .prepare('SELECT group_id FROM authorization_rule_groups WHERE rule_id = ?')
        .bind(rule.id)
        .all<{ group_id: string }>();

      groupMatch = (ruleGroupRows || []).some((g) => userGroupIds.has(g.group_id));
    }

    if (!userMatch && !groupMatch) {
      continue;
    }

    // Check Target: Asset or Asset Group (with tree inheritance)
    const { results: ruleAssetRows } = await db
      .prepare('SELECT asset_id FROM authorization_rule_assets WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ asset_id: string }>();

    const assetMatch = (ruleAssetRows || []).some((a) => a.asset_id === assetId);

    let assetGroupMatch = false;
    if (!assetMatch && effectiveAssetGroupIds.size > 0) {
      const { results: ruleAssetGroupRows } = await db
        .prepare('SELECT asset_group_id FROM authorization_rule_asset_groups WHERE rule_id = ?')
        .bind(rule.id)
        .all<{ asset_group_id: string }>();

      assetGroupMatch = (ruleAssetGroupRows || []).some((ag) =>
        effectiveAssetGroupIds.has(ag.asset_group_id)
      );
    }

    if (!assetMatch && !assetGroupMatch) {
      continue;
    }

    // Check Account: all_accounts = 1 (@ALL) OR specific account_id
    if (rule.all_accounts === 1) {
      // Matches any enabled account bound to this asset
      return { authorized: true, matchedRuleId: rule.id };
    }

    const { results: ruleAccountRows } = await db
      .prepare('SELECT account_id FROM authorization_rule_accounts WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ account_id: string }>();

    const accountMatch = (ruleAccountRows || []).some((a) => a.account_id === accountId);
    if (accountMatch) {
      return { authorized: true, matchedRuleId: rule.id };
    }
  }

  // Default Deny
  return { authorized: false, reason: 'Default Deny: No matching authorization rule' };
}

/**
 * Dynamic Visibility Resolver: Returns ONLY assets the user is authorized to connect to,
 * along with their authorized accounts. Unauthorized assets are completely hidden.
 */
export async function getAuthorizedAssetsForUser(
  userId: string,
  db: D1Database,
  now: number = Date.now()
): Promise<AuthorizedAsset[]> {
  // 1. Verify user is active
  const user = await db
    .prepare('SELECT id, status FROM users WHERE id = ?')
    .bind(userId)
    .first<UserRow>();

  if (!user || user.status !== 'active') {
    return [];
  }

  if (await isAssetAdministrator(userId, db)) {
    const assets = await db.prepare('SELECT * FROM assets WHERE enabled = 1').all<AssetRow>();
    const accounts = await db.prepare(`SELECT a.id, a.asset_id, a.username, c.type AS credential_type, c.name AS credential_name
      FROM asset_accounts a JOIN credentials c ON c.id = a.credential_id WHERE a.enabled = 1`).all<{
        id: string; asset_id: string; username: string; credential_type: CredentialType; credential_name: string;
      }>();
    const visible: AuthorizedAsset[] = assets.results.map((asset) => ({
      id: asset.id, name: asset.name, hostname: asset.hostname, port: asset.port, description: asset.description,
      platform: asset.platform, environment: asset.environment, groupIds: [],
      accounts: accounts.results.filter((account) => account.asset_id === asset.id).map((account) => ({
        id: account.id, username: account.username, credentialType: account.credential_type, credentialName: account.credential_name,
      })),
    }));
    return enrichAssetGroups(visible, db);
  }

  // 2. Fetch user's user group memberships
  const { results: userGroupRows } = await db
    .prepare('SELECT group_id FROM group_members WHERE user_id = ?')
    .bind(userId)
    .all<{ group_id: string }>();

  const userGroupIds = new Set<string>((userGroupRows || []).map((r) => r.group_id));

  // 3. Fetch all active candidate rules
  const { results: candidateRules } = await db
    .prepare(
      `SELECT * FROM authorization_rules
       WHERE enabled = 1
         AND (valid_from IS NULL OR valid_from <= ?)
         AND (valid_until IS NULL OR valid_until >= ?)`
    )
    .bind(now, now)
    .all<AuthorizationRuleRow>();

  if (!candidateRules || candidateRules.length === 0) {
    return [];
  }

  // Map of assetId -> { asset: AssetRow, accounts: Map<accountId, AuthorizedAssetAccount> }
  const assetMap = new Map<
    string,
    {
      asset: AssetRow;
      accounts: Map<string, AuthorizedAssetAccount>;
    }
  >();

  for (const rule of candidateRules) {
    // Check Action: must include 'connect' (or default connect)
    const { results: actionRows } = await db
      .prepare('SELECT action FROM authorization_rule_actions WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ action: string }>();

    const ruleActions = (actionRows || []).map((r) => r.action);
    if (!ruleActions.includes('connect')) {
      continue;
    }

    // Check Subject: User or User Group
    const { results: ruleUserRows } = await db
      .prepare('SELECT user_id FROM authorization_rule_users WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ user_id: string }>();

    const userMatch = (ruleUserRows || []).some((u) => u.user_id === userId);

    let groupMatch = false;
    if (!userMatch && userGroupIds.size > 0) {
      const { results: ruleGroupRows } = await db
        .prepare('SELECT group_id FROM authorization_rule_groups WHERE rule_id = ?')
        .bind(rule.id)
        .all<{ group_id: string }>();

      groupMatch = (ruleGroupRows || []).some((g) => userGroupIds.has(g.group_id));
    }

    if (!userMatch && !groupMatch) {
      continue;
    }

    // Resolve Target Assets for this rule:
    const targetAssetIds = new Set<string>();

    // 1. Direct assets
    const { results: ruleAssetRows } = await db
      .prepare('SELECT asset_id FROM authorization_rule_assets WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ asset_id: string }>();

    for (const a of ruleAssetRows || []) {
      targetAssetIds.add(a.asset_id);
    }

    // 2. Asset groups (with tree inheritance: includes all descendant groups)
    const { results: ruleAssetGroupRows } = await db
      .prepare('SELECT asset_group_id FROM authorization_rule_asset_groups WHERE rule_id = ?')
      .bind(rule.id)
      .all<{ asset_group_id: string }>();

    for (const ag of ruleAssetGroupRows || []) {
      const descendantGroups = await getAssetGroupDescendants(ag.asset_group_id, db);
      for (const dGid of descendantGroups) {
        const { results: memberAssets } = await db
          .prepare('SELECT asset_id FROM asset_group_members WHERE group_id = ?')
          .bind(dGid)
          .all<{ asset_id: string }>();

        for (const ma of memberAssets || []) {
          targetAssetIds.add(ma.asset_id);
        }
      }
    }

    if (targetAssetIds.size === 0) {
      continue;
    }

    // Get rule's explicitly authorized account IDs (if not all_accounts)
    let explicitAccountIds: Set<string> | null = null;
    if (rule.all_accounts !== 1) {
      const { results: ruleAccountRows } = await db
        .prepare('SELECT account_id FROM authorization_rule_accounts WHERE rule_id = ?')
        .bind(rule.id)
        .all<{ account_id: string }>();

      explicitAccountIds = new Set((ruleAccountRows || []).map((r) => r.account_id));
    }

    // For each target asset, load its enabled accounts
    for (const assetId of targetAssetIds) {
      let entry = assetMap.get(assetId);
      if (!entry) {
        const asset = await db
          .prepare('SELECT * FROM assets WHERE id = ? AND enabled = 1')
          .bind(assetId)
          .first<AssetRow>();

        if (!asset) continue; // Skip disabled or non-existent assets

        entry = { asset, accounts: new Map() };
        assetMap.set(assetId, entry);
      }

      // Load enabled accounts for this asset
      const { results: accountRows } = await db
        .prepare(
          `SELECT a.id, a.username, c.type as credential_type, c.name as credential_name
           FROM asset_accounts a
           JOIN credentials c ON a.credential_id = c.id
           WHERE a.asset_id = ? AND a.enabled = 1`
        )
        .bind(assetId)
        .all<{
          id: string;
          username: string;
          credential_type: CredentialType;
          credential_name: string;
        }>();

      for (const acc of accountRows || []) {
        if (rule.all_accounts === 1 || (explicitAccountIds && explicitAccountIds.has(acc.id))) {
          entry.accounts.set(acc.id, {
            id: acc.id,
            username: acc.username,
            credentialType: acc.credential_type,
            credentialName: acc.credential_name,
          });
        }
      }
    }
  }

  // Filter out any assets that have no authorized accounts
  const result: AuthorizedAsset[] = [];
  for (const { asset, accounts } of assetMap.values()) {
    if (accounts.size > 0) {
      result.push({
        id: asset.id,
        name: asset.name,
        hostname: asset.hostname,
        port: asset.port,
        description: asset.description,
        platform: asset.platform,
        environment: asset.environment,
        accounts: Array.from(accounts.values()),
        groupIds: [],
      });
    }
  }

  return enrichAssetGroups(result, db);
}

async function enrichAssetGroups(result: AuthorizedAsset[], db: D1Database): Promise<AuthorizedAsset[]> {
  for (const asset of result) {
    const memberships = await db.prepare('SELECT group_id FROM asset_group_members WHERE asset_id = ?').bind(asset.id).all<{ group_id: string }>();
    asset.groupIds = (memberships.results || []).map((row) => row.group_id);
    const rows = await db.prepare(`WITH RECURSIVE paths(id, name, parent_id) AS (
      SELECT g.id, g.name, g.parent_id FROM asset_groups g JOIN asset_group_members m ON m.group_id = g.id WHERE m.asset_id = ?
      UNION SELECT g.id, g.name, g.parent_id FROM asset_groups g JOIN paths p ON g.id = p.parent_id
    ) SELECT * FROM paths`).bind(asset.id).all<{ id: string; name: string; parent_id: string | null }>();
    asset.groups = (rows.results || []).map((group) => ({ id: group.id, name: group.name, parentId: group.parent_id }));
  }

  // Sort by asset name
  result.sort((a, b) => a.name.localeCompare(b.name));
  return result;
}

function validateRuleInput(input: UpdateAuthorizationRuleInput): void {
  if (input.actions !== undefined && (!Array.isArray(input.actions) || !input.actions.length || input.actions.some((action) => action !== 'connect'))) {
    throw new Error('V1 authorization actions must contain connect only');
  }
  for (const time of [input.validFrom, input.validUntil]) {
    if (time != null && (!Number.isSafeInteger(time) || time < 0)) throw new Error('Invalid authorization time');
  }
  if (input.validFrom != null && input.validUntil != null && input.validFrom > input.validUntil) throw new Error('Invalid authorization time range');
}
