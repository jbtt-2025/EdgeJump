import type { AssetRow, AssetGroupRow, AssetAccountRow, CredentialType, SSHHostKeyRow } from '../types.ts';
import type { AssetSummary, AssetGroupSummary, AssetAccountSummary } from '../shared/types.ts';
import { assertPublicTarget } from '../backend/security.ts';
import { recordAuditEvent } from '../audit/audit-service.ts';

export interface CreateAssetInput {
  name: string;
  hostname: string;
  port?: number;
  description?: string | null;
  platform?: string;
  environment?: string;
  enabled?: boolean;
  groupIds?: string[];
}

export interface UpdateAssetInput {
  name?: string;
  hostname?: string;
  port?: number;
  description?: string | null;
  platform?: string;
  environment?: string;
  enabled?: boolean;
  groupIds?: string[];
}

export interface CreateAssetGroupInput {
  name: string;
  description?: string | null;
  parentId?: string | null;
}

export interface UpdateAssetGroupInput {
  name?: string;
  description?: string | null;
  parentId?: string | null;
}

export interface CreateAssetAccountInput {
  assetId: string;
  username: string;
  credentialId: string;
  enabled?: boolean;
}

export interface UpdateAssetAccountInput {
  username?: string;
  credentialId?: string;
  enabled?: boolean;
}

// -------------------------------------------------------------
// Assets CRUD
// -------------------------------------------------------------

export async function createAsset(
  input: CreateAssetInput,
  createdBy: string | null,
  db: D1Database
): Promise<AssetSummary> {
  const prepared = await prepareAssetCreation(input, createdBy, db);
  for (const statement of prepared.statements) await statement.run();
  return prepared.asset;
}

export async function prepareAssetCreation(
  input: CreateAssetInput, createdBy: string | null, db: D1Database
): Promise<{ asset: AssetSummary; statements: D1PreparedStatement[] }> {
  const name = input.name.trim();
  if (!name) throw new Error('Asset name is required');

  const hostname = input.hostname.trim();
  if (!hostname) throw new Error('Asset hostname is required');

  const port = input.port ?? 22;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port: ${port}`);
  }

  await assertPublicTarget(hostname, port);

  const id = `asset_${crypto.randomUUID()}`;
  const now = Date.now();
  const platform = input.platform ?? 'linux';
  const environment = input.environment ?? 'production';
  const enabledInt = input.enabled ?? true ? 1 : 0;

  const statements = [db
    .prepare(
      `INSERT INTO assets (
        id, name, hostname, port, description,
        platform, environment, enabled, host_key_policy,
        last_seen_host_key, created_at, updated_at, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'strict', NULL, ?, ?, ?)`
    )
    .bind(
      id,
      name,
      hostname,
      port,
      input.description ?? null,
      platform,
      environment,
      enabledInt,
      now,
      now,
      createdBy
    )];

  const groupIds = input.groupIds ?? [];
  for (const gid of groupIds) {
    statements.push(db
      .prepare('INSERT OR IGNORE INTO asset_group_members (group_id, asset_id) VALUES (?, ?)')
      .bind(gid, id));
  }

  return { statements, asset: {
    id,
    name,
    hostname,
    port,
    description: input.description ?? null,
    platform,
    environment,
    enabled: enabledInt === 1,
    groupIds,
  } };
}

export async function getAsset(id: string, db: D1Database): Promise<AssetSummary | null> {
  const row = await db
    .prepare('SELECT * FROM assets WHERE id = ?')
    .bind(id)
    .first<AssetRow>();

  if (!row) return null;

  const { results: groupRows } = await db
    .prepare('SELECT group_id FROM asset_group_members WHERE asset_id = ?')
    .bind(id)
    .all<{ group_id: string }>();

  return {
    id: row.id,
    name: row.name,
    hostname: row.hostname,
    port: row.port,
    description: row.description,
    platform: row.platform,
    environment: row.environment,
    enabled: row.enabled === 1,
    groupIds: (groupRows || []).map((g) => g.group_id),
  };
}

export async function updateAsset(
  id: string,
  input: UpdateAssetInput,
  db: D1Database
): Promise<AssetSummary> {
  const existing = await getAsset(id, db);
  if (!existing) throw new Error(`Asset not found: ${id}`);

  let hostname = existing.hostname;
  if (input.hostname !== undefined) {
    hostname = input.hostname.trim();
    if (!hostname) throw new Error('Asset hostname cannot be empty');
  }

  let port = existing.port;
  if (input.port !== undefined) {
    port = input.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid port: ${port}`);
    }
  }

  const name = input.name !== undefined ? input.name.trim() : existing.name;
  if (input.hostname !== undefined || input.port !== undefined) await assertPublicTarget(hostname, port);
  if (!name) throw new Error('Asset name cannot be empty');

  const description = input.description !== undefined ? input.description : existing.description;
  const platform = input.platform !== undefined ? input.platform : existing.platform;
  const environment = input.environment !== undefined ? input.environment : existing.environment;
  const enabledInt = input.enabled !== undefined ? (input.enabled ? 1 : 0) : existing.enabled ? 1 : 0;
  const now = Date.now();

  await db
    .prepare(
      `UPDATE assets SET
        name = ?, hostname = ?, port = ?, description = ?,
        platform = ?, environment = ?, enabled = ?, updated_at = ?
      WHERE id = ?`
    )
    .bind(name, hostname, port, description, platform, environment, enabledInt, now, id)
    .run();

  let groupIds = existing.groupIds;
  if (input.groupIds !== undefined) {
    await db.prepare('DELETE FROM asset_group_members WHERE asset_id = ?').bind(id).run();
    for (const gid of input.groupIds) {
      await db
        .prepare('INSERT OR IGNORE INTO asset_group_members (group_id, asset_id) VALUES (?, ?)')
        .bind(gid, id)
        .run();
    }
    groupIds = input.groupIds;
  }

  return {
    id,
    name,
    hostname,
    port,
    description,
    platform,
    environment,
    enabled: enabledInt === 1,
    groupIds,
  };
}

export async function deleteAsset(id: string, db: D1Database): Promise<void> {
  await db.prepare('DELETE FROM assets WHERE id = ?').bind(id).run();
}

export async function listAssets(
  db: D1Database,
  options: { enabledOnly?: boolean; search?: string } = {}
): Promise<AssetSummary[]> {
  let query = 'SELECT * FROM assets';
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.enabledOnly) {
    conditions.push('enabled = 1');
  }
  if (options.search) {
    conditions.push('(name LIKE ? OR hostname LIKE ?)');
    const term = `%${options.search}%`;
    params.push(term, term);
  }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  query += ' ORDER BY name ASC';

  const { results: assets } = await db.prepare(query).bind(...params).all<AssetRow>();
  if (!assets || assets.length === 0) return [];

  const { results: memberships } = await db
    .prepare('SELECT group_id, asset_id FROM asset_group_members')
    .all<{ group_id: string; asset_id: string }>();

  const groupMap = new Map<string, string[]>();
  for (const m of memberships || []) {
    const list = groupMap.get(m.asset_id) ?? [];
    list.push(m.group_id);
    groupMap.set(m.asset_id, list);
  }

  return assets.map((a) => ({
    id: a.id,
    name: a.name,
    hostname: a.hostname,
    port: a.port,
    description: a.description,
    platform: a.platform,
    environment: a.environment,
    enabled: a.enabled === 1,
    groupIds: groupMap.get(a.id) ?? [],
  }));
}

// -------------------------------------------------------------
// Asset Groups CRUD & Tree Hierarchy
// -------------------------------------------------------------

export async function createAssetGroup(
  input: CreateAssetGroupInput,
  db: D1Database
): Promise<AssetGroupSummary> {
  const name = input.name.trim();
  if (!name) throw new Error('Asset group name is required');

  const id = `ag_${crypto.randomUUID()}`;
  const now = Date.now();
  const parentId = input.parentId ?? null;

  if (parentId) {
    const parent = await db.prepare('SELECT id FROM asset_groups WHERE id = ?').bind(parentId).first();
    if (!parent) throw new Error(`Parent asset group not found: ${parentId}`);
  }

  await db
    .prepare(
      'INSERT INTO asset_groups (id, name, description, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
    .bind(id, name, input.description ?? null, parentId, now, now)
    .run();

  return {
    id,
    name,
    description: input.description ?? null,
    parentId,
    assetCount: 0,
  };
}

export async function getAssetGroup(id: string, db: D1Database): Promise<AssetGroupSummary | null> {
  const row = await db
    .prepare('SELECT * FROM asset_groups WHERE id = ?')
    .bind(id)
    .first<AssetGroupRow>();

  if (!row) return null;

  const countRow = await db
    .prepare('SELECT COUNT(*) as count FROM asset_group_members WHERE group_id = ?')
    .bind(id)
    .first<{ count: number }>();

  return {
    id: row.id,
    name: row.name,
    description: row.description,
    parentId: row.parent_id,
    assetCount: countRow?.count ?? 0,
  };
}

export async function updateAssetGroup(
  id: string,
  input: UpdateAssetGroupInput,
  db: D1Database
): Promise<AssetGroupSummary> {
  const existing = await getAssetGroup(id, db);
  if (!existing) throw new Error(`Asset group not found: ${id}`);

  const name = input.name !== undefined ? input.name.trim() : existing.name;
  if (!name) throw new Error('Asset group name cannot be empty');

  let parentId = existing.parentId;
  if (input.parentId !== undefined) {
    if (input.parentId === id) {
      throw new Error('Asset group cannot be its own parent');
    }
    if (input.parentId) {
      const parent = await db.prepare('SELECT id FROM asset_groups WHERE id = ?').bind(input.parentId).first();
      if (!parent) throw new Error(`Parent asset group not found: ${input.parentId}`);
      const cycle = await db.prepare(`WITH RECURSIVE descendants(id) AS (
        SELECT id FROM asset_groups WHERE id = ?
        UNION SELECT g.id FROM asset_groups g JOIN descendants d ON g.parent_id = d.id
      ) SELECT id FROM descendants WHERE id = ?`).bind(id, input.parentId).first();
      if (cycle) throw new Error('Asset group cannot be moved into its descendants');
    }
    parentId = input.parentId;
  }

  const description = input.description !== undefined ? input.description : existing.description;
  const now = Date.now();

  await db
    .prepare(
      'UPDATE asset_groups SET name = ?, description = ?, parent_id = ?, updated_at = ? WHERE id = ?'
    )
    .bind(name, description, parentId, now, id)
    .run();

  return {
    id,
    name,
    description,
    parentId,
    assetCount: existing.assetCount,
  };
}

export async function deleteAssetGroup(id: string, db: D1Database): Promise<void> {
  await db.prepare('DELETE FROM asset_groups WHERE id = ?').bind(id).run();
}

export async function listAssetGroups(db: D1Database): Promise<AssetGroupSummary[]> {
  const { results: groups } = await db
    .prepare('SELECT * FROM asset_groups ORDER BY name ASC')
    .all<AssetGroupRow>();

  if (!groups || groups.length === 0) return [];

  const { results: counts } = await db
    .prepare('SELECT group_id, COUNT(*) as count FROM asset_group_members GROUP BY group_id')
    .all<{ group_id: string; count: number }>();

  const countMap = new Map<string, number>();
  for (const c of counts || []) {
    countMap.set(c.group_id, c.count);
  }

  return groups.map((g) => ({
    id: g.id,
    name: g.name,
    description: g.description,
    parentId: g.parent_id,
    assetCount: countMap.get(g.id) ?? 0,
  }));
}

export async function addAssetToGroup(
  groupId: string,
  assetId: string,
  db: D1Database
): Promise<void> {
  await db
    .prepare('INSERT OR IGNORE INTO asset_group_members (group_id, asset_id) VALUES (?, ?)')
    .bind(groupId, assetId)
    .run();
}

export async function removeAssetFromGroup(
  groupId: string,
  assetId: string,
  db: D1Database
): Promise<void> {
  await db
    .prepare('DELETE FROM asset_group_members WHERE group_id = ? AND asset_id = ?')
    .bind(groupId, assetId)
    .run();
}

/**
 * Returns a group and all its descendant group IDs in the tree hierarchy.
 */
export async function getAssetGroupDescendants(
  groupId: string,
  db: D1Database
): Promise<Set<string>> {
  const { results } = await db.prepare('SELECT id, parent_id FROM asset_groups').all<AssetGroupRow>();
  const childrenMap = new Map<string, string[]>();

  for (const row of results || []) {
    if (row.parent_id) {
      const list = childrenMap.get(row.parent_id) ?? [];
      list.push(row.id);
      childrenMap.set(row.parent_id, list);
    }
  }

  const descendants = new Set<string>([groupId]);
  const queue = [groupId];

  while (queue.length > 0) {
    const current = queue.shift()!;
    const children = childrenMap.get(current) ?? [];
    for (const childId of children) {
      if (!descendants.has(childId)) {
        descendants.add(childId);
        queue.push(childId);
      }
    }
  }

  return descendants;
}

/**
 * Returns all ancestor group IDs (including itself) for a given group.
 */
export async function getAssetGroupAncestors(
  groupId: string,
  db: D1Database
): Promise<Set<string>> {
  const { results } = await db.prepare('SELECT id, parent_id FROM asset_groups').all<AssetGroupRow>();
  const parentMap = new Map<string, string | null>();

  for (const row of results || []) {
    parentMap.set(row.id, row.parent_id);
  }

  const ancestors = new Set<string>();
  let current: string | null = groupId;

  while (current && !ancestors.has(current)) {
    ancestors.add(current);
    current = parentMap.get(current) ?? null;
  }

  return ancestors;
}

// -------------------------------------------------------------
// Asset Accounts CRUD
// -------------------------------------------------------------

export async function createAssetAccount(
  input: CreateAssetAccountInput,
  db: D1Database
): Promise<AssetAccountSummary> {
  const username = input.username.trim();
  if (!username) throw new Error('Account username is required');

  const asset = await db.prepare('SELECT id FROM assets WHERE id = ?').bind(input.assetId).first();
  if (!asset) throw new Error(`Asset not found: ${input.assetId}`);

  const credential = await db
    .prepare('SELECT id, name, type FROM credentials WHERE id = ?')
    .bind(input.credentialId)
    .first<{ id: string; name: string; type: CredentialType }>();

  if (!credential) throw new Error(`Credential not found: ${input.credentialId}`);

  const prepared = prepareAccountCreation(input, credential, db);
  await prepared.statement.run();
  return prepared.account;
}

export function prepareAccountCreation(
  input: CreateAssetAccountInput,
  credential: { name: string; type: CredentialType },
  db: D1Database
): { account: AssetAccountSummary; statement: D1PreparedStatement } {
  const username = input.username.trim();
  if (!username) throw new Error('Account username is required');

  const id = `acc_${crypto.randomUUID()}`;
  const now = Date.now();
  const enabledInt = input.enabled ?? true ? 1 : 0;

  const statement = db
    .prepare(
      `INSERT INTO asset_accounts (
        id, asset_id, username, credential_id, enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(id, input.assetId, username, input.credentialId, enabledInt, now, now);

  return { statement, account: {
    id,
    assetId: input.assetId,
    username,
    credentialId: input.credentialId,
    credentialType: credential.type,
    credentialName: credential.name,
    enabled: enabledInt === 1,
  } };
}

export async function getAssetAccount(
  id: string,
  db: D1Database
): Promise<AssetAccountSummary | null> {
  const row = await db
    .prepare(
      `SELECT a.*, c.name as credential_name, c.type as credential_type
       FROM asset_accounts a
       JOIN credentials c ON a.credential_id = c.id
       WHERE a.id = ?`
    )
    .bind(id)
    .first<AssetAccountRow & { credential_name: string; credential_type: CredentialType }>();

  if (!row) return null;

  return {
    id: row.id,
    assetId: row.asset_id,
    username: row.username,
    credentialId: row.credential_id,
    credentialType: row.credential_type,
    credentialName: row.credential_name,
    enabled: row.enabled === 1,
  };
}

export async function updateAssetAccount(
  id: string,
  input: UpdateAssetAccountInput,
  db: D1Database
): Promise<AssetAccountSummary> {
  const existing = await getAssetAccount(id, db);
  if (!existing) throw new Error(`Asset account not found: ${id}`);

  const username = input.username !== undefined ? input.username.trim() : existing.username;
  if (!username) throw new Error('Account username cannot be empty');

  let credentialId = existing.credentialId;
  let credentialName = existing.credentialName;
  let credentialType = existing.credentialType;

  if (input.credentialId !== undefined) {
    const cred = await db
      .prepare('SELECT id, name, type FROM credentials WHERE id = ?')
      .bind(input.credentialId)
      .first<{ id: string; name: string; type: CredentialType }>();
    if (!cred) throw new Error(`Credential not found: ${input.credentialId}`);
    credentialId = cred.id;
    credentialName = cred.name;
    credentialType = cred.type;
  }

  const enabledInt = input.enabled !== undefined ? (input.enabled ? 1 : 0) : existing.enabled ? 1 : 0;
  const now = Date.now();

  await db
    .prepare(
      'UPDATE asset_accounts SET username = ?, credential_id = ?, enabled = ?, updated_at = ? WHERE id = ?'
    )
    .bind(username, credentialId, enabledInt, now, id)
    .run();

  return {
    id,
    assetId: existing.assetId,
    username,
    credentialId,
    credentialType,
    credentialName,
    enabled: enabledInt === 1,
  };
}

export async function deleteAssetAccount(id: string, db: D1Database): Promise<void> {
  await db.prepare('DELETE FROM asset_accounts WHERE id = ?').bind(id).run();
}

export async function listAssetAccounts(
  assetId: string,
  db: D1Database
): Promise<AssetAccountSummary[]> {
  return listAccounts(assetId, db);
}

export async function listAllAssetAccounts(db: D1Database): Promise<AssetAccountSummary[]> {
  return listAccounts(null, db);
}

async function listAccounts(assetId: string | null, db: D1Database): Promise<AssetAccountSummary[]> {
  const { results } = await db
    .prepare(
      `SELECT a.*, c.name as credential_name, c.type as credential_type
       FROM asset_accounts a
       JOIN credentials c ON a.credential_id = c.id
       ${assetId === null ? '' : 'WHERE a.asset_id = ?'}
       ORDER BY a.username ASC`
    )
    .bind(...(assetId === null ? [] : [assetId]))
    .all<AssetAccountRow & { credential_name: string; credential_type: CredentialType }>();

  return (results || []).map((row) => ({
    id: row.id,
    assetId: row.asset_id,
    username: row.username,
    credentialId: row.credential_id,
    credentialType: row.credential_type,
    credentialName: row.credential_name,
    enabled: row.enabled === 1,
  }));
}

// -------------------------------------------------------------
// Host Key Management (Section 39, 41, 42)
// -------------------------------------------------------------

export async function getHostKeyForAsset(
  assetId: string,
  db: D1Database
): Promise<SSHHostKeyRow | null> {
  return db
    .prepare('SELECT * FROM ssh_host_keys WHERE asset_id = ?')
    .bind(assetId)
    .first<SSHHostKeyRow>();
}

export async function listHostKeysForAsset(assetId: string, db: D1Database): Promise<SSHHostKeyRow[]> {
  const rows = await db.prepare('SELECT * FROM ssh_host_keys WHERE asset_id = ? ORDER BY created_at').bind(assetId).all<SSHHostKeyRow>();
  return rows.results || [];
}

export async function resetHostKeyForAsset(
  assetId: string, actorUserId: string, db: D1Database
): Promise<void> {
  if (!await getAsset(assetId, db)) throw new Error('Asset not found');
  await db.batch([
    db.prepare("UPDATE assets SET host_key_policy = 'approval_required' WHERE id = ?").bind(assetId),
    db.prepare("UPDATE ssh_host_keys SET status = 'unverified' WHERE asset_id = ?").bind(assetId),
  ]);
}

export async function approveHostKeyForAsset(
  assetId: string, algorithm: string, fingerprint: string, actorUserId: string, db: D1Database
): Promise<void> {
  const rows = await listHostKeysForAsset(assetId, db);
  const row = rows.find((key) => key.algorithm === algorithm &&
    (key.candidate_fingerprint === fingerprint || key.fingerprint === fingerprint));
  if (!row) throw new Error('Host key fingerprint is not an observed key for this asset');
  const publicKey = row.candidate_fingerprint === fingerprint ? row.candidate_public_key : row.public_key;
  await db.batch([
    db.prepare("DELETE FROM ssh_host_keys WHERE asset_id = ? AND id != ? AND status != 'verified'").bind(assetId, row.id),
    db.prepare(`UPDATE ssh_host_keys SET fingerprint = ?, public_key = ?, status = 'verified',
      verified_by = ?, verified_at = ?, candidate_fingerprint = NULL, candidate_public_key = NULL WHERE id = ?`)
      .bind(fingerprint, publicKey, actorUserId, Date.now(), row.id),
    db.prepare("UPDATE assets SET host_key_policy = 'strict', last_seen_host_key = ? WHERE id = ?").bind(fingerprint, assetId),
  ]);
}
