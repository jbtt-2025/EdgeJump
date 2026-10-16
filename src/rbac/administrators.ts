/** Resolve built-in administrator roles from D1; names and usernames confer no asset access. */
export async function isAssetAdministrator(userId: string, db: D1Database): Promise<boolean> {
  return !!await db.prepare(`SELECT 1 FROM user_roles
    WHERE user_id = ? AND role_id IN ('role_super_admin', 'role_asset_admin') LIMIT 1`).bind(userId).first();
}

export async function getDemoProtectedUserIds(db: D1Database): Promise<Set<string>> {
  const rows = await db.prepare(`SELECT DISTINCT u.id FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id
    WHERE u.username = 'admin' OR ur.role_id IN ('role_super_admin', 'role_asset_admin')`).all<{ id: string }>();
  return new Set(rows.results.map((row) => row.id));
}

export async function changesProtectedGroupMembers(groupId: string, proposed: string[], db: D1Database): Promise<boolean> {
  const protectedIds = await getDemoProtectedUserIds(db);
  const current = await db.prepare('SELECT user_id FROM group_members WHERE group_id = ?').bind(groupId).all<{ user_id: string }>();
  const currentIds = new Set(current.results.map((row) => row.user_id));
  const proposedIds = new Set(proposed);
  return [...protectedIds].some((id) => currentIds.has(id) !== proposedIds.has(id));
}
