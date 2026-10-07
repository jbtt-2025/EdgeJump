import { DatabaseSync } from 'node:sqlite';
import * as fs from 'node:fs';
import * as path from 'node:path';

class MockD1PreparedStatement {
  private db: DatabaseSync;
  private sql: string;
  private params: unknown[];

  constructor(db: DatabaseSync, sql: string, params: unknown[] = []) {
    this.db = db;
    this.sql = sql;
    this.params = params.map((p) => (p === undefined ? null : p));
  }

  bind(...params: unknown[]): MockD1PreparedStatement {
    return new MockD1PreparedStatement(this.db, this.sql, params);
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const stmt = this.db.prepare(this.sql);
    const row = stmt.get(...(this.params as any[])) as Record<string, unknown> | undefined;
    if (!row) return null;
    if (colName) return (row[colName] ?? null) as T;
    return row as T;
  }

  async all<T = unknown>(): Promise<{ results: T[]; success: boolean; meta: any }> {
    const stmt = this.db.prepare(this.sql);
    const rows = stmt.all(...(this.params as any[])) as T[];
    return { results: rows, success: true, meta: {} };
  }

  async run(): Promise<{ success: boolean; meta: { changes: number; last_row_id: number } }> {
    const stmt = this.db.prepare(this.sql);
    const res = stmt.run(...(this.params as any[]));
    return {
      success: true,
      meta: { changes: Number(res.changes), last_row_id: Number(res.lastInsertRowid) },
    };
  }

  async raw<T = unknown>(): Promise<T[]> {
    const stmt = this.db.prepare(this.sql);
    const rows = stmt.all(...(this.params as any[])) as Record<string, unknown>[];
    return rows.map((r) => Object.values(r)) as T[];
  }
}

export class MockD1Database {
  public sqlite: DatabaseSync;

  constructor(sqlite?: DatabaseSync) {
    this.sqlite = sqlite ?? new DatabaseSync(':memory:');
  }

  prepare(sql: string): MockD1PreparedStatement {
    return new MockD1PreparedStatement(this.sqlite, sql);
  }

  async batch(statements: MockD1PreparedStatement[]): Promise<any[]> {
    const results = [];
    for (const stmt of statements) {
      results.push(await stmt.run());
    }
    return results;
  }

  async exec(query: string): Promise<{ count: number; duration: number }> {
    this.sqlite.exec(query);
    return { count: 1, duration: 0 };
  }

  async dump(): Promise<ArrayBuffer> {
    throw new Error('dump not implemented in mock');
  }
}

/**
 * Creates an in-memory D1 database with initial migrations applied.
 */
export async function createTestDatabase(): Promise<D1Database> {
  const db = new MockD1Database();

  const m1Path = path.resolve(process.cwd(), 'migrations', '0001_initial_schema.sql');
  const m2Path = path.resolve(process.cwd(), 'migrations', '0002_initial_roles_permissions.sql');

  const m1 = fs.readFileSync(m1Path, 'utf8');
  const m2 = fs.readFileSync(m2Path, 'utf8');

  await db.exec(m1);
  await db.exec(m2);

  return db as unknown as D1Database;
}
