import type { CredentialType, CredentialRow, Env } from '../types.ts';
import type { CredentialSummary } from '../shared/types.ts';
import { encryptCredential, decryptCredential, rotateCredentialKey } from '../crypto/envelope.ts';

export interface CreateCredentialInput {
  name: string;
  type: CredentialType;
  secret: string;
}

/**
 * Creates a new credential using AES-256-GCM Envelope Encryption.
 * Per AGENTS.md Section 18: Write-Only / Replace-Only.
 * Plaintext and ciphertext are NEVER returned to API callers.
 */
export async function createCredential(
  input: CreateCredentialInput,
  masterKek: string,
  db: D1Database
): Promise<CredentialSummary> {
  const prepared = await prepareCredentialCreation(input, masterKek, db);
  await prepared.statement.run();
  return prepared.credential;
}

export async function prepareCredentialCreation(
  input: CreateCredentialInput, masterKek: string, db: D1Database
): Promise<{ credential: CredentialSummary; statement: D1PreparedStatement }> {
  const name = input.name.trim();
  if (!name) {
    throw new Error('Credential name is required');
  }

  if (input.type !== 'password' && input.type !== 'private_key') {
    throw new Error("Invalid credential type: must be 'password' or 'private_key'");
  }

  if (!input.secret || input.secret.trim() === '') {
    throw new Error('Credential secret is required');
  }

  if (!masterKek) {
    throw new Error('Master KEK is required for envelope encryption');
  }

  const id = `cred_${crypto.randomUUID()}`;
  const now = Date.now();
  const keyVersion = 'v1';

  const encryptedBlob = await encryptCredential(
    input.secret,
    id,
    input.type,
    masterKek,
    keyVersion
  );

  const statement = db
    .prepare(
      `INSERT INTO credentials (
        id, name, type,
        credential_ciphertext, credential_nonce,
        encrypted_dek, dek_nonce,
        key_version, credential_key_version, algorithm,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      id,
      name,
      input.type,
      encryptedBlob.credentialCiphertext,
      encryptedBlob.credentialNonce,
      encryptedBlob.encryptedDek,
      encryptedBlob.dekNonce,
      keyVersion,
      keyVersion,
      'AES-256-GCM',
      now,
      now
    );

  return { statement, credential: {
    id,
    name,
    type: input.type,
    keyVersion,
    createdAt: now,
    updatedAt: now,
  } };
}

/**
 * Replaces an existing credential's secret.
 * Per AGENTS.md Section 18: Modifying a credential means Replace Credential, never reading old secret.
 */
export async function replaceCredential(
  id: string,
  secret: string,
  masterKek: string,
  db: D1Database
): Promise<CredentialSummary> {
  if (!secret || secret.trim() === '') {
    throw new Error('Credential secret cannot be empty');
  }

  if (!masterKek) {
    throw new Error('Master KEK is required for envelope encryption');
  }

  const existing = await db
    .prepare('SELECT id, name, type, created_at FROM credentials WHERE id = ?')
    .bind(id)
    .first<{ id: string; name: string; type: CredentialType; created_at: number }>();

  if (!existing) {
    throw new Error('Credential not found');
  }

  const now = Date.now();
  const keyVersion = 'v1';

  const encryptedBlob = await encryptCredential(
    secret,
    id,
    existing.type,
    masterKek,
    keyVersion
  );

  await db
    .prepare(
      `UPDATE credentials SET
        credential_ciphertext = ?,
        credential_nonce = ?,
        encrypted_dek = ?,
        dek_nonce = ?,
        key_version = ?,
        credential_key_version = ?,
        updated_at = ?
      WHERE id = ?`
    )
    .bind(
      encryptedBlob.credentialCiphertext,
      encryptedBlob.credentialNonce,
      encryptedBlob.encryptedDek,
      encryptedBlob.dekNonce,
      keyVersion,
      keyVersion,
      now,
      id
    )
    .run();

  return {
    id: existing.id,
    name: existing.name,
    type: existing.type,
    keyVersion,
    createdAt: existing.created_at,
    updatedAt: now,
  };
}

/**
 * Returns public metadata for a credential.
 * NEVER returns plaintext, ciphertext, or DEKs.
 */
export async function getCredential(
  id: string,
  db: D1Database
): Promise<CredentialSummary | null> {
  const row = await db
    .prepare(
      'SELECT id, name, type, key_version, created_at, updated_at FROM credentials WHERE id = ?'
    )
    .bind(id)
    .first<CredentialRow>();

  if (!row) return null;

  return {
    id: row.id,
    name: row.name,
    type: row.type,
    keyVersion: row.key_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Lists all credentials with safe metadata only.
 */
export async function listCredentials(db: D1Database): Promise<CredentialSummary[]> {
  const { results } = await db
    .prepare(
      'SELECT id, name, type, key_version, created_at, updated_at FROM credentials ORDER BY created_at DESC'
    )
    .all<CredentialRow>();

  return (results || []).map((row) => ({
    id: row.id,
    name: row.name,
    type: row.type,
    keyVersion: row.key_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

/**
 * Deletes a credential. Fails if the credential is in use by any asset account.
 */
export async function deleteCredential(id: string, db: D1Database): Promise<void> {
  const inUse = await db
    .prepare('SELECT COUNT(*) as count FROM asset_accounts WHERE credential_id = ?')
    .bind(id)
    .first<{ count: number }>();

  if (inUse && inUse.count > 0) {
    throw new Error(
      `Cannot delete credential: it is currently referenced by ${inUse.count} asset account(s)`
    );
  }

  await db.prepare('DELETE FROM credentials WHERE id = ?').bind(id).run();
}

/**
 * Internal-only helper used by SSH Session DO / Session service to decrypt credentials
 * in memory strictly during SSH handshake.
 * Plaintext MUST NOT be stored, logged, or returned in public APIs.
 */
export async function getDecryptedCredential(
  id: string,
  masterKek: string,
  db: D1Database
): Promise<{ plaintext: string; type: CredentialType; name: string }> {
  const row = await db
    .prepare('SELECT * FROM credentials WHERE id = ?')
    .bind(id)
    .first<CredentialRow>();

  if (!row) {
    throw new Error(`Credential with ID ${id} not found`);
  }

  const plaintext = await decryptCredential(
    {
      credentialCiphertext: row.credential_ciphertext,
      credentialNonce: row.credential_nonce,
      encryptedDek: row.encrypted_dek,
      dekNonce: row.dek_nonce,
      keyVersion: row.key_version,
      credentialKeyVersion: row.credential_key_version,
      type: row.type,
    },
    row.id,
    masterKek
  );

  return {
    plaintext,
    type: row.type,
    name: row.name,
  };
}

export function getCredentialKek(env: Env, version: string): string {
  const key = version === 'v1' ? env.CREDENTIAL_KEK_V1 : version === 'v2' ? env.CREDENTIAL_KEK_V2 : undefined;
  if (!key) throw new Error('Credential encryption key version is not configured');
  return key;
}

export async function getSessionCredential(id: string, env: Env) {
  const row = await env.DB.prepare('SELECT key_version FROM credentials WHERE id = ?')
    .bind(id).first<{ key_version: string }>();
  if (!row) throw new Error('Credential not found');
  return getDecryptedCredential(id, getCredentialKek(env, row.key_version), env.DB);
}

export async function rewrapCredential(id: string, version: string, env: Env): Promise<void> {
  const row = await env.DB.prepare('SELECT * FROM credentials WHERE id = ?').bind(id).first<CredentialRow>();
  if (!row) throw new Error('Credential not found');
  const blob = await rotateCredentialKey({
    type: row.type, credentialCiphertext: row.credential_ciphertext,
    credentialNonce: row.credential_nonce, encryptedDek: row.encrypted_dek,
    dekNonce: row.dek_nonce, keyVersion: row.key_version,
    credentialKeyVersion: row.credential_key_version,
  }, id, getCredentialKek(env, row.key_version), getCredentialKek(env, version), version);
  await env.DB.prepare(`UPDATE credentials SET encrypted_dek = ?, dek_nonce = ?, key_version = ?,
    credential_key_version = ?, updated_at = ? WHERE id = ?`)
    .bind(blob.encryptedDek, blob.dekNonce, version, blob.credentialKeyVersion, Date.now(), id).run();
}
