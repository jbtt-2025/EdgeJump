import type { Env } from '../types.ts';
import { DEFAULT_PBKDF2_ITERATIONS, PASSWORD_ALGORITHM, type HashPasswordResult } from '../crypto/password.ts';

export class PasswordKdfUnavailableError extends Error {
  constructor() { super('Password service unavailable. Please try again later.'); }
}

async function compute(userId: string, operation: 'hash' | 'verify', body: object, env: Env): Promise<unknown> {
  try {
    const stub = env.PASSWORD_KDF.get(env.PASSWORD_KDF.idFromName(userId));
    const response = await stub.fetch(`https://password.internal/${operation}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    if (!response.ok) throw new PasswordKdfUnavailableError();
    return await response.json();
  } catch {
    throw new PasswordKdfUnavailableError();
  }
}

export async function hashUserPassword(userId: string, password: string, env: Env): Promise<HashPasswordResult> {
  const result = await compute(userId, 'hash', { password }, env) as HashPasswordResult;
  if (!result || !/^[a-f\d]{64}$/.test(result.hash) || !/^[a-f\d]{32}$/.test(result.salt) ||
      result.iterations !== DEFAULT_PBKDF2_ITERATIONS || result.algorithm !== PASSWORD_ALGORITHM) throw new PasswordKdfUnavailableError();
  return result;
}

export async function verifyUserPassword(userId: string, password: string, hash: string, salt: string, iterations: number, env: Env): Promise<boolean> {
  const result = await compute(userId, 'verify', { password, hash, salt, iterations }, env) as { valid: boolean };
  if (!result || typeof result.valid !== 'boolean') throw new PasswordKdfUnavailableError();
  return result.valid;
}
