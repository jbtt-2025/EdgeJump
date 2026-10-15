import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, encodeUtf8, timingSafeEqual } from './utils.ts';

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const DEFAULT_SALT_BYTES = 16;
export const PASSWORD_ALGORITHM = 'pbkdf2-sha256';

// Standard PBKDF2, independent of the managed Workers native iteration cap.
// Production callers run this in PasswordKdfDO, outside the HTTP Worker's CPU budget.
async function derivePassword(password: string, pepper: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const material = encodeUtf8(pepper ? `${password}${pepper}` : password);
  try {
    return await pbkdf2Async(sha256, material, salt, { c: iterations, dkLen: 32 });
  } finally {
    material.fill(0);
  }
}

export interface HashPasswordResult {
  hash: string;
  salt: string;
  iterations: number;
  algorithm: string;
}

/**
 * Hash a plaintext password using PBKDF2-HMAC-SHA256 with 600,000 iterations (or custom iterations),
 * a 16-byte cryptographically secure random salt, and an optional secret pepper.
 *
 * @param password The plaintext password to hash
 * @param pepper Optional AUTH_PEPPER secret from worker environment
 * @param iterations Number of PBKDF2 iterations (defaults to 600,000 per AGENTS.md)
 */
export async function hashPassword(
  password: string,
  pepper: string = '',
  iterations: number = DEFAULT_PBKDF2_ITERATIONS
): Promise<HashPasswordResult> {
  const salt = crypto.getRandomValues(new Uint8Array(DEFAULT_SALT_BYTES));
  const derived = await derivePassword(password, pepper, salt, iterations);
  try {
    return { hash: bytesToHex(derived), salt: bytesToHex(salt), iterations, algorithm: PASSWORD_ALGORITHM };
  } finally {
    derived.fill(0);
  }
}

/**
 * Verify a plaintext password against a stored PBKDF2 hash, salt, and iteration count.
 * Uses timing-safe constant-time comparison to prevent timing attacks.
 *
 * @param password The candidate plaintext password
 * @param pepper Optional AUTH_PEPPER secret from worker environment
 * @param hash The expected hex-encoded PBKDF2 hash
 * @param salt The hex-encoded 16-byte salt
 * @param iterations The iteration count used when hashing
 */
export async function verifyPassword(
  password: string,
  pepper: string = '',
  hash: string,
  salt: string,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS
): Promise<boolean> {
  if (!/^[a-f\d]{64}$/i.test(hash) || !/^(?:[a-f\d]{2})+$/i.test(salt)) return false;
  const derived = await derivePassword(password, pepper, hexToBytes(salt), iterations);
  try {
    return timingSafeEqual(derived, hexToBytes(hash));
  } finally {
    derived.fill(0);
  }
}
