import { bytesToHex, hexToBytes, encodeUtf8, timingSafeEqual, toBufferSource } from './utils.ts';

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const DEFAULT_SALT_BYTES = 16;
export const PASSWORD_ALGORITHM = 'pbkdf2-sha256';

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
  const combinedPassword = pepper ? `${password}${pepper}` : password;

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    toBufferSource(encodeUtf8(combinedPassword)),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: toBufferSource(salt),
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256 // 32 bytes = 256 bits
  );

  return {
    hash: bytesToHex(new Uint8Array(derivedBits)),
    salt: bytesToHex(salt),
    iterations,
    algorithm: PASSWORD_ALGORITHM,
  };
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
  try {
    const saltBytes = hexToBytes(salt);
    const expectedHashBytes = hexToBytes(hash);
    const combinedPassword = pepper ? `${password}${pepper}` : password;

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      toBufferSource(encodeUtf8(combinedPassword)),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: toBufferSource(saltBytes),
        iterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    );

    return timingSafeEqual(new Uint8Array(derivedBits), expectedHashBytes);
  } catch {
    return false;
  }
}
