// Web Login Session Token generation and SHA-256 hashing for EdgeJump
// Per AGENTS.md Section 7:
// Browser stores session_token in HttpOnly Strict Cookie.
// D1 stores SHA-256(session_token). Plaintext is never stored.

import { encodeUtf8, bytesToHex, bytesToBase64Url, toBufferSource } from './utils.ts';

export const SESSION_TOKEN_BYTE_LENGTH = 32; // 256 bits

/**
 * Generate a cryptographically secure 256-bit random session token.
 *
 * @param format 'hex' (64 hex characters) or 'base64url' (43 url-safe characters). Defaults to 'hex'.
 */
export function generateSessionToken(format: 'hex' | 'base64url' = 'hex'): string {
  const bytes = crypto.getRandomValues(new Uint8Array(SESSION_TOKEN_BYTE_LENGTH));
  if (format === 'base64url') {
    return bytesToBase64Url(bytes);
  }
  return bytesToHex(bytes);
}

/**
 * Compute the SHA-256 hash of a session token for authoritative storage in D1 `auth_sessions.token_hash`.
 *
 * @param token The plaintext session token
 * @returns 64-character lowercase hexadecimal SHA-256 hash
 */
export async function hashToken(token: string): Promise<string> {
  if (!token) {
    throw new Error('Token cannot be empty');
  }
  const data = encodeUtf8(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', toBufferSource(data));
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Generate a cryptographically secure random recovery code for MFA.
 * Format: 8-digit alphanumeric string or formatted with hyphens (e.g. ABCD-1234).
 */
export function generateRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(5));
  const hex = bytesToHex(bytes).toUpperCase();
  return `${hex.slice(0, 5)}-${hex.slice(5, 10)}`;
}

/**
 * Hash an MFA recovery code with SHA-256 for D1 storage.
 */
export async function hashRecoveryCode(code: string): Promise<string> {
  const normalized = code.replace(/[\s-]/g, '').toUpperCase();
  return hashToken(normalized);
}
