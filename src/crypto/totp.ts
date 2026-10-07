import { toBufferSource } from './utils.ts';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_DEFAULT_WINDOW = 1; // +/- 1 step (30s before and after)

/**
 * Encode a byte array into standard RFC 4648 Base32 string (unpadded).
 */
export function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decode an RFC 4648 Base32 string into bytes.
 * Tolerates whitespace, hyphens, lowercase characters, and padding '='.
 */
export function decodeBase32(base32Str: string): Uint8Array {
  const cleaned = base32Str.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const result: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned[i];
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base32 character: ${char}`);
    }
    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      result.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(result);
}

/**
 * Generate a random 160-bit (20-byte) Base32 secret for TOTP.
 */
export function generateTotpSecret(byteLength: number = 20): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return encodeBase32(bytes);
}

/**
 * Compute an RFC 4226 HOTP code for a given counter value.
 */
async function computeHotp(
  secretBytes: Uint8Array,
  counter: bigint | number,
  digits: number = TOTP_DIGITS
): Promise<string> {
  const counterBytes = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }

  const key = await crypto.subtle.importKey(
    'raw',
    toBufferSource(secretBytes),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, toBufferSource(counterBytes)));
  const offset = hmac[hmac.length - 1] & 0x0f;

  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const modulo = 10 ** digits;
  const otp = binary % modulo;
  return otp.toString().padStart(digits, '0');
}

/**
 * Generate a 6-digit TOTP code for the given secret and timestamp.
 *
 * @param secret Base32-encoded TOTP secret
 * @param timestamp Unix timestamp in milliseconds (defaults to Date.now())
 * @param digits Number of digits (defaults to 6)
 * @param stepSeconds Time step in seconds (defaults to 30)
 */
export async function generateTotpCode(
  secret: string,
  timestamp: number = Date.now(),
  digits: number = TOTP_DIGITS,
  stepSeconds: number = TOTP_STEP_SECONDS
): Promise<string> {
  const secretBytes = decodeBase32(secret);
  const counter = Math.floor(timestamp / (stepSeconds * 1000));
  return computeHotp(secretBytes, counter, digits);
}

/**
 * Verify a user-provided TOTP code against a secret.
 *
 * @param secret Base32-encoded TOTP secret
 * @param code 6-digit candidate code from user
 * @param window Allowed time step drift in either direction (defaults to 1 = +/- 30s)
 * @param timestamp Optional custom timestamp for testing (defaults to Date.now())
 */
export async function verifyTotpCode(
  secret: string,
  code: string,
  window: number = TOTP_DEFAULT_WINDOW,
  timestamp: number = Date.now()
): Promise<boolean> {
  try {
    const cleanedCode = code.replace(/[\s-]/g, '').trim();
    if (!/^\d{6}$/.test(cleanedCode)) {
      return false;
    }

    const secretBytes = decodeBase32(secret);
    const currentCounter = Math.floor(timestamp / (TOTP_STEP_SECONDS * 1000));

    for (let delta = -window; delta <= window; delta++) {
      const stepCounter = currentCounter + delta;
      if (stepCounter < 0) continue;

      const expectedCode = await computeHotp(secretBytes, stepCounter, TOTP_DIGITS);
      if (expectedCode === cleanedCode) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Generate an otpauth:// URI for QR code generation in authenticator apps.
 */
export function getTotpUri(
  secret: string,
  accountName: string,
  issuer: string = 'EdgeJump'
): string {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccount = encodeURIComponent(accountName);
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}
