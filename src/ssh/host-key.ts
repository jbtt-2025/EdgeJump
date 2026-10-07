// SSH Host Key Verification and TOFU (Trust On First Use) for EdgeJump

import type { HostKeyTrust } from './types.ts';
import {
  base64UrlUnsigned,
  readBytes,
  readString,
  toBase64,
  toBufferSource,
} from './utils.ts';

export type { HostKeyTrust };

/**
 * Classifies host key trust per TOFU policy:
 * - 'first-seen': No prior fingerprint stored in DB, will be trusted on first use.
 * - 'trusted': Matches the existing verified fingerprint in DB.
 * - 'changed': Mismatch with existing verified fingerprint -> potential MITM, must block!
 */
export function classifyHostKey(
  expectedFingerprint: string | undefined | null,
  fingerprint: string,
): HostKeyTrust {
  if (!expectedFingerprint) return 'first-seen';
  return expectedFingerprint === fingerprint ? 'trusted' : 'changed';
}

/**
 * Computes standard OpenSSH SHA256 base64 fingerprint without trailing '=' padding:
 * Example: 'SHA256:mZ3eQ9...'
 */
export async function computeHostKeyFingerprint(hostKey: Uint8Array): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', toBufferSource(hostKey)));
  return `SHA256:${toBase64(hash).replace(/=+$/, '')}`;
}

/**
 * Extracts algorithm name from raw SSH public host key blob.
 */
export function getHostKeyAlgorithm(hostKey: Uint8Array): string {
  const parsed = readString(hostKey, 0);
  return parsed.value;
}

/**
 * Converts SSH ECDSA signature format (r || s MPINTs) into raw IEEE P1363 (r || s) for WebCrypto.
 */
export function sshEcdsaToRaw(signature: Uint8Array, coordinateBytes: number): Uint8Array {
  const rField = readBytes(signature, 0, 'ECDSA signature r');
  const sField = readBytes(signature, rField.next, 'ECDSA signature s');
  if (sField.next !== signature.length) throw new Error('Malformed ECDSA signature trailing data');

  const trim = (value: Uint8Array): Uint8Array => {
    if (value.length === 0 || (value[0] & 0x80) !== 0) throw new Error('ECDSA signature integers must be positive');
    if (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) throw new Error('ECDSA signature integer is not minimally encoded');
    const normalized = value.length > 1 && value[0] === 0 ? value.subarray(1) : value;
    if (normalized.every((byte) => byte === 0)) throw new Error('ECDSA signature integers must be non-zero');
    return normalized;
  };

  const r = trim(rField.value);
  const s = trim(sField.value);
  if (r.length > coordinateBytes || s.length > coordinateBytes) throw new Error('Invalid ECDSA signature length');

  const result = new Uint8Array(coordinateBytes * 2);
  result.set(r, coordinateBytes - r.length);
  result.set(s, coordinateBytes * 2 - s.length);
  return result;
}

/**
 * Verifies public host key signature on exchange hash (RFC 4253 / RFC 5656 / RFC 8332 / RFC 8709).
 */
export async function verifyHostKeySignature(
  hostKey: Uint8Array,
  signature: Uint8Array,
  exchangeHash: Uint8Array,
  negotiatedHostKeyAlgorithm?: string,
): Promise<boolean> {
  let offset = 0;
  const keyType = readString(hostKey, offset, 'host key type');
  offset = keyType.next;

  let sigOffset = 0;
  const signatureType = readString(signature, sigOffset, 'host signature type');
  sigOffset = signatureType.next;

  const signatureField = readBytes(signature, sigOffset, 'host signature blob');
  if (signatureField.next !== signature.length) throw new Error('Malformed SSH host signature');
  const rawSignature = signatureField.value;

  // Ed25519
  if (keyType.value === 'ssh-ed25519') {
    if (negotiatedHostKeyAlgorithm && negotiatedHostKeyAlgorithm !== 'ssh-ed25519') {
      throw new Error(`Ed25519 host key does not match negotiated algorithm ${negotiatedHostKeyAlgorithm}`);
    }
    if (signatureType.value !== 'ssh-ed25519') {
      throw new Error('Ed25519 signature type mismatch');
    }
    const keyField = readBytes(hostKey, offset, 'Ed25519 public key');
    if (keyField.next !== hostKey.length || keyField.value.length !== 32 || rawSignature.length !== 64) {
      throw new Error('Malformed Ed25519 host key or signature');
    }
    const rawKey = keyField.value;
    const key = await crypto.subtle.importKey('raw', toBufferSource(rawKey), { name: 'Ed25519' }, false, ['verify']);
    return crypto.subtle.verify('Ed25519', key, toBufferSource(rawSignature), toBufferSource(exchangeHash));
  }

  // ECDSA (P-256, P-384, P-521)
  if (keyType.value.startsWith('ecdsa-sha2-nistp')) {
    if (negotiatedHostKeyAlgorithm && negotiatedHostKeyAlgorithm !== keyType.value) {
      throw new Error(`ECDSA host key does not match negotiated algorithm ${negotiatedHostKeyAlgorithm}`);
    }
    if (signatureType.value !== keyType.value) {
      throw new Error('ECDSA signature type mismatch');
    }
    const curveName = readString(hostKey, offset, 'ECDSA curve name');
    offset = curveName.next;
    const keyField = readBytes(hostKey, offset, 'ECDSA public key point');
    if (keyField.next !== hostKey.length) throw new Error('Malformed ECDSA host key');
    const rawKey = keyField.value;

    const curve = keyType.value.endsWith('256') ? 'P-256' : keyType.value.endsWith('384') ? 'P-384' : 'P-521';
    if (curveName.value !== keyType.value.replace('ecdsa-sha2-', '')) {
      throw new Error('ECDSA curve name does not match the host key type');
    }
    const digest = curve === 'P-256' ? 'SHA-256' : curve === 'P-384' ? 'SHA-384' : 'SHA-512';
    const coordinateBytes = curve === 'P-256' ? 32 : curve === 'P-384' ? 48 : 66;

    const key = await crypto.subtle.importKey('raw', toBufferSource(rawKey), { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
    const rawSig = sshEcdsaToRaw(rawSignature, coordinateBytes);
    return crypto.subtle.verify({ name: 'ECDSA', hash: digest }, key, toBufferSource(rawSig), toBufferSource(exchangeHash));
  }

  // RSA (rsa-sha2-256, rsa-sha2-512)
  if (keyType.value === 'ssh-rsa') {
    if (signatureType.value !== 'rsa-sha2-256' && signatureType.value !== 'rsa-sha2-512') {
      throw new Error(`Unsupported RSA host signature type: ${signatureType.value}`);
    }
    if (negotiatedHostKeyAlgorithm && signatureType.value !== negotiatedHostKeyAlgorithm) {
      throw new Error(`RSA signature ${signatureType.value} does not match negotiated ${negotiatedHostKeyAlgorithm}`);
    }
    const exponent = readBytes(hostKey, offset, 'RSA public exponent');
    offset = exponent.next;
    const modulusField = readBytes(hostKey, offset, 'RSA modulus');
    if (modulusField.next !== hostKey.length || exponent.value.length === 0 || modulusField.value.length === 0) {
      throw new Error('Malformed RSA host key');
    }
    const modulus = modulusField.value;
    const digest = signatureType.value === 'rsa-sha2-512' ? 'SHA-512' : 'SHA-256';

    const jwk = {
      kty: 'RSA',
      e: base64UrlUnsigned(exponent.value),
      n: base64UrlUnsigned(modulus),
      ext: true,
    };
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: digest },
      false,
      ['verify']
    );
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, toBufferSource(rawSignature), toBufferSource(exchangeHash));
  }

  throw new Error(`Unsupported host key type: ${keyType.value}`);
}
