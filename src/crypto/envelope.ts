// AES-256-GCM Envelope Encryption for EdgeJump SSH Credentials
// Per AGENTS.md Sections 18, 19, 20, 21

import {
  encodeUtf8,
  decodeUtf8,
  bytesToBase64,
  base64ToBytes,
  hexToBytes,
  toBufferSource,
} from './utils.ts';

export type CredentialType = 'password' | 'private_key';

export interface EncryptedCredentialBlob {
  credentialCiphertext: string;
  credentialNonce: string;
  encryptedDek: string;
  dekNonce: string;
  keyVersion: string;
  type?: CredentialType | string;
  algorithm?: string;
  credentialKeyVersion?: string;

  // D1 Database column aliases (snake_case)
  credential_ciphertext?: string;
  credential_nonce?: string;
  encrypted_dek?: string;
  dek_nonce?: string;
  key_version?: string;
  credential_type?: string;
}

const DEK_BYTE_LENGTH = 32; // 256 bits
const GCM_NONCE_BYTE_LENGTH = 12; // 96 bits standard for AES-GCM

/**
 * Builds canonical AAD for credential ciphertext:
 * AAD = [credentialId, type, keyVersion]
 */
export function buildCredentialAad(
  credentialId: string,
  type: string,
  keyVersion: string
): Uint8Array {
  return encodeUtf8(`${credentialId}:${type}:${keyVersion}`);
}

/**
 * Builds canonical AAD for encrypted DEK:
 * AAD = [credentialId, keyVersion]
 */
export function buildDekAad(
  credentialId: string,
  keyVersion: string
): Uint8Array {
  return encodeUtf8(`${credentialId}:${keyVersion}`);
}

/**
 * Parse and validate a 32-byte (64 hex characters) master KEK.
 */
function parseMasterKek(masterKekHex: string): Uint8Array {
  const cleaned = masterKekHex.trim();
  if (cleaned.length !== 64) {
    throw new Error('Master KEK must be a 64-character hex string (32 bytes)');
  }
  const bytes = hexToBytes(cleaned);
  if (bytes.length !== 32) {
    throw new Error('Master KEK must be 32 bytes (256 bits)');
  }
  return bytes;
}

/**
 * Encrypt a credential using AES-256-GCM Envelope Encryption.
 *
 * 1. Generates a fresh random 256-bit DEK.
 * 2. Encrypts plaintext with DEK and AAD = [credentialId, type, keyVersion].
 * 3. Encrypts DEK with masterKek and AAD = [credentialId, keyVersion].
 * 4. Clears plaintext and DEK memory buffers.
 *
 * @param plaintext The secret plaintext (password or private key)
 * @param credentialId Unique ID of the credential
 * @param type Credential type ('password' | 'private_key')
 * @param masterKekHex 64-character hex representation of 256-bit Master KEK
 * @param keyVersion Master key version (e.g. 'v1')
 */
export async function encryptCredential(
  plaintext: string,
  credentialId: string,
  type: CredentialType | string,
  masterKekHex: string,
  keyVersion: string
): Promise<EncryptedCredentialBlob> {
  if (!plaintext) {
    throw new Error('Plaintext cannot be empty');
  }
  if (!credentialId) {
    throw new Error('Credential ID is required');
  }
  if (!type) {
    throw new Error('Credential type is required');
  }
  if (!keyVersion) {
    throw new Error('Key version is required');
  }

  const masterKekBytes = parseMasterKek(masterKekHex);
  const dekBytes = crypto.getRandomValues(new Uint8Array(DEK_BYTE_LENGTH));
  const credentialNonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_BYTE_LENGTH));
  const dekNonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_BYTE_LENGTH));

  const plaintextBytes = encodeUtf8(plaintext);

  try {
    // 1. Encrypt plaintext using DEK
    const dekKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(dekBytes),
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const credentialAad = buildCredentialAad(credentialId, type, keyVersion);
    const credentialCipherBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(credentialNonce),
        additionalData: toBufferSource(credentialAad),
      },
      dekKey,
      toBufferSource(plaintextBytes)
    );

    // 2. Encrypt DEK using Master KEK
    const masterKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(masterKekBytes),
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const dekAad = buildDekAad(credentialId, keyVersion);
    const encryptedDekBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(dekNonce),
        additionalData: toBufferSource(dekAad),
      },
      masterKey,
      toBufferSource(dekBytes)
    );

    const credentialCiphertext = bytesToBase64(new Uint8Array(credentialCipherBuffer));
    const credentialNonceB64 = bytesToBase64(credentialNonce);
    const encryptedDek = bytesToBase64(new Uint8Array(encryptedDekBuffer));
    const dekNonceB64 = bytesToBase64(dekNonce);

    return {
      credentialCiphertext,
      credentialNonce: credentialNonceB64,
      encryptedDek,
      dekNonce: dekNonceB64,
      keyVersion,
      type: type as CredentialType,
      algorithm: 'AES-256-GCM',
      credentialKeyVersion: keyVersion,

      // snake_case aliases for D1 DB row compatibility
      credential_ciphertext: credentialCiphertext,
      credential_nonce: credentialNonceB64,
      encrypted_dek: encryptedDek,
      dek_nonce: dekNonceB64,
      key_version: keyVersion,
    };
  } finally {
    // Ensure plaintext and keys are zeroed out from typed arrays
    plaintextBytes.fill(0);
    dekBytes.fill(0);
    masterKekBytes.fill(0);
  }
}

/**
 * Decrypt a credential using AES-256-GCM Envelope Encryption.
 *
 * 1. Decrypts DEK using Master KEK and AAD = [credentialId, keyVersion].
 * 2. Decrypts plaintext using DEK and AAD = [credentialId, type, credentialKeyVersion].
 * 3. Clears decrypted buffers and DEK from memory before returning plaintext.
 *
 * @param encryptedBlob The encrypted credential record
 * @param credentialId Unique ID of the credential
 * @param masterKekHex 64-character hex representation of 256-bit Master KEK
 */
export async function decryptCredential(
  encryptedBlob: EncryptedCredentialBlob,
  credentialId: string,
  masterKekHex: string
): Promise<string> {
  const ciphertextB64 = encryptedBlob.credentialCiphertext ?? encryptedBlob.credential_ciphertext;
  const credentialNonceB64 = encryptedBlob.credentialNonce ?? encryptedBlob.credential_nonce;
  const encryptedDekB64 = encryptedBlob.encryptedDek ?? encryptedBlob.encrypted_dek;
  const dekNonceB64 = encryptedBlob.dekNonce ?? encryptedBlob.dek_nonce;
  const keyVersion = encryptedBlob.keyVersion ?? encryptedBlob.key_version ?? 'v1';
  const type = (encryptedBlob.type ?? encryptedBlob.credential_type) as string;
  const credKeyVersion = encryptedBlob.credentialKeyVersion ?? keyVersion;

  if (!ciphertextB64 || !credentialNonceB64 || !encryptedDekB64 || !dekNonceB64) {
    throw new Error('Malformed encrypted credential blob: missing ciphertext or nonces');
  }
  if (!type) {
    throw new Error('Credential type is required in encrypted blob for AAD verification');
  }

  const masterKekBytes = parseMasterKek(masterKekHex);
  let dekBytes: Uint8Array | null = null;
  let decryptedBytes: Uint8Array | null = null;

  try {
    // 1. Decrypt DEK using Master KEK
    const masterKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(masterKekBytes),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const dekAad = buildDekAad(credentialId, keyVersion);
    const dekNonceBytes = base64ToBytes(dekNonceB64);
    const encryptedDekBytes = base64ToBytes(encryptedDekB64);

    const dekBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(dekNonceBytes),
        additionalData: toBufferSource(dekAad),
      },
      masterKey,
      toBufferSource(encryptedDekBytes)
    );

    dekBytes = new Uint8Array(dekBuffer);

    // 2. Decrypt credential ciphertext using DEK
    const dekKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(dekBytes),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const credNonceBytes = base64ToBytes(credentialNonceB64);
    const cipherBytes = base64ToBytes(ciphertextB64);

    let credentialBuffer: ArrayBuffer;
    const credAad = buildCredentialAad(credentialId, type, credKeyVersion);

    try {
      credentialBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: toBufferSource(credNonceBytes),
          additionalData: toBufferSource(credAad),
        },
        dekKey,
        toBufferSource(cipherBytes)
      );
    } catch (err) {
      // In case the blob was loaded from a DB row where key_version was rotated to 'v2'
      // but credentialKeyVersion wasn't explicitly saved, fallback to 'v1'
      if (!encryptedBlob.credentialKeyVersion && credKeyVersion !== 'v1') {
        const fallbackAad = buildCredentialAad(credentialId, type, 'v1');
        credentialBuffer = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: toBufferSource(credNonceBytes),
            additionalData: toBufferSource(fallbackAad),
          },
          dekKey,
          toBufferSource(cipherBytes)
        );
      } else {
        throw err;
      }
    }

    decryptedBytes = new Uint8Array(credentialBuffer);
    return decodeUtf8(decryptedBytes);
  } finally {
    if (decryptedBytes) {
      decryptedBytes.fill(0);
    }
    if (dekBytes) {
      dekBytes.fill(0);
    }
    masterKekBytes.fill(0);
  }
}

/**
 * Rotates the Master KEK protecting a credential DEK without decrypting or exposing the plaintext.
 *
 * 1. Decrypts DEK using oldMasterKek and old keyVersion.
 * 2. Re-encrypts DEK using newMasterKek, fresh nonce, and newKeyVersion.
 * 3. Leaves credentialCiphertext untouched.
 *
 * @param encryptedBlob Existing encrypted credential record
 * @param credentialId Unique ID of the credential
 * @param oldMasterKekHex Old Master KEK (64 hex characters)
 * @param newMasterKekHex New Master KEK (64 hex characters)
 * @param newKeyVersion New key version identifier (e.g. 'v2')
 */
export async function rotateCredentialKey(
  encryptedBlob: EncryptedCredentialBlob,
  credentialId: string,
  oldMasterKekHex: string,
  newMasterKekHex: string,
  newKeyVersion: string
): Promise<EncryptedCredentialBlob> {
  const encryptedDekB64 = encryptedBlob.encryptedDek ?? encryptedBlob.encrypted_dek;
  const dekNonceB64 = encryptedBlob.dekNonce ?? encryptedBlob.dek_nonce;
  const currentKeyVersion = encryptedBlob.keyVersion ?? encryptedBlob.key_version ?? 'v1';

  if (!encryptedDekB64 || !dekNonceB64) {
    throw new Error('Malformed encrypted credential blob: missing encrypted DEK or nonce');
  }
  if (!newKeyVersion) {
    throw new Error('New key version is required');
  }

  const oldMasterKekBytes = parseMasterKek(oldMasterKekHex);
  const newMasterKekBytes = parseMasterKek(newMasterKekHex);
  let dekBytes: Uint8Array | null = null;

  try {
    // 1. Decrypt DEK with old master KEK
    const oldMasterKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(oldMasterKekBytes),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const oldDekAad = buildDekAad(credentialId, currentKeyVersion);
    const dekNonceBytes = base64ToBytes(dekNonceB64);
    const encryptedDekBytes = base64ToBytes(encryptedDekB64);

    const dekBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(dekNonceBytes),
        additionalData: toBufferSource(oldDekAad),
      },
      oldMasterKey,
      toBufferSource(encryptedDekBytes)
    );

    dekBytes = new Uint8Array(dekBuffer);

    // 2. Re-encrypt DEK with new master KEK and fresh nonce
    const newMasterKey = await crypto.subtle.importKey(
      'raw',
      toBufferSource(newMasterKekBytes),
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const newDekNonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_BYTE_LENGTH));
    const newDekAad = buildDekAad(credentialId, newKeyVersion);

    const newEncryptedDekBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toBufferSource(newDekNonce),
        additionalData: toBufferSource(newDekAad),
      },
      newMasterKey,
      toBufferSource(dekBytes)
    );

    const newEncryptedDekB64 = bytesToBase64(new Uint8Array(newEncryptedDekBuffer));
    const newDekNonceB64 = bytesToBase64(newDekNonce);
    const originalCredKeyVersion = encryptedBlob.credentialKeyVersion ?? currentKeyVersion;

    return {
      ...encryptedBlob,
      encryptedDek: newEncryptedDekB64,
      dekNonce: newDekNonceB64,
      keyVersion: newKeyVersion,
      credentialKeyVersion: originalCredKeyVersion,

      encrypted_dek: newEncryptedDekB64,
      dek_nonce: newDekNonceB64,
      key_version: newKeyVersion,
    };
  } finally {
    if (dekBytes) {
      dekBytes.fill(0);
    }
    oldMasterKekBytes.fill(0);
    newMasterKekBytes.fill(0);
  }
}
