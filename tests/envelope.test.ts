// Unit and integration tests for EdgeJump cryptographic primitives and envelope encryption
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  encryptCredential,
  decryptCredential,
  rotateCredentialKey,
} from '../src/crypto/envelope.ts';

import {
  hashPassword,
  verifyPassword,
  DEFAULT_PBKDF2_ITERATIONS,
} from '../src/crypto/password.ts';

import {
  generateTotpSecret,
  generateTotpCode,
  verifyTotpCode,
  getTotpUri,
  decodeBase32,
  encodeBase32,
} from '../src/crypto/totp.ts';

import {
  generateSessionToken,
  hashToken,
  generateRecoveryCode,
  hashRecoveryCode,
} from '../src/crypto/token.ts';

import {
  bytesToHex,
} from '../src/crypto/utils.ts';

// Helper to generate a 32-byte (64 hex char) master KEK
function generateMasterKekHex(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}

describe('AES-256-GCM Envelope Encryption', () => {
  const masterKek1 = generateMasterKekHex();
  const masterKek2 = generateMasterKekHex();

  it('encrypts and decrypts a password credential', async () => {
    const credentialId = 'cred_pwd_001';
    const password = 'CorrectHorseBatteryStaple!2026';
    const keyVersion = 'v1';

    const encrypted = await encryptCredential(
      password,
      credentialId,
      'password',
      masterKek1,
      keyVersion
    );

    assert.ok(encrypted.credentialCiphertext, 'credentialCiphertext should be present');
    assert.ok(encrypted.credentialNonce, 'credentialNonce should be present');
    assert.ok(encrypted.encryptedDek, 'encryptedDek should be present');
    assert.ok(encrypted.dekNonce, 'dekNonce should be present');
    assert.strictEqual(encrypted.keyVersion, 'v1');
    assert.strictEqual(encrypted.type, 'password');

    // Decrypt and verify matching plaintext
    const decrypted = await decryptCredential(encrypted, credentialId, masterKek1);
    assert.strictEqual(decrypted, password);
  });

  it('encrypts and decrypts a private key credential (multi-line PEM)', async () => {
    const credentialId = 'cred_key_002';
    const privateKeyPem = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBqm35Y3W3z28F+XqZk62G+B3k9U7/v2M4Wd8C5K2l1AAAAsA/vA/wP7w
P8AAAAAtzc2gtZWQyNTUxOQAAACBqm35Y3W3z28F+XqZk62G+B3k9U7/v2M4Wd8C5K2l1
AAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgZ
-----END OPENSSH PRIVATE KEY-----`;
    const keyVersion = 'v1';

    const encrypted = await encryptCredential(
      privateKeyPem,
      credentialId,
      'private_key',
      masterKek1,
      keyVersion
    );

    const decrypted = await decryptCredential(encrypted, credentialId, masterKek1);
    assert.strictEqual(decrypted, privateKeyPem);
  });

  it('fails decryption with wrong master KEK', async () => {
    const credentialId = 'cred_fail_kek';
    const secret = 'super-secret-password';
    const encrypted = await encryptCredential(
      secret,
      credentialId,
      'password',
      masterKek1,
      'v1'
    );

    const wrongMasterKek = generateMasterKekHex();
    await assert.rejects(
      async () => {
        await decryptCredential(encrypted, credentialId, wrongMasterKek);
      },
      (err: Error) => {
        return err.name === 'OperationError' || err.message.length > 0;
      },
      'Should reject when master KEK is wrong'
    );
  });

  it('fails decryption with wrong AAD (wrong credentialId)', async () => {
    const credentialId = 'cred_correct_id';
    const secret = 'secret-data';
    const encrypted = await encryptCredential(
      secret,
      credentialId,
      'password',
      masterKek1,
      'v1'
    );

    const wrongCredentialId = 'cred_wrong_id';
    await assert.rejects(
      async () => {
        await decryptCredential(encrypted, wrongCredentialId, masterKek1);
      },
      (err: Error) => {
        return err.name === 'OperationError' || err.message.length > 0;
      },
      'Should reject when credentialId does not match AAD'
    );
  });

  it('fails decryption with wrong AAD (wrong type)', async () => {
    const credentialId = 'cred_type_test';
    const secret = 'secret-data';
    const encrypted = await encryptCredential(
      secret,
      credentialId,
      'password',
      masterKek1,
      'v1'
    );

    // Tamper with the type in the encrypted blob
    const tamperedBlob = {
      ...encrypted,
      type: 'private_key',
    };

    await assert.rejects(
      async () => {
        await decryptCredential(tamperedBlob, credentialId, masterKek1);
      },
      (err: Error) => {
        return err.name === 'OperationError' || err.message.length > 0;
      },
      'Should reject when credential type does not match AAD'
    );
  });

  it('fails decryption when ciphertext is modified', async () => {
    const credentialId = 'cred_tamper_cipher';
    const secret = 'top-secret';
    const encrypted = await encryptCredential(
      secret,
      credentialId,
      'password',
      masterKek1,
      'v1'
    );

    // Corrupt one character in ciphertext
    const originalCipher = encrypted.credentialCiphertext;
    const corruptedCipher =
      originalCipher[0] === 'A'
        ? 'B' + originalCipher.slice(1)
        : 'A' + originalCipher.slice(1);

    const tamperedBlob = {
      ...encrypted,
      credentialCiphertext: corruptedCipher,
    };

    await assert.rejects(
      async () => {
        await decryptCredential(tamperedBlob, credentialId, masterKek1);
      },
      (err: Error) => {
        return err.name === 'OperationError' || err.message.length > 0;
      },
      'Should reject modified ciphertext due to AES-GCM auth tag verification failure'
    );
  });

  it('fails decryption when nonce is modified', async () => {
    const credentialId = 'cred_tamper_nonce';
    const secret = 'top-secret';
    const encrypted = await encryptCredential(
      secret,
      credentialId,
      'password',
      masterKek1,
      'v1'
    );

    // Corrupt the nonce
    const originalNonce = encrypted.credentialNonce;
    const corruptedNonce =
      originalNonce[0] === 'X'
        ? 'Y' + originalNonce.slice(1)
        : 'X' + originalNonce.slice(1);

    const tamperedBlob = {
      ...encrypted,
      credentialNonce: corruptedNonce,
    };

    await assert.rejects(
      async () => {
        await decryptCredential(tamperedBlob, credentialId, masterKek1);
      },
      (err: Error) => {
        return err.name === 'OperationError' || err.message.length > 0;
      },
      'Should reject modified nonce'
    );
  });

  it('fails decryption when encrypted DEK is modified', async () => {
    const credentialId = 'cred_tamper_dek';
    const secret = 'top-secret';
    const encrypted = await encryptCredential(
      secret,
      credentialId,
      'password',
      masterKek1,
      'v1'
    );

    const originalDek = encrypted.encryptedDek;
    const corruptedDek =
      originalDek[0] === 'A'
        ? 'B' + originalDek.slice(1)
        : 'A' + originalDek.slice(1);

    const tamperedBlob = {
      ...encrypted,
      encryptedDek: corruptedDek,
    };

    await assert.rejects(
      async () => {
        await decryptCredential(tamperedBlob, credentialId, masterKek1);
      },
      'Should reject modified encrypted DEK'
    );
  });

  it('fails decryption when DEK nonce is modified', async () => {
    const credentialId = 'cred_tamper_dek_nonce';
    const secret = 'top-secret';
    const encrypted = await encryptCredential(
      secret,
      credentialId,
      'password',
      masterKek1,
      'v1'
    );

    const originalNonce = encrypted.dekNonce;
    const corruptedNonce =
      originalNonce[0] === 'X'
        ? 'Y' + originalNonce.slice(1)
        : 'X' + originalNonce.slice(1);

    const tamperedBlob = {
      ...encrypted,
      dekNonce: corruptedNonce,
    };

    await assert.rejects(
      async () => {
        await decryptCredential(tamperedBlob, credentialId, masterKek1);
      },
      'Should reject modified DEK nonce'
    );
  });

  it('rejects invalid inputs to encryptCredential', async () => {
    await assert.rejects(
      async () => {
        await encryptCredential('', 'id', 'password', masterKek1, 'v1');
      },
      /empty/i
    );

    await assert.rejects(
      async () => {
        await encryptCredential('secret', 'id', 'password', 'invalid-short-kek', 'v1');
      },
      /64-character/i
    );
  });

  it('supports key rotation (rewrapping DEK with new master KEK without plaintext)', async () => {
    const credentialId = 'cred_rotate_001';
    const originalSecret = 'database-super-admin-password';
    const oldKek = masterKek1;
    const newKek = masterKek2;

    // 1. Initial encryption under KEK v1
    const originalBlob = await encryptCredential(
      originalSecret,
      credentialId,
      'password',
      oldKek,
      'v1'
    );

    // 2. Rotate master key from v1 to v2 (caller never provides plaintext!)
    const rotatedBlob = await rotateCredentialKey(
      originalBlob,
      credentialId,
      oldKek,
      newKek,
      'v2'
    );

    assert.strictEqual(rotatedBlob.keyVersion, 'v2');
    // Ensure ciphertext remained identical (no re-encryption of data with plaintext)
    assert.strictEqual(rotatedBlob.credentialCiphertext, originalBlob.credentialCiphertext);
    assert.strictEqual(rotatedBlob.credentialNonce, originalBlob.credentialNonce);
    // Ensure encrypted DEK changed
    assert.notStrictEqual(rotatedBlob.encryptedDek, originalBlob.encryptedDek);

    // 3. Decrypting rotated blob with old KEK should fail
    await assert.rejects(
      async () => {
        await decryptCredential(rotatedBlob, credentialId, oldKek);
      },
      'Old KEK should fail to decrypt rotated DEK'
    );

    // 4. Decrypting rotated blob with new KEK succeeds
    const decrypted = await decryptCredential(rotatedBlob, credentialId, newKek);
    assert.strictEqual(decrypted, originalSecret);

    // 5. Rotating with wrong old KEK should fail
    const wrongKek = generateMasterKekHex();
    await assert.rejects(
      async () => {
        await rotateCredentialKey(
          originalBlob,
          credentialId,
          wrongKek,
          newKek,
          'v2'
        );
      },
      'Key rotation with wrong old master KEK must fail'
    );
  });
});

describe('PBKDF2 Password Hashing & Verification', () => {
  const pepper = 'edgejump-auth-pepper-secret-v1';

  it('hashes and verifies a password with pepper', async () => {
    const password = 'UserSecurePassword!123';
    // Using a smaller iteration count in unit test for speed, then checking default
    const result = await hashPassword(password, pepper, 10_000);

    assert.ok(result.hash, 'Hash should be generated');
    assert.ok(result.salt, 'Salt should be generated');
    assert.strictEqual(result.iterations, 10_000);
    assert.strictEqual(result.algorithm, 'pbkdf2-sha256');

    // Correct verification
    const isValid = await verifyPassword(
      password,
      pepper,
      result.hash,
      result.salt,
      result.iterations
    );
    assert.strictEqual(isValid, true, 'Correct password and pepper should verify');

    // Wrong password
    const isWrongPwdValid = await verifyPassword(
      'WrongPassword',
      pepper,
      result.hash,
      result.salt,
      result.iterations
    );
    assert.strictEqual(isWrongPwdValid, false, 'Wrong password should fail verification');

    // Wrong pepper
    const isWrongPepperValid = await verifyPassword(
      password,
      'different-pepper',
      result.hash,
      result.salt,
      result.iterations
    );
    assert.strictEqual(isWrongPepperValid, false, 'Wrong pepper should fail verification');

    // Wrong salt
    const isWrongSaltValid = await verifyPassword(
      password,
      pepper,
      result.hash,
      '0123456789abcdef0123456789abcdef',
      result.iterations
    );
    assert.strictEqual(isWrongSaltValid, false, 'Wrong salt should fail verification');
  });

  it('generates unique salts across multiple hashes of identical password', async () => {
    const password = 'IdenticalPassword123';
    const res1 = await hashPassword(password, pepper, 5_000);
    const res2 = await hashPassword(password, pepper, 5_000);

    assert.notStrictEqual(res1.salt, res2.salt, 'Salts must be unique per hash');
    assert.notStrictEqual(res1.hash, res2.hash, 'Hashes must differ because salts differ');
  });

  it('handles empty pepper gracefully', async () => {
    const password = 'PasswordWithoutPepper';
    const res = await hashPassword(password, '', 5_000);
    const valid = await verifyPassword(password, '', res.hash, res.salt, res.iterations);
    assert.strictEqual(valid, true);

    const invalid = await verifyPassword(password, 'added-pepper', res.hash, res.salt, res.iterations);
    assert.strictEqual(invalid, false);
  });

  it('verifies password with default 600,000 iterations per AGENTS.md', async () => {
    const password = 'ProductionDefaultIterationsPassword!456';
    const res = await hashPassword(password, pepper);
    assert.strictEqual(res.iterations, 600_000);
    assert.strictEqual(res.iterations, DEFAULT_PBKDF2_ITERATIONS);
    const valid = await verifyPassword(password, pepper, res.hash, res.salt, res.iterations);
    assert.strictEqual(valid, true);
  });
});

describe('RFC 6238 TOTP Validation', () => {
  it('generates a valid Base32 secret', () => {
    const secret = generateTotpSecret();
    assert.strictEqual(typeof secret, 'string');
    assert.strictEqual(secret.length, 32); // 20 bytes * 8 / 5 = 32 chars
    // Base32 decode and re-encode should be identical
    const decoded = decodeBase32(secret);
    assert.strictEqual(decoded.length, 20);
    const reEncoded = encodeBase32(decoded);
    assert.strictEqual(reEncoded, secret);
  });

  it('generates and verifies 6-digit TOTP code within current window', async () => {
    const secret = generateTotpSecret();
    const now = Date.now();
    const code = await generateTotpCode(secret, now);

    assert.match(code, /^\d{6}$/, 'TOTP code must be 6 digits');

    const isValid = await verifyTotpCode(secret, code, 1, now);
    assert.strictEqual(isValid, true, 'Generated TOTP code should be valid');

    const isInvalid = await verifyTotpCode(secret, '999999', 1, now);
    // Extremely unlikely that random 999999 matches
    assert.strictEqual(isInvalid, false, 'Arbitrary wrong code should fail');
  });

  it('verifies code within time step window (30s drift)', async () => {
    const secret = generateTotpSecret();
    const now = 1700000000000; // Fixed timestamp

    // Code generated 25 seconds ago (still within same or adjacent window)
    const codePast = await generateTotpCode(secret, now - 30_000);
    const validWithWindow = await verifyTotpCode(secret, codePast, 1, now);
    assert.strictEqual(validWithWindow, true, 'Code from previous step should be accepted with window=1');

    // Code from 3 steps ago (90s ago) should fail with window=1
    const codeOld = await generateTotpCode(secret, now - 90_000);
    const invalidOld = await verifyTotpCode(secret, codeOld, 1, now);
    assert.strictEqual(invalidOld, false, 'Code from 90s ago should be rejected with window=1');
  });

  it('matches RFC 6238 test vectors (HMAC-SHA1)', async () => {
    // RFC 6238 Appendix B test secret: "12345678901234567890" ASCII
    // In Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    // Test vector at Unix time 59s: expected 6-digit OTP is 287082
    const code59 = await generateTotpCode(rfcSecret, 59 * 1000);
    assert.strictEqual(code59, '287082');

    // Test vector at Unix time 1111111109s: expected 6-digit OTP is 081804
    const code1111 = await generateTotpCode(rfcSecret, 1111111109 * 1000);
    assert.strictEqual(code1111, '081804');

    // Test vector at Unix time 1234567890s: expected 6-digit OTP is 005924
    const code1234 = await generateTotpCode(rfcSecret, 1234567890 * 1000);
    assert.strictEqual(code1234, '005924');

    // Test vector at Unix time 2000000000s: expected 6-digit OTP is 279037
    const code2000 = await generateTotpCode(rfcSecret, 2000000000 * 1000);
    assert.strictEqual(code2000, '279037');
  });

  it('generates valid otpauth URI for authenticator apps', () => {
    const secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
    const uri = getTotpUri(secret, 'admin@example.com', 'EdgeJump');
    assert.ok(uri.startsWith('otpauth://totp/EdgeJump:admin%40example.com?secret=JBSWY3DPEHPK3PXP'));
    assert.ok(uri.includes('algorithm=SHA1'));
    assert.ok(uri.includes('digits=6'));
    assert.ok(uri.includes('period=30'));
  });
});

describe('Web Login Session Tokens & SHA-256 Hashing', () => {
  it('generates 256-bit secure session tokens', () => {
    const tokenHex = generateSessionToken('hex');
    assert.strictEqual(tokenHex.length, 64);
    assert.match(tokenHex, /^[0-9a-f]{64}$/);

    const tokenBase64Url = generateSessionToken('base64url');
    assert.strictEqual(tokenBase64Url.length, 43);

    const token2 = generateSessionToken();
    assert.notStrictEqual(tokenHex, token2, 'Generated tokens should be unique');
  });

  it('hashes session tokens with SHA-256 hex string for D1 storage', async () => {
    const token = generateSessionToken('hex');
    const hash = await hashToken(token);

    assert.strictEqual(hash.length, 64, 'SHA-256 hash must be 64 hex characters');
    assert.match(hash, /^[0-9a-f]{64}$/);

    // Hashing same token produces deterministic hash
    const hash2 = await hashToken(token);
    assert.strictEqual(hash, hash2);

    // Known test vector: SHA-256("hello")
    const helloHash = await hashToken('hello');
    assert.strictEqual(
      helloHash,
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    );
  });

  it('generates recovery codes and validates recovery code hash', async () => {
    const code = generateRecoveryCode();
    assert.match(code, /^[0-9A-F]{5}-[0-9A-F]{5}$/);

    const codeHash = await hashRecoveryCode(code);
    assert.strictEqual(codeHash.length, 64);

    // Normalization test (lowercase and without hyphens produces identical hash)
    const codeWithoutHyphen = code.replace('-', '').toLowerCase();
    const codeHash2 = await hashRecoveryCode(codeWithoutHyphen);
    assert.strictEqual(codeHash, codeHash2);
  });
});
