// Control Plane Tests: Bootstrap, Auth, Credentials, Assets, Audit
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createTestDatabase } from './mock-d1.ts';
import { isBootstrapNeeded, bootstrapSuperAdmin } from '../src/auth/bootstrap.ts';
import {
  login,
  validateSession,
  logout,
  setupMfa,
  confirmMfa,
} from '../src/auth/auth-service.ts';
import {
  createCredential,
  replaceCredential,
  getCredential,
  listCredentials,
  deleteCredential,
  getDecryptedCredential,
} from '../src/credentials/credential-service.ts';
import {
  createAsset,
  getAsset,
  updateAsset,
  deleteAsset,
  createAssetGroup,
  createAssetAccount,
} from '../src/assets/asset-service.ts';
import {
  recordAuditEvent,
  listAuditEvents,
  getAuditEvent,
  sanitizeAuditMetadata,
} from '../src/audit/audit-service.ts';
import { bytesToHex } from '../src/crypto/utils.ts';
import { generateTotpCode } from '../src/crypto/totp.ts';
import type { Env } from '../src/types.ts';
import { createPasswordKdfNamespace } from './password-kdf-fixture.ts';

function generateMasterKekHex(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}

describe('Control Plane Services', () => {
  let db: D1Database;
  const masterKek = generateMasterKekHex();
  const bootstrapToken = 'super-secret-bootstrap-token-2026';
  const authPepper = 'pepper-secret-value';

  let env: Env;

  beforeEach(async () => {
    db = await createTestDatabase();
    env = {
      DB: db,
      BOOTSTRAP_TOKEN: bootstrapToken,
      CREDENTIAL_KEK_V1: masterKek,
      AUTH_PEPPER: authPepper,
      PASSWORD_KDF: createPasswordKdfNamespace(authPepper),
      SSH_SESSIONS: undefined as any,
      RATE_LIMIT: undefined as any,
      RECORDINGS: undefined as any,
      KV_CACHE: undefined as any,
    };
  });

  describe('Bootstrap Service', () => {
    it('allows one-time Super Admin bootstrap and permanently disables setup afterwards', async () => {
      // 1. Initially bootstrap is needed
      const neededBefore = await isBootstrapNeeded(db);
      assert.equal(neededBefore, true);

      // 2. Reject wrong bootstrap token
      await assert.rejects(
        async () => {
          await bootstrapSuperAdmin(
            {
              bootstrapToken: 'wrong-token',
              username: 'admin',
              password: 'SuperAdminPassword123!',
            },
            env
          );
        },
        /Invalid bootstrap token/
      );

      // 3. Successful bootstrap
      const result = await bootstrapSuperAdmin(
        {
          bootstrapToken,
          username: 'admin',
          password: 'SuperAdminPassword123!',
          displayName: 'Admin User',
          email: 'admin@example.com',
        },
        env
      );

      assert.equal(result.success, true);
      assert.equal(result.user.username, 'admin');
      assert.deepEqual(result.user.roles, ['role_super_admin']);

      // 4. Verify bootstrap is now permanently disabled
      const neededAfter = await isBootstrapNeeded(db);
      assert.equal(neededAfter, false);

      // 5. Subsequent bootstrap attempt must fail
      await assert.rejects(
        async () => {
          await bootstrapSuperAdmin(
            {
              bootstrapToken,
              username: 'admin2',
              password: 'SuperAdminPassword123!',
            },
            env
          );
        },
        /already completed/
      );
    });
  });

  describe('Auth Service (Login, Session, MFA)', () => {
    beforeEach(async () => {
      await bootstrapSuperAdmin(
        {
          bootstrapToken,
          username: 'admin',
          password: 'AdminPassword123!',
        },
        env
      );
    });

    it('authenticates user with password and sets HttpOnly Secure Strict cookie', async () => {
      const loginRes = await login(
        {
          username: 'admin',
          password: 'AdminPassword123!',
          clientIp: '198.51.100.10',
          userAgent: 'TestBrowser',
        },
        env
      );

      assert.equal(loginRes.mfaRequired, false);
      if (!loginRes.mfaRequired) {
        assert.ok(loginRes.sessionToken);
        assert.match(loginRes.cookie, /HttpOnly; Secure; SameSite=Strict/);
        assert.match(loginRes.cookie, /edgejump_session=/);
        assert.equal(loginRes.user.username, 'admin');
        assert.deepEqual(loginRes.permissions, []);
        assert.equal(loginRes.mfaSetupRequired, true);

        // Validate session
        const authUser = await validateSession(loginRes.sessionToken, db);
        assert.ok(authUser);
        assert.equal(authUser.username, 'admin');
        assert.equal(authUser.mfaPending, true);

        // Logout revokes session
        const clearCookie = await logout(loginRes.sessionToken, db, authUser.id);
        assert.match(clearCookie, /Max-Age=0/);

        // After logout, session is invalid
        const revalidate = await validateSession(loginRes.sessionToken, db);
        assert.equal(revalidate, null);
      }
    });

    it('rejects invalid password', async () => {
      await assert.rejects(
        async () => {
          await login(
            {
              username: 'admin',
              password: 'WrongPassword!',
              clientIp: '198.51.100.10',
            },
            env
          );
        },
        /Invalid username or password/
      );
    });

    it('enforces TOTP MFA and recovery code login flow', async () => {
      // 1. Initial login to get user ID
      const initialLogin = await login(
        { username: 'admin', password: 'AdminPassword123!', clientIp: '198.51.100.10' },
        env
      );
      assert.equal(initialLogin.mfaRequired, false);
      const userId = (initialLogin as any).user.id;

      // 2. Setup MFA
      const mfaSetup = await setupMfa(userId, env);
      assert.ok(mfaSetup.secret);
      assert.ok(mfaSetup.uri.startsWith('otpauth://'));
      assert.equal(mfaSetup.recoveryCodes.length, 8);

      // 3. Confirm MFA with valid TOTP code
      const validCode = await generateTotpCode(mfaSetup.secret);
      const confirmed = await confirmMfa(userId, validCode, env);
      assert.equal(confirmed, true);

      // 4. Next login requires MFA
      const loginChallenge = await login(
        { username: 'admin', password: 'AdminPassword123!', clientIp: '198.51.100.10' },
        env
      );
      assert.equal(loginChallenge.mfaRequired, true);

      // 5. Login with invalid TOTP code fails
      await assert.rejects(
        async () => {
          await login(
            {
              username: 'admin',
              password: 'AdminPassword123!',
              totpCode: '000000',
              clientIp: '198.51.100.10',
            },
            env
          );
        },
        /Invalid TOTP code/
      );

      // 6. Login with valid TOTP code succeeds
      const loginTotpSuccess = await login(
        {
          username: 'admin',
          password: 'AdminPassword123!',
          totpCode: await generateTotpCode(mfaSetup.secret),
          clientIp: '198.51.100.10',
        },
        env
      );
      assert.equal(loginTotpSuccess.mfaRequired, false);

      // 7. Login with recovery code succeeds
      const recoveryCode = mfaSetup.recoveryCodes[0];
      const loginRecoverySuccess = await login(
        {
          username: 'admin',
          password: 'AdminPassword123!',
          recoveryCode,
          clientIp: '198.51.100.10',
        },
        env
      );
      assert.equal(loginRecoverySuccess.mfaRequired, false);

      // 8. Reusing the same recovery code fails
      await assert.rejects(
        async () => {
          await login(
            {
              username: 'admin',
              password: 'AdminPassword123!',
              recoveryCode,
              clientIp: '198.51.100.10',
            },
            env
          );
        },
        /Invalid or already used recovery code/
      );
    });
  });

  describe('Credential Service (Write-Only / Replace-Only)', () => {
    it('creates and replaces credentials without exposing secret in GET APIs', async () => {
      // 1. Create Credential
      const cred = await createCredential(
        {
          name: 'Target SSH Key',
          type: 'private_key',
          secret: '-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----',
        },
        masterKek,
        db
      );

      assert.ok(cred.id.startsWith('cred_'));
      assert.equal(cred.type, 'private_key');
      assert.equal((cred as any).secret, undefined);
      assert.equal((cred as any).ciphertext, undefined);

      // 2. GET returns metadata ONLY
      const fetched = await getCredential(cred.id, db);
      assert.ok(fetched);
      assert.equal(fetched.id, cred.id);
      assert.equal(fetched.name, 'Target SSH Key');
      assert.equal((fetched as any).secret, undefined);
      assert.equal((fetched as any).credential_ciphertext, undefined);

      // 3. Internal decryption succeeds with Master KEK
      const decrypted = await getDecryptedCredential(cred.id, masterKek, db);
      assert.equal(decrypted.type, 'private_key');
      assert.match(decrypted.plaintext, /BEGIN OPENSSH PRIVATE KEY/);

      // 4. Replace Credential
      const updated = await replaceCredential(cred.id, 'new-secret-key-material', masterKek, db);
      assert.equal(updated.id, cred.id);

      const decryptedUpdated = await getDecryptedCredential(cred.id, masterKek, db);
      assert.equal(decryptedUpdated.plaintext, 'new-secret-key-material');

      // 5. List credentials returns metadata only
      const list = await listCredentials(db);
      assert.equal(list.length, 1);
      assert.equal((list[0] as any).secret, undefined);

      // 6. Delete credential
      await deleteCredential(cred.id, db);
      const afterDelete = await getCredential(cred.id, db);
      assert.equal(afterDelete, null);
    });
  });

  describe('Asset Service & SSRF Protection', () => {
    it('rejects private and loopback targets per SSRF requirements', async () => {
      await assert.rejects(
        async () => {
          await createAsset(
            { name: 'Bad Host 1', hostname: '127.0.0.1', port: 22 },
            null,
            db
          );
        },
        /Private and reserved SSH targets are disabled/
      );

      await assert.rejects(
        async () => {
          await createAsset(
            { name: 'Bad Host 2', hostname: '10.0.0.5', port: 22 },
            null,
            db
          );
        },
        /Private and reserved SSH targets are disabled/
      );

      await assert.rejects(
        async () => {
          await createAsset(
            { name: 'Bad Host 3', hostname: '169.254.169.254', port: 22 },
            null,
            db
          );
        },
        /Private and reserved SSH targets are disabled/
      );
    });

    it('performs CRUD for assets and hierarchical groups', async () => {
      const parentGroup = await createAssetGroup({ name: 'Datacenter East' }, db);
      const childGroup = await createAssetGroup(
        { name: 'Web Cluster', parentId: parentGroup.id },
        db
      );

      const asset = await createAsset(
        {
          name: 'public-node-01',
          hostname: '93.184.216.34',
          port: 22,
          groupIds: [childGroup.id],
        },
        null,
        db
      );

      assert.ok(asset.id);
      assert.deepEqual(asset.groupIds, [childGroup.id]);

      const fetched = await getAsset(asset.id, db);
      assert.ok(fetched);
      assert.equal(fetched.hostname, '93.184.216.34');

      const updated = await updateAsset(asset.id, { description: 'Updated desc' }, db);
      assert.equal(updated.description, 'Updated desc');

      await deleteAsset(asset.id, db);
      assert.equal(await getAsset(asset.id, db), null);
    });
  });

  describe('Audit Service & Metadata Sanitization', () => {
    it('redacts sensitive fields and records immutable audit events', async () => {
      const dirtyMetadata = {
        username: 'alice',
        password: 'PlainTextPassword!',
        token: 'session-secret-token',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        nested: {
          private_key: 'id_ed25519_key_data',
          normalField: 'safe value',
        },
      };

      const sanitized = sanitizeAuditMetadata(dirtyMetadata) as any;
      assert.equal(sanitized.password, '[REDACTED]');
      assert.equal(sanitized.token, '[REDACTED]');
      assert.equal(sanitized.totpSecret, '[REDACTED]');
      assert.equal(sanitized.nested.private_key, '[REDACTED]');
      assert.equal(sanitized.nested.normalField, 'safe value');

      const auditId = await recordAuditEvent(
        {
          action: 'TEST_EVENT',
          resourceType: 'test',
          sourceIp: '127.0.0.1',
          result: 'success',
          metadata: dirtyMetadata,
        },
        db
      );

      const event = await getAuditEvent(auditId, db);
      assert.ok(event);
      assert.ok(event.metadataJson);
      assert.ok(!event.metadataJson.includes('PlainTextPassword!'));
      assert.ok(event.metadataJson.includes('[REDACTED]'));
    });
  });
});
