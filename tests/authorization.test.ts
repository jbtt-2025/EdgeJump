// Authorization Engine and Control Plane Integration Tests for EdgeJump
// Per AGENTS.md JumpServer Model & System Architecture

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createTestDatabase } from './mock-d1.ts';
import {
  createAuthorizationRule,
  checkUserAssetAccountAccess,
  getAuthorizedAssetsForUser,
} from '../src/authorization/authorization-service.ts';
import {
  createAsset,
  createAssetGroup,
  createAssetAccount,
  addAssetToGroup,
} from '../src/assets/asset-service.ts';
import { createCredential } from '../src/credentials/credential-service.ts';
import { hashPassword, DEFAULT_PBKDF2_ITERATIONS } from '../src/crypto/password.ts';
import { bytesToHex } from '../src/crypto/utils.ts';
import { createSession } from '../src/sessions/session-service.ts';
import type { Env } from '../src/types.ts';

function generateMasterKekHex(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(bytes);
}

describe('Asset Authorization Engine (JumpServer Model)', () => {
  let db: D1Database;
  const masterKek = generateMasterKekHex();

  // Test Entities
  let userAlice: { id: string; username: string };
  let userBob: { id: string; username: string };
  let userCharlieDisabled: { id: string; username: string };

  let groupDevOps: { id: string; name: string };
  let groupDevelopers: { id: string; name: string };

  let agProductionRoot: { id: string; name: string };
  let agWebChild: { id: string; name: string };
  let agStaging: { id: string; name: string };

  let assetProdWeb: { id: string; name: string };
  let assetProdDb: { id: string; name: string };
  let assetStagingWeb: { id: string; name: string };
  let assetDisabled: { id: string; name: string };

  let accProdWebDeploy: { id: string; username: string };
  let accProdWebRoot: { id: string; username: string };
  let accProdWebOldAdminDisabled: { id: string; username: string };

  let accProdDbDba: { id: string; username: string };
  let accStagingWebDeploy: { id: string; username: string };
  let accStagingWebAdmin: { id: string; username: string };

  beforeEach(async () => {
    db = await createTestDatabase();
    const now = Date.now();

    // 1. Create Users
    const pwdHash = await hashPassword('TestPassword123!', '', DEFAULT_PBKDF2_ITERATIONS);
    const pwdParams = JSON.stringify({ iterations: pwdHash.iterations });

    userAlice = { id: 'u_alice', username: 'alice' };
    userBob = { id: 'u_bob', username: 'bob' };
    userCharlieDisabled = { id: 'u_charlie', username: 'charlie' };

    await db
      .prepare(
        `INSERT INTO users (id, username, display_name, password_hash, password_algorithm, password_params, password_salt, status, mfa_enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'pbkdf2-sha256', ?, ?, ?, 0, ?, ?)`
      )
      .bind(userAlice.id, userAlice.username, 'Alice Admin', pwdHash.hash, pwdParams, pwdHash.salt, 'active', now, now)
      .run();

    await db
      .prepare(
        `INSERT INTO users (id, username, display_name, password_hash, password_algorithm, password_params, password_salt, status, mfa_enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'pbkdf2-sha256', ?, ?, ?, 0, ?, ?)`
      )
      .bind(userBob.id, userBob.username, 'Bob Dev', pwdHash.hash, pwdParams, pwdHash.salt, 'active', now, now)
      .run();

    await db
      .prepare(
        `INSERT INTO users (id, username, display_name, password_hash, password_algorithm, password_params, password_salt, status, mfa_enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'pbkdf2-sha256', ?, ?, ?, 0, ?, ?)`
      )
      .bind(userCharlieDisabled.id, userCharlieDisabled.username, 'Charlie Disabled', pwdHash.hash, pwdParams, pwdHash.salt, 'disabled', now, now)
      .run();

    // 2. Create User Groups & Memberships
    groupDevOps = { id: 'grp_devops', name: 'DevOps' };
    groupDevelopers = { id: 'grp_developers', name: 'Developers' };

    await db
      .prepare('INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(groupDevOps.id, groupDevOps.name, 'DevOps Team', now, now)
      .run();

    await db
      .prepare('INSERT INTO groups (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(groupDevelopers.id, groupDevelopers.name, 'Developer Team', now, now)
      .run();

    // Alice -> DevOps; Bob -> Developers
    await db
      .prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)')
      .bind(groupDevOps.id, userAlice.id, now)
      .run();

    await db
      .prepare('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)')
      .bind(groupDevelopers.id, userBob.id, now)
      .run();

    // 3. Create Credentials
    const credDeploy = await createCredential({ name: 'Deploy Cred', type: 'password', secret: 'SecretDeployPass1' }, masterKek, db);
    const credRoot = await createCredential({ name: 'Root Cred', type: 'password', secret: 'SecretRootPass2' }, masterKek, db);
    const credDba = await createCredential({ name: 'DBA Cred', type: 'password', secret: 'SecretDbaPass3' }, masterKek, db);

    // 4. Create Asset Groups (Hierarchical tree)
    // Production (agProductionRoot)
    // └── Web (agWebChild)
    // Staging (agStaging)
    agProductionRoot = await createAssetGroup({ name: 'Production', description: 'Production Environment' }, db);
    agWebChild = await createAssetGroup({ name: 'Web', description: 'Production Web Tier', parentId: agProductionRoot.id }, db);
    agStaging = await createAssetGroup({ name: 'Staging', description: 'Staging Environment' }, db);

    // 5. Create Assets
    assetProdWeb = await createAsset(
      { name: 'prod-web-01', hostname: '8.8.8.8', port: 22, platform: 'linux', environment: 'production', enabled: true },
      userAlice.id,
      db
    );
    await addAssetToGroup(agWebChild.id, assetProdWeb.id, db);

    assetProdDb = await createAsset(
      { name: 'prod-db-01', hostname: '8.8.4.4', port: 22, platform: 'linux', environment: 'production', enabled: true },
      userAlice.id,
      db
    );
    await addAssetToGroup(agProductionRoot.id, assetProdDb.id, db);

    assetStagingWeb = await createAsset(
      { name: 'staging-web-01', hostname: '1.1.1.1', port: 22, platform: 'linux', environment: 'staging', enabled: true },
      userAlice.id,
      db
    );
    await addAssetToGroup(agStaging.id, assetStagingWeb.id, db);

    assetDisabled = await createAsset(
      { name: 'disabled-host', hostname: '1.0.0.1', port: 22, platform: 'linux', environment: 'testing', enabled: false },
      userAlice.id,
      db
    );

    // 6. Create Asset Accounts
    accProdWebDeploy = await createAssetAccount({ assetId: assetProdWeb.id, username: 'deploy', credentialId: credDeploy.id, enabled: true }, db);
    accProdWebRoot = await createAssetAccount({ assetId: assetProdWeb.id, username: 'root', credentialId: credRoot.id, enabled: true }, db);
    accProdWebOldAdminDisabled = await createAssetAccount({ assetId: assetProdWeb.id, username: 'oldadmin', credentialId: credRoot.id, enabled: false }, db);

    accProdDbDba = await createAssetAccount({ assetId: assetProdDb.id, username: 'dba', credentialId: credDba.id, enabled: true }, db);

    accStagingWebDeploy = await createAssetAccount({ assetId: assetStagingWeb.id, username: 'deploy', credentialId: credDeploy.id, enabled: true }, db);
    accStagingWebAdmin = await createAssetAccount({ assetId: assetStagingWeb.id, username: 'admin', credentialId: credRoot.id, enabled: true }, db);
  });

  // -------------------------------------------------------------
  // Test 1: Direct user authorization to asset
  // -------------------------------------------------------------
  it('authorizes direct user access to asset and rejects unassigned accounts/users', async () => {
    // Authorize Bob directly to staging-web-01 for account 'deploy' only
    await createAuthorizationRule(
      {
        name: 'Bob Staging Access',
        userIds: [userBob.id],
        assetIds: [assetStagingWeb.id],
        accountIds: [accStagingWebDeploy.id],
        allAccounts: false,
      },
      userAlice.id,
      db
    );

    // 1. Bob connecting to staging-web-01 as deploy -> ALLOWED
    const bobDeployCheck = await checkUserAssetAccountAccess(
      userBob.id,
      assetStagingWeb.id,
      accStagingWebDeploy.id,
      'connect',
      db
    );
    assert.equal(bobDeployCheck.authorized, true);

    // 2. Bob connecting to staging-web-01 as admin -> DENIED (not in rule)
    const bobAdminCheck = await checkUserAssetAccountAccess(
      userBob.id,
      assetStagingWeb.id,
      accStagingWebAdmin.id,
      'connect',
      db
    );
    assert.equal(bobAdminCheck.authorized, false);
    assert.match(bobAdminCheck.reason ?? '', /Default Deny/);

    // 3. Alice connecting to staging-web-01 -> DENIED (not in rule)
    const aliceCheck = await checkUserAssetAccountAccess(
      userAlice.id,
      assetStagingWeb.id,
      accStagingWebDeploy.id,
      'connect',
      db
    );
    assert.equal(aliceCheck.authorized, false);
  });

  // -------------------------------------------------------------
  // Test 2: User group authorization to asset group (tree inheritance)
  // -------------------------------------------------------------
  it('authorizes user group to asset group with hierarchical tree inheritance', async () => {
    // Authorize DevOps group to Production root group for 'deploy' and 'dba' accounts
    // prod-web-01 is in Web child group; prod-db-01 is directly in Production root group
    await createAuthorizationRule(
      {
        name: 'DevOps Production Access',
        groupIds: [groupDevOps.id],
        assetGroupIds: [agProductionRoot.id],
        accountIds: [accProdWebDeploy.id, accProdDbDba.id],
        allAccounts: false,
      },
      userAlice.id,
      db
    );

    // Alice is in DevOps group.
    // 1. Alice -> prod-web-01 (child group) with 'deploy' account -> ALLOWED (tree inheritance)
    const aliceWebCheck = await checkUserAssetAccountAccess(
      userAlice.id,
      assetProdWeb.id,
      accProdWebDeploy.id,
      'connect',
      db
    );
    assert.equal(aliceWebCheck.authorized, true, 'Alice should access child group asset via inheritance');

    // 2. Alice -> prod-db-01 (direct root group) with 'dba' account -> ALLOWED
    const aliceDbCheck = await checkUserAssetAccountAccess(
      userAlice.id,
      assetProdDb.id,
      accProdDbDba.id,
      'connect',
      db
    );
    assert.equal(aliceDbCheck.authorized, true);

    // 3. Alice -> prod-web-01 with 'root' account -> DENIED (account not authorized in rule)
    const aliceRootCheck = await checkUserAssetAccountAccess(
      userAlice.id,
      assetProdWeb.id,
      accProdWebRoot.id,
      'connect',
      db
    );
    assert.equal(aliceRootCheck.authorized, false, 'Unassigned account on authorized asset must be denied');

    // 4. Bob (in Developers group) -> prod-web-01 -> DENIED (group not in rule)
    const bobCheck = await checkUserAssetAccountAccess(
      userBob.id,
      assetProdWeb.id,
      accProdWebDeploy.id,
      'connect',
      db
    );
    assert.equal(bobCheck.authorized, false, 'Users outside DevOps group must be denied');
  });

  // -------------------------------------------------------------
  // Test 3: @ALL account matching (all_accounts = 1) vs specific account matching
  // -------------------------------------------------------------
  it('matches all accounts on asset when all_accounts = 1 (@ALL) vs specific account matching', async () => {
    // Rule with all_accounts = 1 for Bob on staging-web-01
    await createAuthorizationRule(
      {
        name: 'Bob Staging All Accounts',
        userIds: [userBob.id],
        assetIds: [assetStagingWeb.id],
        allAccounts: true, // @ALL
      },
      userAlice.id,
      db
    );

    // 1. Bob accessing 'deploy' account -> ALLOWED
    const checkDeploy = await checkUserAssetAccountAccess(
      userBob.id,
      assetStagingWeb.id,
      accStagingWebDeploy.id,
      'connect',
      db
    );
    assert.equal(checkDeploy.authorized, true);

    // 2. Bob accessing 'admin' account -> ALLOWED via @ALL
    const checkAdmin = await checkUserAssetAccountAccess(
      userBob.id,
      assetStagingWeb.id,
      accStagingWebAdmin.id,
      'connect',
      db
    );
    assert.equal(checkAdmin.authorized, true);

    // Contrast: specific account rule on prod-web-01 for Bob
    await createAuthorizationRule(
      {
        name: 'Bob Specific Account Rule',
        userIds: [userBob.id],
        assetIds: [assetProdWeb.id],
        accountIds: [accProdWebDeploy.id],
        allAccounts: false,
      },
      userAlice.id,
      db
    );

    // 'deploy' is ALLOWED
    const checkSpecificDeploy = await checkUserAssetAccountAccess(
      userBob.id,
      assetProdWeb.id,
      accProdWebDeploy.id,
      'connect',
      db
    );
    assert.equal(checkSpecificDeploy.authorized, true);

    // 'root' is DENIED
    const checkSpecificRoot = await checkUserAssetAccountAccess(
      userBob.id,
      assetProdWeb.id,
      accProdWebRoot.id,
      'connect',
      db
    );
    assert.equal(checkSpecificRoot.authorized, false);
  });

  // -------------------------------------------------------------
  // Test 4: Expired rule (valid_until in past) rejected
  // -------------------------------------------------------------
  it('rejects authorization when rule valid_until is in the past', async () => {
    const now = Date.now();
    await createAuthorizationRule(
      {
        name: 'Expired Rule',
        userIds: [userBob.id],
        assetIds: [assetStagingWeb.id],
        accountIds: [accStagingWebDeploy.id],
        validFrom: now - 3600_000,
        validUntil: now - 1000, // Expired 1 second ago
      },
      userAlice.id,
      db
    );

    const check = await checkUserAssetAccountAccess(
      userBob.id,
      assetStagingWeb.id,
      accStagingWebDeploy.id,
      'connect',
      db,
      now
    );
    assert.equal(check.authorized, false, 'Expired authorization rule must be rejected');
    assert.match(check.reason ?? '', /Default Deny/);
  });

  // -------------------------------------------------------------
  // Test 5: Future rule (valid_from in future) rejected
  // -------------------------------------------------------------
  it('rejects authorization when rule valid_from is in the future', async () => {
    const now = Date.now();
    await createAuthorizationRule(
      {
        name: 'Future Rule',
        userIds: [userBob.id],
        assetIds: [assetStagingWeb.id],
        accountIds: [accStagingWebDeploy.id],
        validFrom: now + 3600_000, // Starts in 1 hour
        validUntil: now + 7200_000,
      },
      userAlice.id,
      db
    );

    const check = await checkUserAssetAccountAccess(
      userBob.id,
      assetStagingWeb.id,
      accStagingWebDeploy.id,
      'connect',
      db,
      now
    );
    assert.equal(check.authorized, false, 'Future authorization rule must be rejected before valid_from');
    assert.match(check.reason ?? '', /Default Deny/);
  });

  // -------------------------------------------------------------
  // Test 6: Disabled user / disabled asset / disabled account rejected
  // -------------------------------------------------------------
  it('rejects disabled user, disabled asset, and disabled account even with matching rule', async () => {
    // 1. Disabled User (Charlie) assigned access
    await createAuthorizationRule(
      {
        name: 'Charlie Rule',
        userIds: [userCharlieDisabled.id],
        assetIds: [assetStagingWeb.id],
        allAccounts: true,
      },
      userAlice.id,
      db
    );
    const userCheck = await checkUserAssetAccountAccess(
      userCharlieDisabled.id,
      assetStagingWeb.id,
      accStagingWebDeploy.id,
      'connect',
      db
    );
    assert.equal(userCheck.authorized, false);
    assert.match(userCheck.reason ?? '', /User account is disabled/);

    // 2. Disabled Asset (assetDisabled)
    const accOnDisabledAsset = await createAssetAccount(
      { assetId: assetDisabled.id, username: 'testuser', credentialId: (await createCredential({ name: 'c', type: 'password', secret: 'p' }, masterKek, db)).id },
      db
    );
    await createAuthorizationRule(
      {
        name: 'Bob Disabled Asset Rule',
        userIds: [userBob.id],
        assetIds: [assetDisabled.id],
        allAccounts: true,
      },
      userAlice.id,
      db
    );
    const assetCheck = await checkUserAssetAccountAccess(
      userBob.id,
      assetDisabled.id,
      accOnDisabledAsset.id,
      'connect',
      db
    );
    assert.equal(assetCheck.authorized, false);
    assert.match(assetCheck.reason ?? '', /Asset is disabled/);

    // 3. Disabled Account (accProdWebOldAdminDisabled) with @ALL rule
    await createAuthorizationRule(
      {
        name: 'Bob Prod Web All Accounts',
        userIds: [userBob.id],
        assetIds: [assetProdWeb.id],
        allAccounts: true,
      },
      userAlice.id,
      db
    );
    const accountCheck = await checkUserAssetAccountAccess(
      userBob.id,
      assetProdWeb.id,
      accProdWebOldAdminDisabled.id,
      'connect',
      db
    );
    assert.equal(accountCheck.authorized, false);
    assert.match(accountCheck.reason ?? '', /Account is disabled/);
  });

  // -------------------------------------------------------------
  // Test 7: Visibility filtering: unauthorized assets are excluded from list
  // -------------------------------------------------------------
  it('filters visible assets dynamically: unauthorized assets are completely hidden', async () => {
    // Authorize Bob ONLY to staging-web-01 for account 'deploy'
    await createAuthorizationRule(
      {
        name: 'Bob Staging Web Only',
        userIds: [userBob.id],
        assetIds: [assetStagingWeb.id],
        accountIds: [accStagingWebDeploy.id],
        allAccounts: false,
      },
      userAlice.id,
      db
    );

    const bobAssets = await getAuthorizedAssetsForUser(userBob.id, db);

    // Bob should see ONLY staging-web-01
    assert.equal(bobAssets.length, 1);
    assert.equal(bobAssets[0].id, assetStagingWeb.id);
    assert.equal(bobAssets[0].name, 'staging-web-01');

    // Only 'deploy' account should be visible to Bob; 'admin' is hidden
    assert.equal(bobAssets[0].accounts.length, 1);
    assert.equal(bobAssets[0].accounts[0].id, accStagingWebDeploy.id);
    assert.equal(bobAssets[0].accounts[0].username, 'deploy');

    // prod-web-01, prod-db-01, and disabled-host must be completely absent
    const assetIds = bobAssets.map((a) => a.id);
    assert.ok(!assetIds.includes(assetProdWeb.id));
    assert.ok(!assetIds.includes(assetProdDb.id));
    assert.ok(!assetIds.includes(assetDisabled.id));

    // User with no rules should see an empty list
    const aliceAssetsBeforeRule = await getAuthorizedAssetsForUser(userAlice.id, db);
    assert.equal(aliceAssetsBeforeRule.length, 0);

    // Disabled user should see an empty list even if rule exists
    const charlieAssets = await getAuthorizedAssetsForUser(userCharlieDisabled.id, db);
    assert.equal(charlieAssets.length, 0);
  });

  // -------------------------------------------------------------
  // Test 8: End-to-end Session Service Integration
  // -------------------------------------------------------------
  it('creates an SSH session with snapshot fields, ticket, and audit event when authorized', async () => {
    // Authorize Bob to staging-web-01 for deploy
    await createAuthorizationRule(
      {
        name: 'Bob Staging Connection',
        userIds: [userBob.id],
        assetIds: [assetStagingWeb.id],
        accountIds: [accStagingWebDeploy.id],
        allAccounts: false,
      },
      userAlice.id,
      db
    );

    const mockEnv: Env = {
      DB: db,
      CREDENTIAL_KEK_V1: masterKek,
      AUTH_PEPPER: 'test-pepper',
      SSH_SESSIONS: undefined as any,
      RATE_LIMIT: undefined as any,
      RECORDINGS: undefined as any,
      KV_CACHE: undefined as any,
    };

    // Successful session creation
    const sessionRes = await createSession(
      userBob.id,
      assetStagingWeb.id,
      accStagingWebDeploy.id,
      '198.51.100.25',
      'Mozilla/5.0 Test Agent',
      mockEnv
    );

    assert.ok(sessionRes.sessionId.startsWith('sess_'));
    assert.ok(sessionRes.ticket.includes('.'));
    assert.ok(sessionRes.wsUrl.includes(sessionRes.sessionId));

    // Verify session record in D1 ssh_sessions with immutable snapshots
    const sessionRow = await db
      .prepare('SELECT * FROM ssh_sessions WHERE id = ?')
      .bind(sessionRes.sessionId)
      .first<any>();

    assert.ok(sessionRow);
    assert.equal(sessionRow.username_snapshot, 'bob');
    assert.equal(sessionRow.asset_name_snapshot, 'staging-web-01');
    assert.equal(sessionRow.account_name_snapshot, 'deploy');
    assert.equal(sessionRow.source_ip, '198.51.100.25');
    assert.equal(sessionRow.status, 'creating');

    // Verify audit event SESSION_CREATED
    const auditRow = await db
      .prepare("SELECT * FROM audit_events WHERE action = 'SESSION_CREATED' AND resource_id = ?")
      .bind(sessionRes.sessionId)
      .first<any>();

    assert.ok(auditRow);
    assert.equal(auditRow.actor_username_snapshot, 'bob');
    assert.equal(auditRow.result, 'success');

    // Attempting unauthorized session creation must throw and log SESSION_DENIED
    await assert.rejects(
      async () => {
        await createSession(
          userBob.id,
          assetProdWeb.id, // Bob not authorized to prod-web-01
          accProdWebDeploy.id,
          '198.51.100.25',
          'Mozilla/5.0 Test Agent',
          mockEnv
        );
      },
      /Access denied/
    );

    const deniedAudit = await db
      .prepare("SELECT * FROM audit_events WHERE action = 'SESSION_DENIED' AND actor_user_id = ?")
      .bind(userBob.id)
      .first<any>();

    assert.ok(deniedAudit);
    assert.equal(deniedAudit.result, 'denied');
  });
});
