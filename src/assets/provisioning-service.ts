import type { Env } from '../types.ts';
import type { AccountConnectionInput, AssetAccountConnectionInput, AssetAccountSummary, CredentialSummary } from '../shared/types.ts';
import { prepareAssetCreation, prepareAccountCreation, getAsset, getAssetAccount, type CreateAssetInput } from './asset-service.ts';
import { prepareCredentialCreation } from '../credentials/credential-service.ts';
import { prepareAuditEvent } from '../audit/audit-service.ts';

type Actor = { id: string; username: string; sourceIp: string; userAgent?: string };

export class ProvisioningInputError extends Error {}

async function addAudit(statements: D1PreparedStatement[], actor: Actor, env: Env,
  action: string, resourceType: string, resourceId: string, resourceName: string, metadata?: Record<string, unknown>) {
  const audit = await prepareAuditEvent({ actorUserId: actor.id, actorUsername: actor.username,
    sourceIp: actor.sourceIp, userAgent: actor.userAgent, result: 'success', action, resourceType, resourceId, resourceName, metadata }, env.DB);
  statements.push(audit.statement);
}

async function prepareConnection(input: AssetAccountConnectionInput, assetId: string, assetName: string,
  statements: D1PreparedStatement[], actor: Actor, env: Env): Promise<AssetAccountSummary> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new ProvisioningInputError('SSH 账号格式不正确。');
  let accountInput: AccountConnectionInput;
  let credential: Pick<CredentialSummary, 'id' | 'name' | 'type'>;
  if ('sourceAccountId' in input) {
    if (typeof input.sourceAccountId !== 'string') throw new ProvisioningInputError('请选择要复用的 SSH 账号。');
    const source = await getAssetAccount(input.sourceAccountId, env.DB);
    if (!source || !source.enabled) throw new ProvisioningInputError('要复用的 SSH 账号不存在或已停用。');
    accountInput = { username: source.username, credentialId: source.credentialId, enabled: true };
    credential = { id: source.credentialId, name: source.credentialName, type: source.credentialType };
  } else {
    if (typeof input.username !== 'string' || !input.username.trim()) throw new ProvisioningInputError('请输入 SSH 用户名。');
    if (!!input.credentialId === !!input.credential) throw new ProvisioningInputError('请选择已有凭证或新建凭证。');
    accountInput = input;
    if (input.credential) {
      const value = input.credential;
      if (!['password', 'private_key'].includes(value.type) || typeof value.secret !== 'string' || !value.secret.trim() ||
        (value.name !== undefined && typeof value.name !== 'string')) throw new ProvisioningInputError('请填写有效的 SSH 密码或私钥。');
      const prepared = await prepareCredentialCreation({ name: value.name?.trim() || `${assetName} / ${input.username.trim()}`,
        type: value.type, secret: value.secret }, env.CREDENTIAL_KEK_V1 ?? '', env.DB);
      credential = prepared.credential;
      statements.push(prepared.statement);
      await addAudit(statements, actor, env, 'CREDENTIAL_CREATED', 'credential', credential.id, credential.name);
    } else {
      const existing = await env.DB.prepare('SELECT id, name, type FROM credentials WHERE id = ?')
        .bind(input.credentialId).first<CredentialSummary>();
      if (!existing) throw new ProvisioningInputError('所选凭证不存在，请重新选择。');
      credential = existing;
    }
  }
  const prepared = prepareAccountCreation({ assetId, username: accountInput.username, credentialId: credential.id, enabled: accountInput.enabled }, credential, env.DB);
  statements.push(prepared.statement);
  await addAudit(statements, actor, env, 'ACCOUNT_CREATED', 'account', prepared.account.id, prepared.account.username, { assetId });
  return prepared.account;
}

/** D1 batch commits the machine, its accounts, encrypted credentials and audit events together. */
export async function provisionAsset(input: CreateAssetInput & { accounts: AssetAccountConnectionInput[] }, actor: Actor, env: Env) {
  if (!Array.isArray(input.accounts)) throw new ProvisioningInputError('SSH 账号列表格式不正确。');
  const prepared = await prepareAssetCreation(input, actor.id, env.DB);
  const statements = [...prepared.statements];
  const accounts: AssetAccountSummary[] = [];
  for (const account of input.accounts) accounts.push(await prepareConnection(account, prepared.asset.id, prepared.asset.name, statements, actor, env));
  if (new Set(accounts.map((account) => account.username)).size !== accounts.length) throw new ProvisioningInputError('同一台机器不能重复添加相同的 SSH 用户名。');
  await addAudit(statements, actor, env, 'ASSET_CREATED', 'asset', prepared.asset.id, prepared.asset.name);
  await env.DB.batch(statements);
  return { ...prepared.asset, accounts };
}

export async function provisionAccount(assetId: string, input: AccountConnectionInput, actor: Actor, env: Env) {
  const asset = await getAsset(assetId, env.DB);
  if (!asset) throw new ProvisioningInputError('目标机器不存在，请重新选择。');
  const statements: D1PreparedStatement[] = [];
  const account = await prepareConnection(input, asset.id, asset.name, statements, actor, env);
  const existing = await env.DB.prepare('SELECT id FROM asset_accounts WHERE asset_id = ? AND username = ?')
    .bind(assetId, account.username).first();
  if (existing) throw new ProvisioningInputError('该机器已存在同名 SSH 账号。');
  await env.DB.batch(statements);
  return account;
}
