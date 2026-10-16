import React from 'react';
import type { AccountConnectionInput, AssetAccountConnectionInput, AssetAccountSummary, AssetSummary, CredentialSummary } from '../../../src/shared/types';
import { Field, inputClass, buttonClass } from './components';

export function AccountConnectionFields({ value, onChange, credentials, allowCreate = true }: {
  value: AccountConnectionInput; onChange: (value: AccountConnectionInput) => void; credentials: CredentialSummary[]; allowCreate?: boolean;
}) {
  const fresh = value.credential;
  return <>
    <Field label="SSH 用户名"><input required value={value.username} onChange={(event) => onChange({ ...value, username: event.target.value })} className={inputClass} placeholder="例如 root、deploy" /></Field>
    <Field label="绑定凭证"><select required value={fresh ? '__new__' : value.credentialId ?? ''} className={inputClass}
      onChange={(event) => onChange(event.target.value === '__new__'
        ? { ...value, credentialId: undefined, credential: { name: '', type: 'password', secret: '' } }
        : { ...value, credentialId: event.target.value, credential: undefined })}>
      <option value="">选择凭证</option>
      {credentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.name} · {credential.type === 'password' ? '密码' : '私钥'}</option>)}
      {allowCreate && <option value="__new__">＋ 新建凭证</option>}
    </select></Field>
    {fresh && <div className="border-l-2 border-blue-500/50 pl-4 space-y-4">
      <div className="grid sm:grid-cols-2 gap-4">
        <Field label="凭证名称（可选）"><input value={fresh.name ?? ''} onChange={(event) => onChange({ ...value, credential: { ...fresh, name: event.target.value } })} className={inputClass} placeholder="默认使用机器名 / SSH 用户名" /></Field>
        <Field label="凭证类型"><select value={fresh.type} onChange={(event) => onChange({ ...value, credential: { ...fresh, type: event.target.value as 'password' | 'private_key', secret: '' } })} className={inputClass}><option value="password">密码</option><option value="private_key">私钥</option></select></Field>
      </div>
      <Field label={fresh.type === 'password' ? 'SSH 密码' : 'SSH 私钥'}>{fresh.type === 'password'
        ? <input required type="password" autoComplete="new-password" value={fresh.secret} onChange={(event) => onChange({ ...value, credential: { ...fresh, secret: event.target.value } })} className={inputClass} />
        : <textarea required rows={5} autoComplete="off" value={fresh.secret} onChange={(event) => onChange({ ...value, credential: { ...fresh, secret: event.target.value } })} className={`${inputClass} font-mono`} placeholder="粘贴完整私钥" />}</Field>
    </div>}
  </>;
}

export function AssetConnectionFields({ value, onChange, accounts, assets, credentials }: {
  value: AssetAccountConnectionInput[]; onChange: (value: AssetAccountConnectionInput[]) => void;
  accounts: AssetAccountSummary[]; assets: AssetSummary[]; credentials: CredentialSummary[];
}) {
  const assetName = (id: string) => assets.find((asset) => asset.id === id)?.name ?? '';
  const selected = new Set(value.flatMap((item) => 'sourceAccountId' in item ? [item.sourceAccountId] : []));
  const available = accounts.filter((account) => account.enabled && !selected.has(account.id));
  return <fieldset className="border-t border-slate-600 pt-4 space-y-4">
    <legend className="font-medium pr-3">SSH 账号</legend>
    {!value.length && <p className="text-sm text-slate-400">选择已有账号，或直接新建账号和凭证。也可保存机器后再添加。</p>}
    {value.map((item, index) => {
      const source = 'sourceAccountId' in item ? accounts.find((account) => account.id === item.sourceAccountId) : null;
      return <section key={index} className="border border-slate-600 rounded-lg p-4 space-y-4" aria-label={`SSH 账号 ${index + 1}`}>
        <div className="flex items-center justify-between gap-3"><strong className="text-sm">{source ? source.username : `新账号 ${index + 1}`}</strong><button type="button" className="text-sm text-slate-400 hover:text-red-300" aria-label={`移除账号 ${index + 1}`} onClick={() => onChange(value.filter((_, itemIndex) => itemIndex !== index))}>移除</button></div>
        {'sourceAccountId' in item ? <p className="text-sm text-slate-300">{source?.credentialName} · 来自 {source ? assetName(source.assetId) : ''}</p>
          : <AccountConnectionFields value={item} credentials={credentials} onChange={(next) => onChange(value.map((current, itemIndex) => itemIndex === index ? next : current))} />}
      </section>;
    })}
    <div className="flex flex-col sm:flex-row gap-3">
      <select aria-label="复用已有 SSH 账号" value="" className={`${inputClass} flex-1 min-w-0`} disabled={!available.length} onChange={(event) => { if (event.target.value) onChange([...value, { sourceAccountId: event.target.value }]); }}>
        <option value="">{available.length ? '＋ 复用已有 SSH 账号' : '暂无可复用的 SSH 账号'}</option>
        {available.map((account) => <option key={account.id} value={account.id}>{account.username} · {account.credentialName}（{assetName(account.assetId)}）</option>)}
      </select>
      <button type="button" className={`${buttonClass} shrink-0`} onClick={() => onChange([...value, { username: '', credentialId: '',
        ...(!credentials.length ? { credential: { name: '', type: 'password', secret: '' } as const } : {}), enabled: true }])}>新建 SSH 账号</button>
    </div>
  </fieldset>;
}
