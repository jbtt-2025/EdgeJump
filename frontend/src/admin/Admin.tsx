import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { AssetTree, groupPath } from '../assets/AssetTree';
import type { AssetSummary, AssetGroupSummary, AssetAccountSummary, CredentialSummary, AuthorizationRuleSummary,
  AdminUserSummary, UserGroupSummary, RoleSummary, HostKeySummary } from '../../../src/shared/types';

type Kind = 'asset' | 'asset-group' | 'account' | 'credential' | 'rule' | 'user' | 'user-group' | 'replace' | 'password';
import { Field, Choices, Table, Cell, inputClass, buttonClass, primaryClass } from './components';

export function Admin() {
  const { hasPermission: can, deployType } = useAuth();
  const tabs = [
    ['assets', '资产', 'asset.read'], ['asset-groups', '资产组', 'asset.read'], ['accounts', 'SSH 账号', 'asset.read'],
    ['credentials', '凭证', 'credential.create'], ['rules', '授权规则', 'authorization.read'], ['users', '用户', 'user.read'],
    ['user-groups', '用户组', 'group.read'], ['roles', '角色', 'user.read'], ['settings', '系统设置', 'settings.read'],
  ].filter(([, , permission]) => can(permission));
  const [tab, setTab] = useState(tabs[0]?.[0] ?? 'assets');
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [groups, setGroups] = useState<AssetGroupSummary[]>([]);
  const [accounts, setAccounts] = useState<AssetAccountSummary[]>([]);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [rules, setRules] = useState<AuthorizationRuleSummary[]>([]);
  const [users, setUsers] = useState<AdminUserSummary[]>([]);
  const [userGroups, setUserGroups] = useState<UserGroupSummary[]>([]);
  const [roles, setRoles] = useState<RoleSummary[]>([]);
  const [subjects, setSubjects] = useState<{ users: { id: string; username: string }[]; groups: { id: string; name: string }[] }>({ users: [], groups: [] });
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [hostAsset, setHostAsset] = useState<AssetSummary | null>(null);
  const [hostKeys, setHostKeys] = useState<HostKeySummary[]>([]);
  const [modal, setModal] = useState<{ kind: Kind; id?: string } | null>(null);
  const [form, setForm] = useState<Record<string, any>>({});
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const set = (key: string, value: unknown) => setForm((form) => ({ ...form, [key]: value }));
  const assetOptions = assets.map((asset) => ({ id: asset.id, label: asset.name }));
  const groupOptions = groups.map((group) => ({ id: group.id, label: groupPath(group.id, groups) }));

  async function load() {
    setLoading(true); setError('');
    try {
      if (['assets', 'asset-groups', 'accounts', 'rules'].includes(tab)) {
        const [nextAssets, nextGroups] = await Promise.all([api.listAdminAssets(), api.listAssetGroups()]);
        setAssets(nextAssets); setGroups(nextGroups);
        if (tab === 'accounts' || tab === 'rules') setAccounts((await Promise.all(nextAssets.map((asset) => api.listAssetAccounts(asset.id)))).flat());
      }
      if ((tab === 'credentials' || tab === 'accounts') && ['credential.create', 'credential.replace', 'credential.delete'].some(can)) setCredentials(await api.listCredentials());
      if (tab === 'rules') {
        setRules(await api.listAuthorizations());
        if (can('authorization.write')) setSubjects(await api.getAuthorizationOptions());
      }
      if (tab === 'users' || tab === 'user-groups') {
        if (can('user.read')) setUsers(await api.listUsers());
        if (can('group.read')) setUserGroups(await api.listUserGroups());
      }
      if (tab === 'users' || tab === 'roles') setRoles(await api.listRoles());
      if (tab === 'settings') setSettings(await api.getSettings());
    } catch (error) { setError((error as Error).message); }
    finally { setLoading(false); }
  }
  useEffect(() => { setMessage(''); void load(); }, [tab]);

  function open(kind: Kind, row?: Record<string, any>) {
    setError('');
    const defaults: Record<Kind, Record<string, any>> = {
      asset: { name: '', hostname: '', port: 22, platform: 'linux', environment: 'production', enabled: true, groupIds: [] },
      'asset-group': { name: '', parentId: '', description: '' },
      account: { assetId: assets[0]?.id ?? '', username: '', credentialId: credentials[0]?.id ?? '', enabled: true },
      credential: { name: '', type: 'password', secret: '' },
      rule: { name: '', userIds: [], groupIds: [], assetIds: [], assetGroupIds: [], accountIds: [], allAccounts: false, enabled: true, validFrom: '', validUntil: '' },
      user: { username: '', password: '', displayName: '', roles: ['User'], groups: [] },
      'user-group': { name: '', description: '', members: [] }, replace: { secret: '' }, password: { password: '' },
    };
    const values = { ...defaults[kind], ...row };
    if (kind === 'rule' && row) {
      for (const key of ['validFrom', 'validUntil']) values[key] = row[key] ? localTime(row[key]) : '';
    }
    if (kind === 'user-group' && row) values.members = row.memberIds ?? [];
    setForm(values); setModal({ kind, id: row?.id });
  }
  const localTime = (time: number) => { const date = new Date(time); return new Date(time - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  async function act(action: () => Promise<unknown>) {
    setError(''); setMessage('');
    try { await action(); setMessage('已保存'); await load(); } catch (error) { setError((error as Error).message); }
  }
  async function remove(name: string, action: () => Promise<unknown>) { if (confirm(`确认删除「${name}」？`)) await act(action); }
  async function cleanupRecordings() {
    if (!confirm('按当前保留天数清理一批过期录像？')) return;
    setCleaning(true); setError(''); setMessage('');
    try {
      const result = await api.cleanupExpiredRecordings();
      setMessage(result.retentionDays <= 0 ? '自动清理已关闭，请先设置保留天数。' :
        `本批已清理 ${result.cleanedCount} 个会话录像。${result.budgetExhausted ? '剩余任务将由后台分批继续。' : ''}`);
    } catch (error) { setError((error as Error).message); }
    finally { setCleaning(false); }
  }
  async function save(event: React.FormEvent) {
    event.preventDefault(); if (!modal) return;
    setSaving(true); setError('');
    const { kind, id } = modal;
    try {
      if (kind === 'asset') id ? await api.updateAsset(id, form) : await api.createAsset(form);
      if (kind === 'asset-group') {
        const data = { ...form, parentId: form.parentId || null };
        id ? await api.updateAssetGroup(id, data) : await api.createAssetGroup(data);
      }
      if (kind === 'account') id ? await api.updateAssetAccount(form.assetId, id, form) : await api.createAssetAccount(form.assetId, form);
      if (kind === 'credential') await api.createCredential(form);
      if (kind === 'replace') await api.replaceCredential(id!, form.secret);
      if (kind === 'password') await api.resetUserPassword(id!, form.password);
      if (kind === 'user') id ? await api.updateUser(id, form) : await api.createUser(form);
      if (kind === 'user-group') {
        if (id) await api.updateUserGroup(id, form);
        else {
          const created = await api.createUserGroup(form) as { id: string };
          if (form.members.length) await api.updateUserGroup(created.id, { members: form.members });
        }
      }
      if (kind === 'rule') {
        if (!form.userIds.length && !form.groupIds.length) throw new Error('请选择至少一个用户或用户组');
        if (!form.assetIds.length && !form.assetGroupIds.length) throw new Error('请选择至少一个资产或资产组');
        if (!form.allAccounts && !form.accountIds.length) throw new Error('请选择具体 SSH 账号');
        if (form.allAccounts && !confirm('@ALL 将授予目标资产上的全部账号，包括 root 和以后新增的账号。确认授权？')) return;
        const data = { ...form, actions: ['connect'], validFrom: form.validFrom ? new Date(form.validFrom).getTime() : null, validUntil: form.validUntil ? new Date(form.validUntil).getTime() : null };
        id ? await api.updateAuthorization(id, data) : await api.createAuthorization(data);
      }
      setModal(null); setForm({}); setMessage('已保存'); await load();
    } catch (error) { setError((error as Error).message); }
    finally { setSaving(false); }
  }
  async function showHostKeys(asset: AssetSummary) { setError(''); try { setHostKeys(await api.getHostKey(asset.id)); setHostAsset(asset); } catch (error) { setError((error as Error).message); } }
  const assetName = (id: string) => assets.find((asset) => asset.id === id)?.name ?? id;
  const titles: Record<Kind, string> = { asset: '主机资产', 'asset-group': '资产组', account: 'SSH 账号', credential: '凭证', rule: '授权规则', user: '用户', 'user-group': '用户组', replace: '替换凭证', password: '重置密码' };
  const createKinds: Record<string, [Kind, string]> = { assets: ['asset', 'asset.create'], 'asset-groups': ['asset-group', 'asset.create'], accounts: ['account', 'credential.create'], credentials: ['credential', 'credential.create'], rules: ['rule', 'authorization.write'], users: ['user', 'user.create'], 'user-groups': ['user-group', 'group.write'] };
  const create = createKinds[tab];

  return <main className="max-w-7xl w-full mx-auto p-6 space-y-5">
    <div className="flex justify-between items-center"><h1 className="text-xl font-semibold">堡垒机管理</h1><button onClick={load} disabled={loading} className={buttonClass}>{loading ? '刷新中…' : '刷新'}</button></div>
    <nav className="flex gap-1 flex-wrap border-b border-slate-700 pb-3">{tabs.map(([id, name]) => <button key={id} onClick={() => setTab(id)} className={`px-4 py-2 text-sm rounded-lg ${tab === id ? 'bg-blue-600 text-white' : 'text-slate-400 hover:bg-slate-800'}`}>{name}</button>)}</nav>
    {error && !modal && <p role="alert" className="text-red-300">{error}</p>}{message && <p role="status" className="text-emerald-400 text-sm">{message}</p>}
    <section className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
      <div className="p-4 flex justify-between items-center border-b border-slate-700"><h2 className="font-medium">{tabs.find(([id]) => id === tab)?.[1]}</h2>{create && can(create[1]) && <button onClick={() => open(create[0])} className={primaryClass}>新建{titles[create[0]]}</button>}</div>
      {tab === 'assets' && <Table columns={['资产', '地址', '资产组', '状态', '操作']} empty={!assets.length}>{assets.map((asset) => <tr key={asset.id}><Cell><strong>{asset.name}</strong><p className="text-slate-400 text-xs mt-1">{asset.environment} · {asset.platform}</p></Cell><Cell><span className="font-mono">{asset.hostname}:{asset.port}</span></Cell><Cell>{asset.groupIds.map((id) => groupPath(id, groups)).join('、') || '未分组'}</Cell><Cell>{asset.enabled ? '启用' : '停用'}</Cell><Cell><div className="flex gap-3 whitespace-nowrap">{can('asset.update') && <button className="text-blue-300" onClick={() => open('asset', asset)}>编辑</button>}<button className="text-blue-300" onClick={() => showHostKeys(asset)}>Host Key</button>{can('asset.delete') && <button className="text-red-300" onClick={() => remove(asset.name, () => api.deleteAsset(asset.id))}>删除</button>}</div></Cell></tr>)}</Table>}
      {tab === 'asset-groups' && <div className="grid md:grid-cols-[240px_1fr]"><div className="p-5 border-r border-slate-700"><AssetTree groups={groups} assets={assets} onGroup={(id) => { if (id && can('asset.update')) open('asset-group', groups.find((group) => group.id === id)); }} /></div><Table columns={['路径', '资产数', '操作']} empty={!groups.length}>{groups.map((group) => <tr key={group.id}><Cell>{groupPath(group.id, groups)}</Cell><Cell>{group.assetCount ?? 0}</Cell><Cell><div className="flex gap-3">{can('asset.update') && <button onClick={() => open('asset-group', group)} className="text-blue-300">编辑</button>}{can('asset.delete') && <button onClick={() => remove(group.name, () => api.deleteAssetGroup(group.id))} className="text-red-300">删除</button>}</div></Cell></tr>)}</Table></div>}
      {tab === 'accounts' && <Table columns={['资产', 'SSH 账号', '绑定凭证', '状态', '操作']} empty={!accounts.length}>{accounts.map((account) => <tr key={account.id}><Cell>{assetName(account.assetId)}</Cell><Cell><span className="font-mono">{account.username}</span></Cell><Cell>{account.credentialName}</Cell><Cell>{account.enabled ? '启用' : '停用'}</Cell><Cell><div className="flex gap-3">{can('credential.replace') && <button onClick={() => open('account', account)} className="text-blue-300">编辑 / 改绑</button>}{can('credential.delete') && <button onClick={() => remove(account.username, () => api.deleteAssetAccount(account.assetId, account.id))} className="text-red-300">删除</button>}</div></Cell></tr>)}</Table>}
      {tab === 'credentials' && <Table columns={['凭证', '类型', '更新时间', '密钥版本', '操作']} empty={!credentials.length}>{credentials.map((credential) => <tr key={credential.id}><Cell>{credential.name}<p className="text-emerald-400 text-xs mt-1">凭证已配置</p></Cell><Cell>{credential.type === 'private_key' ? '私钥' : '密码'}</Cell><Cell>{new Date(credential.updatedAt).toLocaleString()}</Cell><Cell>{credential.keyVersion}</Cell><Cell><div className="flex gap-3">{can('credential.replace') && <button onClick={() => open('replace', { id: credential.id, secret: '' })} className="text-blue-300">替换</button>}{can('credential.delete') && <button onClick={() => remove(credential.name, () => api.deleteCredential(credential.id))} className="text-red-300">删除</button>}</div></Cell></tr>)}</Table>}
      {tab === 'rules' && <Table columns={['规则', '主体 / 目标', '账号', '有效期', '状态', '操作']} empty={!rules.length}>{rules.map((rule) => <tr key={rule.id}><Cell>{rule.name}</Cell><Cell><p>{rule.userIds.map((id) => subjects.users.find((user) => user.id === id)?.username ?? id).concat(rule.groupIds.map((id) => subjects.groups.find((group) => group.id === id)?.name ?? id)).join('、')}</p><p className="text-slate-400 mt-1">{rule.assetIds.map(assetName).concat(rule.assetGroupIds.map((id) => groupPath(id, groups))).join('、')}</p></Cell><Cell>{rule.allAccounts ? '@ALL（含新增账号）' : rule.accountIds.map((id) => accounts.find((account) => account.id === id)?.username ?? id).join('、')}</Cell><Cell><p>{rule.validFrom ? new Date(rule.validFrom).toLocaleString() : '立即生效'}</p><p className="text-slate-400 mt-1">{rule.validUntil ? new Date(rule.validUntil).toLocaleString() : '长期有效'}</p></Cell><Cell>{!rule.enabled ? '停用' : rule.validUntil && rule.validUntil < Date.now() ? '已过期' : rule.validFrom && rule.validFrom > Date.now() ? '待生效' : '生效中'}</Cell><Cell>{can('authorization.write') && <div className="flex gap-3"><button onClick={() => open('rule', rule)} className="text-blue-300">编辑</button><button onClick={() => remove(rule.name, () => api.deleteAuthorization(rule.id))} className="text-red-300">删除</button></div>}</Cell></tr>)}</Table>}
      {tab === 'users' && <Table columns={['用户', '角色', '用户组', 'MFA', '最后登录', '状态', '操作']} empty={!users.length}>{users.map((user) => <tr key={user.id}><Cell><strong>{user.username}</strong><p className="text-slate-400 text-xs mt-1">{user.displayName}</p></Cell><Cell>{user.roles.join('、')}</Cell><Cell>{user.groups.join('、') || '—'}</Cell><Cell>{user.mfaEnabled ? '已启用' : '未启用'}</Cell><Cell>{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : '尚未登录'}</Cell><Cell>{user.status}</Cell><Cell><div className="flex flex-wrap gap-3">{can('user.update') && <><button onClick={() => open('user', user)} className="text-blue-300">编辑</button><button onClick={() => open('password', { id: user.id, password: '' })} className="text-blue-300">重置密码</button></>}{can('user.disable') && <button onClick={() => act(() => user.status === 'active' ? api.disableUser(user.id) : api.enableUser(user.id))} className={user.status === 'active' ? 'text-red-300' : 'text-emerald-300'}>{user.status === 'active' ? '禁用' : '启用'}</button>}</div></Cell></tr>)}</Table>}
      {tab === 'user-groups' && <Table columns={['用户组', '成员', '操作']} empty={!userGroups.length}>{userGroups.map((group) => <tr key={group.id}><Cell>{group.name}</Cell><Cell>{group.memberIds.map((id) => users.find((user) => user.id === id)?.username ?? id).join('、') || '无成员'}</Cell><Cell>{can('group.write') && <div className="flex gap-3"><button onClick={() => open('user-group', group)} className="text-blue-300">编辑成员</button><button onClick={() => remove(group.name, () => api.deleteUserGroup(group.id))} className="text-red-300">删除</button></div>}</Cell></tr>)}</Table>}
      {tab === 'roles' && <div className="p-5 space-y-6">{roles.map((role) => <div key={role.id} className="space-y-2"><h3 className="font-medium">{role.name}</h3><p className="text-slate-400 text-sm">{role.description}</p><p className="font-mono text-xs text-blue-300 leading-6">{role.permissions.join(' · ')}</p>{role.id === 'role_security_auditor' && can('settings.write') && <label className="flex gap-2 items-center text-sm"><input type="checkbox" checked={role.permissions.includes('session.terminate')} onChange={(event) => act(() => api.setAuditorTermination(event.target.checked))} />允许安全审计员终止会话</label>}</div>)}</div>}
      {tab === 'settings' && <div className="p-5 grid md:grid-cols-2 gap-6">{[
        ['session_idle_timeout', 'SSH 空闲超时（秒）'], ['session_max_duration', 'SSH 最大时长（秒）'], ['auth_session_idle_ttl', '登录空闲超时（秒）'], ['auth_session_absolute_ttl', '登录最长有效期（秒）'], ['recording_retention_days', '录像自动清理保留天数（0 表示关闭）'],
        ['require_mfa_for_all', '所有用户强制 MFA'], ['terminate_active_sessions_on_disable', '禁用用户时终止在线会话'], ['terminate_sessions_on_permission_revocation', '撤销权限时终止在线会话'], ['disconnect_on_browser_close', '关闭浏览器时断开 SSH'],
      ].map(([key, label]) => <div key={key} className="space-y-3"><Field label={label}>{['true', 'false'].includes(settings[key]) ? <select disabled={!can('settings.write')} value={settings[key]} onChange={(event) => setSettings({ ...settings, [key]: event.target.value })} className={inputClass}><option value="true">开启</option><option value="false">关闭</option></select> : <input type="number" min={key === 'recording_retention_days' ? 0 : 1} disabled={!can('settings.write') || key === 'recording_retention_days' && deployType === 'demo'} value={settings[key] ?? ''} onChange={(event) => setSettings({ ...settings, [key]: event.target.value })} className={inputClass} />}</Field>{can('settings.write') && <button className={buttonClass} disabled={key === 'recording_retention_days' && deployType === 'demo'} onClick={() => act(() => api.updateSetting(key, settings[key]))}>保存</button>}</div>)}<div className="md:col-span-2 border-t border-slate-700 pt-5"><p className="text-sm text-slate-400 mb-3">录像默认不由应用删除。生产环境请在存储桶配置 180 / 365 天保留或 Bucket Lock。</p>{can('settings.write') && <button disabled={cleaning} onClick={() => void cleanupRecordings()} className={buttonClass}>{cleaning ? '清理中…' : '清理一批过期录像'}</button>}</div></div>}
    </section>

    {modal && <div className="fixed inset-0 z-40 bg-black/70 p-5 overflow-auto flex items-start justify-center"><form onSubmit={save} aria-label={`${modal.id ? '编辑' : '新建'}${titles[modal.kind]}`} className="my-auto w-full max-w-2xl bg-slate-800 border border-slate-600 rounded-xl p-6 space-y-5">
      <h2 className="text-xl font-semibold">{modal.id && !['replace', 'password'].includes(modal.kind) ? '编辑' : ''}{titles[modal.kind]}</h2>
      {error && <p role="alert" className="text-red-300">{error}</p>}
      {!['replace', 'password', 'account'].includes(modal.kind) && <Field label={modal.kind === 'user' ? '用户名' : '名称'}><input autoFocus required disabled={modal.kind === 'user' && !!modal.id} value={form[modal.kind === 'user' ? 'username' : 'name'] ?? ''} onChange={(event) => set(modal.kind === 'user' ? 'username' : 'name', event.target.value)} className={inputClass} /></Field>}
      {modal.kind === 'asset' && <><div className="grid sm:grid-cols-[1fr_100px] gap-4"><Field label="公网 IP / 域名"><input required value={form.hostname} onChange={(event) => set('hostname', event.target.value)} className={inputClass} /></Field><Field label="SSH 端口"><input required type="number" min={1} max={65535} value={form.port} onChange={(event) => set('port', Number(event.target.value))} className={inputClass} /></Field></div><Field label="环境"><input value={form.environment} onChange={(event) => set('environment', event.target.value)} className={inputClass} /></Field><Choices label="所属资产组" options={groupOptions} value={form.groupIds} onChange={(value) => set('groupIds', value)} /></>}
      {modal.kind === 'asset-group' && <Field label="父级资产组"><select value={form.parentId || ''} onChange={(event) => set('parentId', event.target.value)} className={inputClass}><option value="">顶层</option>{groupOptions.filter((option) => option.id !== modal.id).map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</select></Field>}
      {modal.kind === 'account' && <><Field label="目标资产"><select required disabled={!!modal.id} value={form.assetId} onChange={(event) => set('assetId', event.target.value)} className={inputClass}><option value="">选择资产</option>{assetOptions.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</select></Field><Field label="SSH 用户名"><input required value={form.username} onChange={(event) => set('username', event.target.value)} className={inputClass} /></Field><Field label="绑定凭证"><select required value={form.credentialId} onChange={(event) => set('credentialId', event.target.value)} className={inputClass}><option value="">选择凭证</option>{credentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.name} · {credential.type}</option>)}</select></Field><p className="text-sm text-slate-400">显式 @ALL 规则也会覆盖新增账号。</p></>}
      {modal.kind === 'credential' && <Field label="凭证类型"><select value={form.type} onChange={(event) => set('type', event.target.value)} className={inputClass}><option value="password">密码</option><option value="private_key">私钥</option></select></Field>}
      {['credential', 'replace'].includes(modal.kind) && <Field label="新凭证内容">{form.type === 'private_key' || modal.kind === 'replace' ? <textarea autoComplete="off" required rows={6} value={form.secret} onChange={(event) => set('secret', event.target.value)} className={`${inputClass} font-mono`} /> : <input autoComplete="new-password" required type="password" value={form.secret} onChange={(event) => set('secret', event.target.value)} className={inputClass} />}</Field>}
      {modal.kind === 'rule' && <><div className="grid sm:grid-cols-2 gap-4"><Choices label="用户" options={subjects.users.map((user) => ({ id: user.id, label: user.username }))} value={form.userIds} onChange={(value) => set('userIds', value)} /><Choices label="用户组" options={subjects.groups.map((group) => ({ id: group.id, label: group.name }))} value={form.groupIds} onChange={(value) => set('groupIds', value)} /><Choices label="资产" options={assetOptions} value={form.assetIds} onChange={(value) => set('assetIds', value)} /><Choices label="资产组（含子组）" options={groupOptions} value={form.assetGroupIds} onChange={(value) => set('assetGroupIds', value)} /></div><Choices label="允许使用的 SSH 账号" options={accounts.map((account) => ({ id: account.id, label: `${assetName(account.assetId)} / ${account.username}` }))} value={form.accountIds} onChange={(value) => set('accountIds', value)} /><label className="flex gap-2 items-center text-sm"><input type="checkbox" checked={form.allAccounts} onChange={(event) => set('allAccounts', event.target.checked)} />@ALL：全部账号（包括 root 和以后新增的账号）</label><Field label="授权动作"><input readOnly value="connect" className={inputClass} /></Field><div className="grid sm:grid-cols-2 gap-4"><Field label="生效时间（留空表示立即）"><input type="datetime-local" value={form.validFrom} onChange={(event) => set('validFrom', event.target.value)} className={inputClass} /></Field><Field label="失效时间（留空表示长期）"><input type="datetime-local" value={form.validUntil} onChange={(event) => set('validUntil', event.target.value)} className={inputClass} /></Field></div></>}
      {modal.kind === 'user' && <><Field label="显示名称"><input value={form.displayName} onChange={(event) => set('displayName', event.target.value)} className={inputClass} /></Field><Choices label="系统角色" options={roles.map((role) => ({ id: role.name, label: role.name }))} value={form.roles} onChange={(value) => set('roles', value)} /><Choices label="用户组" options={userGroups.map((group) => ({ id: group.name, label: group.name }))} value={form.groups} onChange={(value) => set('groups', value)} /></>}
      {(modal.kind === 'user' && !modal.id || modal.kind === 'password') && <Field label="密码（至少 8 位）"><input type="password" required minLength={8} autoComplete="new-password" value={form.password} onChange={(event) => set('password', event.target.value)} className={inputClass} /></Field>}
      {modal.kind === 'user-group' && <Choices label="组成员" options={users.map((user) => ({ id: user.id, label: user.username }))} value={form.members} onChange={(value) => set('members', value)} />}
      {['asset', 'account', 'rule'].includes(modal.kind) && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.enabled} onChange={(event) => set('enabled', event.target.checked)} />启用</label>}
      <div className="flex justify-end gap-3 pt-2"><button type="button" disabled={saving} onClick={() => { setModal(null); setForm({}); setError(''); }} className={buttonClass}>取消</button><button disabled={saving} className={primaryClass}>{saving ? '保存中…' : '保存'}</button></div>
    </form></div>}

    {hostAsset && <div className="fixed inset-0 z-40 bg-black/70 p-5 flex items-center justify-center"><section className="max-w-3xl w-full max-h-[85vh] overflow-auto rounded-xl border border-slate-600 bg-slate-800 p-6 space-y-5"><div className="flex justify-between"><h2 className="text-xl font-semibold">{hostAsset.name} · Host Key</h2><button onClick={() => setHostAsset(null)}>关闭</button></div>{error && <p role="alert" className="text-red-300">{error}</p>}{!hostKeys.length && <p className="text-slate-400">尚未连接，首次 SSH 握手时自动信任。</p>}{hostKeys.map((key) => <div key={key.id} className="space-y-2 border-t border-slate-700 pt-4"><p>{key.algorithm} · <span className={key.status === 'verified' ? 'text-emerald-400' : 'text-red-300'}>{key.status}</span></p><p className="font-mono text-sm break-all">已记录：{key.fingerprint}</p>{key.candidate_fingerprint && <p className="font-mono text-sm text-amber-300 break-all">新指纹：{key.candidate_fingerprint}</p>}<p className="text-sm text-slate-400">{new Date(key.verified_at ?? key.created_at).toLocaleString()}</p>{key.status !== 'verified' && can('asset.update') && <button className={primaryClass} onClick={async () => { const fingerprint = key.candidate_fingerprint ?? key.fingerprint; if (!confirm(`已通过服务器控制台核实此指纹？\n${fingerprint}`)) return; try { await api.approveHostKey(hostAsset.id, key.algorithm, fingerprint); await showHostKeys(hostAsset); } catch (error) { setError((error as Error).message); } }}>批准此指纹</button>}</div>)}{can('asset.update') && hostKeys.length > 0 && <button className={buttonClass} onClick={async () => { if (!confirm('重置后连接将被阻止，直到管理员批准具体指纹。继续？')) return; try { await api.resetHostKey(hostAsset.id); await showHostKeys(hostAsset); } catch (error) { setError((error as Error).message); } }}>重置为待确认</button>}</section></div>}
  </main>;
}
