import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Server, FolderTree, Key, ShieldCheck, Plus, Trash2, Edit2, RefreshCw, Check } from 'lucide-react';

export const Admin: React.FC = () => {
  const [tab, setTab] = useState<'assets' | 'groups' | 'credentials' | 'authorizations' | 'users'>('assets');
  const [assets, setAssets] = useState<any[]>([]);
  const [groups, setGroups] = useState<any[]>([]);
  const [credentials, setCredentials] = useState<any[]>([]);
  const [authorizations, setAuthorizations] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  // Forms state
  const [showAssetModal, setShowAssetModal] = useState(false);
  const [assetForm, setAssetForm] = useState({ name: '', hostname: '', port: 22, platform: 'linux', description: '' });

  const [showCredModal, setShowCredModal] = useState(false);
  const [credForm, setCredForm] = useState({ name: '', type: 'password', secret: '' });

  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authForm, setAuthForm] = useState({ name: '', description: '', allAccounts: true, assetIds: [] as string[] });

  const [showUserModal, setShowUserModal] = useState(false);
  const [userForm, setUserForm] = useState({ username: '', password: '', displayName: '', role: 'User' });

  const loadData = async () => {
    setLoading(true);
    try {
      if (tab === 'assets') {
        const [a, g] = await Promise.all([api.listAdminAssets(), api.listAssetGroups()]);
        setAssets(a);
        setGroups(g);
      } else if (tab === 'groups') {
        setGroups(await api.listAssetGroups());
      } else if (tab === 'credentials') {
        setCredentials(await api.listCredentials());
      } else if (tab === 'authorizations') {
        const [rules, a] = await Promise.all([api.listAuthorizations(), api.listAdminAssets()]);
        setAuthorizations(rules);
        setAssets(a);
      } else if (tab === 'users') {
        setUsers(await api.listUsers());
      }
    } catch (err: any) {
      setMessage(`加载错误: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [tab]);

  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createAsset(assetForm);
      setShowAssetModal(false);
      setAssetForm({ name: '', hostname: '', port: 22, platform: 'linux', description: '' });
      loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleCreateCred = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createCredential(credForm);
      setShowCredModal(false);
      setCredForm({ name: '', type: 'password', secret: '' });
      loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleCreateAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createAuthorization(authForm);
      setShowAuthModal(false);
      setAuthForm({ name: '', description: '', allAccounts: true, assetIds: [] });
      loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  return (
    <div className="flex-1 overflow-auto p-6 bg-slate-900">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-bold text-white flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            <span>堡垒机核心配置与权限管理</span>
          </h1>

          <div className="flex items-center space-x-1 bg-slate-800 p-1 rounded-lg border border-slate-700">
            <button
              onClick={() => setTab('assets')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                tab === 'assets' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              资产清单
            </button>
            <button
              onClick={() => setTab('credentials')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                tab === 'credentials' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              凭证托管库 (信封加密)
            </button>
            <button
              onClick={() => setTab('authorizations')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                tab === 'authorizations' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              授权规则 (JumpServer模型)
            </button>
            <button
              onClick={() => setTab('users')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                tab === 'users' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              用户与RBAC角色
            </button>
          </div>
        </div>

        {tab === 'assets' && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-700 flex items-center justify-between">
              <span className="text-sm font-semibold text-white">主机资产列表</span>
              <button
                onClick={() => setShowAssetModal(true)}
                className="flex items-center space-x-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>新建主机</span>
              </button>
            </div>

            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-700">
                <tr>
                  <th className="px-4 py-3">名称</th>
                  <th className="px-4 py-3">IP / 端口</th>
                  <th className="px-4 py-3">平台</th>
                  <th className="px-4 py-3">Host Key 策略</th>
                  <th className="px-4 py-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/60 font-mono">
                {assets.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-700/30">
                    <td className="px-4 py-3 font-sans font-medium text-white">{a.name}</td>
                    <td className="px-4 py-3 text-slate-300">{a.hostname}:{a.port}</td>
                    <td className="px-4 py-3">{a.platform}</td>
                    <td className="px-4 py-3 text-emerald-400">TOFU 首次自动信任</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={async () => {
                          if (confirm('确认删除此资产？')) {
                            await api.deleteAsset(a.id);
                            loadData();
                          }
                        }}
                        className="text-red-400 hover:text-red-300"
                      >
                        <Trash2 className="w-3.5 h-3.5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'credentials' && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-700 flex items-center justify-between">
              <div>
                <span className="text-sm font-semibold text-white">凭据保险箱</span>
                <p className="text-xs text-slate-400 mt-0.5">
                  所有密码与私钥通过 AES-256-GCM 信封加密托管于 D1，遵循 Write-Only / Replace-Only 原则，永不回传明文。
                </p>
              </div>
              <button
                onClick={() => setShowCredModal(true)}
                className="flex items-center space-x-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>录入新凭证</span>
              </button>
            </div>

            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-700">
                <tr>
                  <th className="px-4 py-3">凭证名称</th>
                  <th className="px-4 py-3">类型</th>
                  <th className="px-4 py-3">主密钥版本</th>
                  <th className="px-4 py-3">安全保护状态</th>
                  <th className="px-4 py-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/60 font-mono">
                {credentials.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-700/30">
                    <td className="px-4 py-3 font-sans font-medium text-white">{c.name}</td>
                    <td className="px-4 py-3">{c.type === 'private_key' ? '私钥 (Ed25519/RSA/ECDSA)' : '密码'}</td>
                    <td className="px-4 py-3 text-blue-400">{c.keyVersion || 'v1'}</td>
                    <td className="px-4 py-3 text-emerald-400">已信封加密 (Write-Only)</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={async () => {
                          if (confirm('确认删除此凭据？')) {
                            await api.deleteCredential(c.id);
                            loadData();
                          }
                        }}
                        className="text-red-400 hover:text-red-300"
                      >
                        <Trash2 className="w-3.5 h-3.5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'authorizations' && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-700 flex items-center justify-between">
              <div>
                <span className="text-sm font-semibold text-white">JumpServer 资产访问授权规则</span>
                <p className="text-xs text-slate-400 mt-0.5">
                  基于经典模型：主体 (Subject) × 资产/节点 (Target) × 账号 (@ALL 或具体账号) × 动作 (connect) × 有效期。
                </p>
              </div>
              <button
                onClick={() => setShowAuthModal(true)}
                className="flex items-center space-x-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>新建授权规则</span>
              </button>
            </div>

            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-700">
                <tr>
                  <th className="px-4 py-3">规则名称</th>
                  <th className="px-4 py-3">账号范围</th>
                  <th className="px-4 py-3">关联资产数</th>
                  <th className="px-4 py-3">状态</th>
                  <th className="px-4 py-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/60">
                {authorizations.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-700/30">
                    <td className="px-4 py-3 font-medium text-white">{r.name}</td>
                    <td className="px-4 py-3 font-mono text-blue-400">{r.allAccounts ? '@ALL (全部账号)' : '指定账号'}</td>
                    <td className="px-4 py-3">{r.assetIds?.length || 0} 台主机</td>
                    <td className="px-4 py-3">
                      <span className="text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 rounded text-xs">
                        已生效
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={async () => {
                          if (confirm('确认删除此规则？')) {
                            await api.deleteAuthorization(r.id);
                            loadData();
                          }
                        }}
                        className="text-red-400 hover:text-red-300"
                      >
                        <Trash2 className="w-3.5 h-3.5 inline" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Modal: New Asset */}
        {showAssetModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <form onSubmit={handleCreateAsset} className="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
              <h3 className="text-lg font-bold text-white">添加主机资产</h3>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">主机名 / 标识</label>
                <input
                  type="text"
                  required
                  placeholder="prod-web-01"
                  value={assetForm.name}
                  onChange={(e) => setAssetForm({ ...assetForm, name: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="grid grid-cols-3 gap-2">
                <div className="col-span-2">
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">公网 IP 或公网域名</label>
                  <input
                    type="text"
                    required
                    placeholder="203.0.113.10"
                    value={assetForm.hostname}
                    onChange={(e) => setAssetForm({ ...assetForm, hostname: e.target.value })}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">端口</label>
                  <input
                    type="number"
                    required
                    value={assetForm.port}
                    onChange={(e) => setAssetForm({ ...assetForm, port: Number(e.target.value) })}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
              </div>
              <div className="flex items-center justify-end space-x-2 pt-2">
                <button type="button" onClick={() => setShowAssetModal(false)} className="px-4 py-2 bg-slate-700 text-slate-300 text-xs rounded-lg">取消</button>
                <button type="submit" className="px-4 py-2 bg-blue-600 text-white text-xs font-medium rounded-lg">创建资产</button>
              </div>
            </form>
          </div>
        )}

        {/* Modal: New Credential */}
        {showCredModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <form onSubmit={handleCreateCred} className="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
              <h3 className="text-lg font-bold text-white">托管 SSH 凭证 (信封加密)</h3>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">凭证名称</label>
                <input
                  type="text"
                  required
                  placeholder="prod-deploy-key"
                  value={credForm.name}
                  onChange={(e) => setCredForm({ ...credForm, name: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">凭证类型</label>
                <select
                  value={credForm.type}
                  onChange={(e) => setCredForm({ ...credForm, type: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="password">密码 (Password)</option>
                  <option value="private_key">私钥 (Private Key PEM)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
                  {credForm.type === 'private_key' ? '私钥内容 (OpenSSH / RSA / Ed25519 PEM)' : '密码明文'}
                </label>
                <textarea
                  required
                  rows={4}
                  placeholder={credForm.type === 'private_key' ? '-----BEGIN OPENSSH PRIVATE KEY-----\n...' : '输入服务器登录密码'}
                  value={credForm.secret}
                  onChange={(e) => setCredForm({ ...credForm, secret: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>
              <div className="flex items-center justify-end space-x-2 pt-2">
                <button type="button" onClick={() => setShowCredModal(false)} className="px-4 py-2 bg-slate-700 text-slate-300 text-xs rounded-lg">取消</button>
                <button type="submit" className="px-4 py-2 bg-blue-600 text-white text-xs font-medium rounded-lg">加密并保存</button>
              </div>
            </form>
          </div>
        )}

        {/* Modal: New Authorization */}
        {showAuthModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <form onSubmit={handleCreateAuth} className="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
              <h3 className="text-lg font-bold text-white">新建授权规则</h3>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">规则名称</label>
                <input
                  type="text"
                  required
                  placeholder="Developers-Access"
                  value={authForm.name}
                  onChange={(e) => setAuthForm({ ...authForm, name: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="allAccounts"
                  checked={authForm.allAccounts}
                  onChange={(e) => setAuthForm({ ...authForm, allAccounts: e.target.checked })}
                  className="text-blue-600 focus:ring-0"
                />
                <label htmlFor="allAccounts" className="text-xs text-slate-300">
                  授予资产绑定的全部 SSH 账号 (@ALL 方案A)
                </label>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">选择授权主机</label>
                <select
                  multiple
                  value={authForm.assetIds}
                  onChange={(e) => {
                    const selected = Array.from(e.target.selectedOptions, (opt) => opt.value);
                    setAuthForm({ ...authForm, assetIds: selected });
                  }}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-blue-500 h-28"
                >
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.hostname})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center justify-end space-x-2 pt-2">
                <button type="button" onClick={() => setShowAuthModal(false)} className="px-4 py-2 bg-slate-700 text-slate-300 text-xs rounded-lg">取消</button>
                <button type="submit" className="px-4 py-2 bg-blue-600 text-white text-xs font-medium rounded-lg">保存授权</button>
              </div>
            </form>
          </div>
        )}

        {tab === 'users' && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-700 flex items-center justify-between">
              <span className="text-sm font-semibold text-white">系统用户与角色列表</span>
              <button
                onClick={() => setShowUserModal(true)}
                className="flex items-center space-x-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>新建用户</span>
              </button>
            </div>

            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-700">
                <tr>
                  <th className="px-4 py-3">用户名</th>
                  <th className="px-4 py-3">显示名称</th>
                  <th className="px-4 py-3">角色权限</th>
                  <th className="px-4 py-3">状态</th>
                  <th className="px-4 py-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/60">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-700/30">
                    <td className="px-4 py-3 font-mono font-medium text-white">{u.username}</td>
                    <td className="px-4 py-3">{u.displayName}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {u.roles.map((r: string) => (
                          <span key={r} className="px-2 py-0.5 bg-blue-900/50 text-blue-300 rounded text-[10px] border border-blue-700/50">
                            {r}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                        u.status === 'active' ? 'bg-emerald-900/50 text-emerald-300 border border-emerald-700/50' : 'bg-red-900/50 text-red-300 border border-red-700/50'
                      }`}>
                        {u.status === 'active' ? '启用中' : '已禁用'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      {u.status === 'active' ? (
                        <button
                          onClick={async () => {
                            if (confirm(`确认禁用用户 ${u.username}？将立即断开其登录及在线SSH会话。`)) {
                              await api.disableUser(u.id);
                              loadData();
                            }
                          }}
                          className="px-2 py-1 bg-red-600/20 text-red-400 hover:bg-red-600/30 rounded text-[11px] transition"
                        >
                          禁用
                        </button>
                      ) : (
                        <button
                          onClick={async () => {
                            await api.enableUser(u.id);
                            loadData();
                          }}
                          className="px-2 py-1 bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600/30 rounded text-[11px] transition"
                        >
                          启用
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {showUserModal && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
            <form onSubmit={async (e) => {
              e.preventDefault();
              try {
                await api.createUser({
                  username: userForm.username,
                  password: userForm.password,
                  displayName: userForm.displayName,
                  roles: [userForm.role],
                });
                setShowUserModal(false);
                setUserForm({ username: '', password: '', displayName: '', role: 'User' });
                loadData();
              } catch (err: any) {
                alert(err.message);
              }
            }} className="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
              <h3 className="text-base font-bold text-white">新建系统用户</h3>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">用户名</label>
                <input
                  type="text"
                  required
                  placeholder="alice"
                  value={userForm.username}
                  onChange={(e) => setUserForm({ ...userForm, username: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">初始密码 (至少8位)</label>
                <input
                  type="password"
                  required
                  minLength={8}
                  placeholder="••••••••"
                  value={userForm.password}
                  onChange={(e) => setUserForm({ ...userForm, password: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">显示名称</label>
                <input
                  type="text"
                  placeholder="Alice Developer"
                  value={userForm.displayName}
                  onChange={(e) => setUserForm({ ...userForm, displayName: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">系统角色 (RBAC)</label>
                <select
                  value={userForm.role}
                  onChange={(e) => setUserForm({ ...userForm, role: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="User">普通用户 (User)</option>
                  <option value="Asset Admin">资产管理员 (Asset Admin)</option>
                  <option value="Security Auditor">安全审计员 (Security Auditor)</option>
                  <option value="Super Admin">超级管理员 (Super Admin)</option>
                </select>
              </div>
              <div className="flex items-center justify-end space-x-2 pt-2">
                <button type="button" onClick={() => setShowUserModal(false)} className="px-4 py-2 bg-slate-700 text-slate-300 text-xs rounded-lg">取消</button>
                <button type="submit" className="px-4 py-2 bg-blue-600 text-white text-xs font-medium rounded-lg">创建用户</button>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};
