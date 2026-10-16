import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Server, Terminal, Shield, RefreshCw, Star, ChevronRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { AssetTree } from '../assets/AssetTree';
import type { AuthorizedAsset, AuthorizedAssetAccount, HistoricalSessionSummary } from '../../../src/shared/types';

interface DashboardProps {
  onOpenTerminal: (sessionData: { sessionId: string; ticket: string; assetName: string; accountName: string }) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onOpenTerminal }) => {
  const { user, hasPermission } = useAuth();
  const administrator = user?.roles.some((role) => ['role_super_admin', 'role_asset_admin'].includes(role));
  const [assets, setAssets] = useState<AuthorizedAsset[]>([]);
  const [sessions, setSessions] = useState<HistoricalSessionSummary[]>([]);
  const [group, setGroup] = useState<string | null>(null);
  const [favorites, setFavorites] = useState<string[]>(() => { try { return JSON.parse(localStorage.getItem(`edgejump:favorites:${user?.id}`) ?? '[]'); } catch { return []; } });
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedAsset, setSelectedAsset] = useState<AuthorizedAsset | null>(null);
  const [selectedAccount, setSelectedAccount] = useState<AuthorizedAssetAccount | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const data = await api.getVisibleAssets();
      setAssets(data);
      if (hasPermission('session.view_own')) setSessions(await api.listMySessions());
      setError(null);
    } catch (err: any) {
      setError(err.message || '获取资产失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const groups = [...new Map(assets.flatMap((asset) => asset.groups ?? []).map((group) => [group.id, group])).values()];
  const shown = assets.filter((asset) => (!group || asset.groups?.some((item) => item.id === group)) && (!favoritesOnly || favorites.includes(asset.id)));
  function favorite(id: string) {
    const next = favorites.includes(id) ? favorites.filter((item) => item !== id) : [...favorites, id];
    setFavorites(next); localStorage.setItem(`edgejump:favorites:${user?.id}`, JSON.stringify(next));
  }

  const handleStartConnect = async () => {
    if (!selectedAsset || !selectedAccount) return;
    setConnecting(true);
    setError(null);

    try {
      const session = await api.createSession(selectedAsset.id, selectedAccount.id);
      onOpenTerminal({
        sessionId: session.sessionId,
        ticket: session.ticket,
        assetName: selectedAsset.name,
        accountName: selectedAccount.username,
      });
    } catch (err: any) {
      setError(err.message || '创建会话失败');
    } finally {
      setConnecting(false);
    }
  };

  return (
    <div className="flex-1 overflow-auto p-6 bg-slate-900">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center space-x-2">
              <Server className="w-5 h-5 text-blue-400" />
              <span>已授权主机资产</span>
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              选择主机与 SSH 账号，开始终端会话。
            </p>
          </div>

          <button
            onClick={fetchAssets}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>刷新</span>
          </button>
        </div>

        {error && (
          <div className="mb-4 bg-red-950/60 border border-red-800 text-red-300 px-4 py-2.5 rounded-lg text-sm">
            {error}
          </div>
        )}

        {loading ? (
          <div className="text-center py-20 text-slate-500">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-2 text-slate-400" />
            <p className="text-sm">正在检索授权资产...</p>
          </div>
        ) : assets.length === 0 ? (
          <div className="bg-slate-800/50 border border-slate-700/60 rounded-xl p-12 text-center">
            <Shield className="w-12 h-12 text-slate-500 mx-auto mb-3" />
            <h3 className="text-base font-medium text-slate-300">暂无可访问资产</h3>
            <p className="text-slate-500 text-sm mt-1 max-w-sm mx-auto">
              {administrator ? '请在堡垒机管理中添加机器与 SSH 账号，保存后即可连接。' : '您目前尚未被授予任何资产的 SSH 登录权限。请联系管理员在堡垒机后台配置授权规则。'}
            </p>
          </div>
        ) : (
          <div className="grid md:grid-cols-[220px_1fr] gap-5">
            <aside className="bg-slate-800 rounded-xl p-5 self-start"><AssetTree groups={groups} assets={assets} selected={group} onGroup={setGroup} onAsset={(id) => { const asset = assets.find((asset) => asset.id === id)!; setSelectedAsset(asset); setSelectedAccount(asset.accounts[0]); }} /><button onClick={() => setFavoritesOnly(!favoritesOnly)} className={`mt-5 text-sm py-2 px-3 rounded-lg ${favoritesOnly ? 'bg-amber-600' : 'bg-slate-700'}`}>收藏资产</button></aside>
            <div className="grid md:grid-cols-2 gap-4">
            {!shown.length && <p className="p-8 text-slate-400 text-sm">暂无符合条件的资产</p>}
            {shown.map((asset) => (
              <div
                key={asset.id}
                className="bg-slate-800 border border-slate-700 rounded-xl p-5 hover:border-blue-500/60 transition shadow-sm flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-semibold text-white text-base">{asset.name}</h3>
                      <p className="text-xs font-mono text-slate-400 mt-0.5">
                        {asset.hostname}:{asset.port}
                      </p>
                    </div>
                    <span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded font-mono">
                      {asset.platform}
                    </span>
                    <button aria-label={`${favorites.includes(asset.id) ? '取消收藏' : '收藏'} ${asset.name}`} onClick={() => favorite(asset.id)} className="p-1 text-amber-400"><Star size={18} fill={favorites.includes(asset.id) ? 'currentColor' : 'none'} /></button>
                  </div>

                  {asset.description && (
                    <p className="text-xs text-slate-400 mt-2 line-clamp-2">{asset.description}</p>
                  )}

                  <div className="mt-4 pt-3 border-t border-slate-700/60">
                    <span className="text-xs text-slate-400 font-medium">可用 SSH 账号：</span>
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      {!asset.accounts.length && <span className="text-sm text-slate-400">尚未配置 SSH 账号</span>}
                      {asset.accounts?.map((acc: any) => (
                        <span
                          key={acc.id}
                          className="text-xs bg-slate-900 text-blue-400 px-2 py-0.5 rounded border border-slate-700 font-mono"
                        >
                          {acc.username}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <button
                  disabled={!asset.accounts.length}
                  onClick={() => {
                    setSelectedAsset(asset);
                    setSelectedAccount(asset.accounts?.[0] || null);
                  }}
                  className="mt-5 w-full flex items-center justify-center space-x-2 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Terminal className="w-4 h-4" />
                  <span>打开 Web Terminal</span>
                </button>
              </div>
            ))}
            </div>
          </div>
        )}

        {hasPermission('session.view_own') && <div className="mt-6 grid md:grid-cols-2 gap-5">{['在线会话', '最近会话'].map((title) => {
          const rows = title === '在线会话' ? sessions.filter((session) => ['creating', 'connecting', 'active'].includes(session.status)) : sessions.slice(0, 5);
          return <section key={title} className="bg-slate-800 rounded-xl p-5"><h2 className="font-medium mb-4">{title}</h2><div className="space-y-3">{rows.map((session) => <div key={session.id} className="flex justify-between gap-3 text-sm"><div>{session.assetName} / {session.accountName}<p className="text-slate-400 text-xs mt-1">{new Date(session.startedAt).toLocaleString()} · {session.status}</p></div>{['connecting', 'active'].includes(session.status) && <button onClick={async () => { try { onOpenTerminal({ ...await api.resumeSession(session.id), assetName: session.assetName, accountName: session.accountName }); } catch (error) { setError((error as Error).message); } }} className="text-blue-300">恢复终端</button>}</div>)}{!rows.length && <p className="text-sm text-slate-400">暂无记录</p>}</div></section>;
        })}</div>}

        {/* Connect Modal */}
        {selectedAsset && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
            <div className="bg-slate-800 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl">
              <h3 className="text-lg font-bold text-white mb-1">连接到 {selectedAsset.name}</h3>
              <p className="text-xs text-slate-400 mb-4">
                目标地址: {selectedAsset.hostname}:{selectedAsset.port}
              </p>

              <div className="space-y-3 mb-6">
                <label className="block text-xs font-semibold text-slate-300 uppercase">选择登录账号</label>
                <div className="space-y-2">
                  {selectedAsset.accounts?.map((acc: any) => (
                    <label
                      key={acc.id}
                      className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer transition ${
                        selectedAccount?.id === acc.id
                          ? 'bg-blue-900/30 border-blue-500 text-white'
                          : 'bg-slate-900/50 border-slate-700 text-slate-300 hover:bg-slate-700/50'
                      }`}
                    >
                      <div className="flex items-center space-x-3">
                        <input
                          type="radio"
                          name="account"
                          checked={selectedAccount?.id === acc.id}
                          onChange={() => setSelectedAccount(acc)}
                          className="text-blue-600 focus:ring-0"
                        />
                        <span className="font-mono text-sm">{acc.username}</span>
                      </div>
                      <span className="text-xs text-slate-400 font-mono bg-slate-800 px-2 py-0.5 rounded">
                        {acc.credentialType === 'private_key' ? '私钥托管' : '密码托管'}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-end space-x-3">
                <button
                  onClick={() => setSelectedAsset(null)}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm rounded-lg transition"
                >
                  取消
                </button>
                <button
                  disabled={connecting || !selectedAccount}
                  onClick={handleStartConnect}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition flex items-center space-x-2 disabled:opacity-50"
                >
                  {connecting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>正在申请会话...</span>
                    </>
                  ) : (
                    <>
                      <span>启动终端</span>
                      <ChevronRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
