import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Clock, Eye, AlertOctagon, ShieldAlert, RefreshCw, FileText } from 'lucide-react';

interface AuditProps {
  onOpenMonitor: (session: { sessionId: string; assetName: string; accountName: string }) => void;
}

export const Audit: React.FC<AuditProps> = ({ onOpenMonitor }) => {
  const [tab, setTab] = useState<'online' | 'historical' | 'events'>('online');
  const [onlineSessions, setOnlineSessions] = useState<any[]>([]);
  const [historicalSessions, setHistoricalSessions] = useState<any[]>([]);
  const [auditEvents, setAuditEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      if (tab === 'online') {
        setOnlineSessions(await api.listOnlineSessions());
      } else if (tab === 'historical') {
        setHistoricalSessions(await api.listHistoricalSessions());
      } else if (tab === 'events') {
        setAuditEvents(await api.listAuditEvents(100));
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [tab]);

  const handleTerminate = async (sessionId: string) => {
    if (confirm('确认强制终止此在线会话？断开后将立即切断连接并记录审计事件。')) {
      await api.terminateSession(sessionId);
      loadData();
    }
  };

  return (
    <div className="flex-1 overflow-auto p-6 bg-slate-900">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-bold text-white flex items-center space-x-2">
            <Clock className="w-5 h-5 text-blue-400" />
            <span>安全审计与会话监控中心</span>
          </h1>

          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-1 bg-slate-800 p-1 rounded-lg border border-slate-700">
              <button
                onClick={() => setTab('online')}
                className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                  tab === 'online' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                在线会话 ({onlineSessions.length})
              </button>
              <button
                onClick={() => setTab('historical')}
                className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                  tab === 'historical' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                历史审计与回放
              </button>
              <button
                onClick={() => setTab('events')}
                className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                  tab === 'events' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                行为审计日志
              </button>
            </div>

            <button
              onClick={loadData}
              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {tab === 'online' && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-700">
              <span className="text-sm font-semibold text-white">当前活动中的 SSH 终端会话</span>
            </div>

            {onlineSessions.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">暂无在线会话</div>
            ) : (
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-700">
                  <tr>
                    <th className="px-4 py-3">用户</th>
                    <th className="px-4 py-3">目标资产</th>
                    <th className="px-4 py-3">登录账号</th>
                    <th className="px-4 py-3">来源 IP</th>
                    <th className="px-4 py-3">开始时间</th>
                    <th className="px-4 py-3">状态</th>
                    <th className="px-4 py-3 text-right">管理控制</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/60 font-mono">
                  {onlineSessions.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-700/30">
                      <td className="px-4 py-3 font-sans font-medium text-white">{s.username}</td>
                      <td className="px-4 py-3 font-sans text-blue-400">{s.assetName}</td>
                      <td className="px-4 py-3">{s.accountName}</td>
                      <td className="px-4 py-3 text-slate-400">{s.sourceIp}</td>
                      <td className="px-4 py-3 text-slate-400">{new Date(s.startedAt).toLocaleTimeString()}</td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center space-x-1 text-emerald-400">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                          <span>{s.status}</span>
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right space-x-2">
                        <button
                          onClick={() =>
                            onOpenMonitor({
                              sessionId: s.id,
                              assetName: s.assetName,
                              accountName: s.accountName,
                            })
                          }
                          className="inline-flex items-center space-x-1 px-2.5 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded font-sans text-xs"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>旁路监视</span>
                        </button>
                        <button
                          onClick={() => handleTerminate(s.id)}
                          className="inline-flex items-center space-x-1 px-2.5 py-1 bg-red-950 hover:bg-red-900 border border-red-800 text-red-300 rounded font-sans text-xs"
                        >
                          <AlertOctagon className="w-3.5 h-3.5" />
                          <span>强制切断</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'historical' && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-700">
              <span className="text-sm font-semibold text-white">历史已结束会话</span>
            </div>

            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-700">
                <tr>
                  <th className="px-4 py-3">用户</th>
                  <th className="px-4 py-3">目标资产</th>
                  <th className="px-4 py-3">账号</th>
                  <th className="px-4 py-3">开始时间</th>
                  <th className="px-4 py-3">状态</th>
                  <th className="px-4 py-3">防篡改哈希 (SHA-256)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/60 font-mono">
                {historicalSessions.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-700/30">
                    <td className="px-4 py-3 font-sans font-medium text-white">{s.username}</td>
                    <td className="px-4 py-3 font-sans text-blue-400">{s.assetName}</td>
                    <td className="px-4 py-3">{s.accountName}</td>
                    <td className="px-4 py-3 text-slate-400">{new Date(s.startedAt).toLocaleString()}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        s.status === 'closed' ? 'bg-slate-700 text-slate-300' : 'bg-red-950 text-red-400'
                      }`}>
                        {s.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 truncate max-w-xs" title={s.recordingHash}>
                      {s.recordingHash ? s.recordingHash.substring(0, 16) + '...' : '未录像'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'events' && (
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-700">
              <span className="text-sm font-semibold text-white">安全审计事件流 (不可篡改)</span>
            </div>

            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-700">
                <tr>
                  <th className="px-4 py-3">时间</th>
                  <th className="px-4 py-3">操作主体</th>
                  <th className="px-4 py-3">动作</th>
                  <th className="px-4 py-3">资源</th>
                  <th className="px-4 py-3">来源 IP</th>
                  <th className="px-4 py-3">结果</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/60 font-mono">
                {auditEvents.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-700/30">
                    <td className="px-4 py-3 text-slate-400">{new Date(e.timestamp).toLocaleTimeString()}</td>
                    <td className="px-4 py-3 font-sans font-medium text-white">{e.actorUsername || 'system'}</td>
                    <td className="px-4 py-3 text-blue-400">{e.action}</td>
                    <td className="px-4 py-3 text-slate-300 font-sans">{e.resourceName || e.resourceType}</td>
                    <td className="px-4 py-3 text-slate-400">{e.sourceIp}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        e.result === 'success' ? 'text-emerald-400' : 'text-red-400'
                      }`}>
                        {e.result}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
