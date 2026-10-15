import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { SessionTable } from '../sessions/SessionTable';
import { Replay } from '../audit/Replay';
import type { HistoricalSessionSummary, OnlineSessionSummary, AuditEventSummary } from '../../../src/shared/types';

export function Audit({ onOpenMonitor }: { onOpenMonitor: (session: { sessionId: string; assetName: string; accountName: string }) => void }) {
  const { hasPermission } = useAuth();
  const [tab, setTab] = useState(hasPermission('session.view_all') ? 'online' : 'events');
  const [online, setOnline] = useState<OnlineSessionSummary[]>([]);
  const [history, setHistory] = useState<HistoricalSessionSummary[]>([]);
  const [events, setEvents] = useState<AuditEventSummary[]>([]);
  const [replayId, setReplayId] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ title: string; commands?: { id: string; command: string; timestamp: number; source: string }[]; events?: AuditEventSummary[] } | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  async function load() {
    setLoading(true);
    try {
      if (tab === 'online') setOnline(await api.listOnlineSessions());
      if (tab === 'historical') setHistory(await api.listHistoricalSessions());
      if (tab === 'events') setEvents(await api.listAuditEvents(100));
      setError('');
    } catch (error) { setError((error as Error).message); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); const timer = setInterval(load, 5000); return () => clearInterval(timer); }, [tab]);
  async function terminate(id: string) {
    if (!confirm('确认终止该在线会话？')) return;
    try { await api.terminateSession(id); await load(); } catch (error) { setError((error as Error).message); }
  }
  async function showDetail(session: HistoricalSessionSummary, commands: boolean) {
    try {
      setDetail(commands ? { title: `${session.assetName} · 命令记录（启发式）`, commands: await api.getSessionCommands(session.id) }
        : { title: `${session.assetName} · 会话事件`, events: await api.listAuditEvents(200, session.id) });
    } catch (error) { setError((error as Error).message); }
  }

  const renderEvents = (items: AuditEventSummary[]) => <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-slate-950/40 text-slate-400"><tr>{['时间', '操作人', '动作', '资源', '来源 IP', '结果'].map((title) => <th key={title} className="p-3 font-medium">{title}</th>)}</tr></thead><tbody className="divide-y divide-slate-700">{items.map((event) => <tr key={event.id}><td className="p-3 text-slate-400 whitespace-nowrap">{new Date(event.timestamp).toLocaleString()}</td><td className="p-3">{event.actorUsername}</td><td className="p-3 text-blue-300 font-mono text-xs">{event.action}</td><td className="p-3">{event.resourceName || event.resourceType}</td><td className="p-3 font-mono">{event.sourceIp}</td><td className="p-3">{event.result}</td></tr>)}</tbody></table>{!items.length && <p className="p-10 text-slate-400 text-center">暂无审计事件</p>}</div>;

  return <main className="max-w-7xl mx-auto w-full p-6 space-y-5">
    <div className="flex flex-wrap gap-4 items-center justify-between"><h1 className="text-xl font-semibold">会话与审计</h1><button onClick={load} disabled={loading} className="text-blue-400">{loading ? '刷新中…' : '刷新'}</button></div>
    <nav className="flex gap-2 text-sm">{[['online', '在线会话'], ['historical', '历史会话'], ['events', '审计日志']].filter(([key]) => key === 'events' ? hasPermission('audit.read') : hasPermission('session.view_all')).map(([key, label]) => <button key={key} onClick={() => setTab(key)} className={`px-4 py-2 rounded-lg ${tab === key ? 'bg-blue-600' : 'bg-slate-800'}`}>{label}</button>)}</nav>
    {error && <p role="alert" className="text-red-300">{error}</p>}
    <section className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
      {tab === 'online' && <SessionTable sessions={online} actions={(session) => <>
        {hasPermission('session.monitor') && <button onClick={() => onOpenMonitor({ sessionId: session.id, assetName: session.assetName, accountName: session.accountName })} className="text-blue-300">监控</button>}
        {hasPermission('session.terminate') && <button onClick={() => terminate(session.id)} className="text-red-300">终止</button>}
      </>} />}
      {tab === 'historical' && <SessionTable sessions={history} historical actions={(session) => <>
        {session.recordingStatus === 'completed' && <button onClick={() => setReplayId(session.id)} className="text-blue-300">回放</button>}
        <button onClick={() => showDetail(session, true)} className="text-blue-300">命令</button>
        {hasPermission('audit.read') && <button onClick={() => showDetail(session, false)} className="text-blue-300">事件</button>}
      </>} />}
      {tab === 'events' && renderEvents(events)}
    </section>
    {replayId && <Replay sessionId={replayId} onClose={() => setReplayId(null)} />}
    {detail && <div className="fixed inset-0 bg-black/70 z-40 p-6 flex items-center justify-center"><section className="w-full max-w-6xl max-h-[85vh] overflow-auto rounded-xl bg-slate-800 border border-slate-700 p-5"><div className="flex justify-between mb-4"><h2 className="font-semibold">{detail.title}</h2><button onClick={() => setDetail(null)}>关闭</button></div>{detail.events && renderEvents(detail.events)}{detail.commands && <><p className="text-sm text-slate-400 mb-4">命令由终端输入推测；以会话录像为准。</p><ul className="space-y-3 font-mono text-sm">{detail.commands.map((command) => <li key={command.id}><time className="text-slate-400 mr-4">{new Date(command.timestamp).toLocaleTimeString()}</time>{command.command}</li>)}</ul>{!detail.commands.length && <p>暂无命令记录</p>}</>}</section></div>}
  </main>;
}
