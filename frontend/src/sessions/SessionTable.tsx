import React from 'react';
import type { HistoricalSessionSummary, OnlineSessionSummary } from '../../../src/shared/types';

export function duration(start: number, end: number = Date.now()) {
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  return `${Math.floor(seconds / 3600)}:${String(Math.floor(seconds / 60) % 60).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

export function SessionTable({ sessions, historical = false, actions }: {
  sessions: (OnlineSessionSummary | HistoricalSessionSummary)[]; historical?: boolean;
  actions?: (session: HistoricalSessionSummary) => React.ReactNode;
}) {
  if (!sessions.length) return <p className="p-12 text-center text-slate-400">暂无会话</p>;
  return <div className="overflow-x-auto"><table className="w-full text-sm text-left whitespace-nowrap">
    <thead className="text-slate-400 bg-slate-950/50"><tr>{['用户', '资产 / 账号', '来源 IP', '开始时间', ...(historical ? ['结束时间'] : []), '时长', '状态', '操作'].map((title) => <th key={title} className="p-3 font-medium">{title}</th>)}</tr></thead>
    <tbody className="divide-y divide-slate-700">{sessions.map((item) => {
      const session = item as HistoricalSessionSummary;
      return <tr key={session.id} className="hover:bg-slate-700/25">
        <td className="p-3">{session.username}</td><td className="p-3"><span className="text-blue-300">{session.assetName}</span><span className="block text-slate-400 font-mono text-xs mt-1">{session.accountName}</span></td>
        <td className="p-3 font-mono text-slate-400">{session.sourceIp}</td><td className="p-3 text-slate-400">{new Date(session.startedAt).toLocaleString()}</td>
        {historical && <td className="p-3 text-slate-400">{session.endedAt ? new Date(session.endedAt).toLocaleString() : '—'}</td>}
        <td className="p-3 font-mono">{duration(session.startedAt, session.endedAt ?? Date.now())}</td><td className="p-3"><span className={session.status === 'active' ? 'text-emerald-400' : 'text-slate-400'}>{session.status}</span>{session.exitCode != null && <span className="block text-xs text-slate-400">退出码 {session.exitCode}</span>}</td>
        <td className="p-3"><div className="flex gap-3">{actions?.(session)}</div></td>
      </tr>;
    })}</tbody>
  </table></div>;
}
