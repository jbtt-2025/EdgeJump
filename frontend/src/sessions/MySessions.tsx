import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { HistoricalSessionSummary } from '../../../src/shared/types';
import { SessionTable } from './SessionTable';

export function MySessions({ onOpenTerminal }: { onOpenTerminal: (session: { sessionId: string; ticket: string; assetName: string; accountName: string }) => void }) {
  const [sessions, setSessions] = useState<HistoricalSessionSummary[]>([]);
  const [error, setError] = useState('');
  const load = async () => { try { setSessions(await api.listMySessions()); setError(''); } catch (error) { setError((error as Error).message); } };
  useEffect(() => { void load(); const interval = setInterval(load, 5000); return () => clearInterval(interval); }, []);
  async function resume(session: HistoricalSessionSummary) {
    try { onOpenTerminal({ ...await api.resumeSession(session.id), assetName: session.assetName, accountName: session.accountName }); }
    catch (error) { setError((error as Error).message); }
  }
  return <main className="max-w-7xl mx-auto w-full p-6 space-y-5">
    <div className="flex justify-between"><h1 className="text-xl font-semibold">我的会话</h1><button onClick={load} className="text-blue-400">刷新</button></div>
    {error && <p role="alert" className="text-red-300">{error}</p>}
    <section className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden"><SessionTable sessions={sessions} historical actions={(session) => ['active', 'connecting'].includes(session.status) ? <>
      <button onClick={() => resume(session)} className="text-blue-300">恢复终端</button>
      <button onClick={async () => { try { await api.disconnectSession(session.id); await load(); } catch (error) { setError((error as Error).message); } }} className="text-red-300">断开</button>
    </> : null} /></section>
  </main>;
}
