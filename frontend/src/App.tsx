import React, { useState, useEffect, lazy, Suspense } from 'react';
import { useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { Login } from './auth/Login';
import { Dashboard } from './dashboard/Dashboard';
const Terminal = lazy(() => import('./terminal/Terminal').then((module) => ({ default: module.Terminal })));
const Admin = lazy(() => import('./admin/Admin').then((module) => ({ default: module.Admin })));
const Audit = lazy(() => import('./audit/Audit').then((module) => ({ default: module.Audit })));
const LiveMonitor = lazy(() => import('./audit/LiveMonitor').then((module) => ({ default: module.LiveMonitor })));
import { Shield } from 'lucide-react';
import { MfaSettings } from './auth/MfaSettings';
import { MySessions } from './sessions/MySessions';

const Application: React.FC = () => {
  const { user, loading } = useAuth();
  const [currentTab, setCurrentTab] = useState<'dashboard' | 'admin' | 'audit' | 'sessions' | 'security'>('dashboard');

  // Terminal active session
  const [activeSession, setActiveSession] = useState<{
    sessionId: string;
    ticket: string;
    assetName: string;
    accountName: string;
  } | null>(null);

  // Live monitor session
  const [monitorSession, setMonitorSession] = useState<{
    sessionId: string;
    assetName: string;
    accountName: string;
  } | null>(null);

  useEffect(() => { setActiveSession(null); setMonitorSession(null); setCurrentTab('dashboard'); }, [user?.id]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-400">
        <Shield className="w-8 h-8 animate-pulse text-blue-500 mb-2" />
      </div>
    );
  }

  if (!user) {
    return <Login />;
  }
  if (user.mfaPending || currentTab === 'security') return <MfaSettings onDone={() => setCurrentTab('dashboard')} />;

  if (activeSession) {
    return (
      <Terminal
        sessionId={activeSession.sessionId}
        ticket={activeSession.ticket}
        assetName={activeSession.assetName}
        accountName={activeSession.accountName}
        onClose={() => setActiveSession(null)}
      />
    );
  }

  if (monitorSession) {
    return (
      <LiveMonitor
        sessionId={monitorSession.sessionId}
        assetName={monitorSession.assetName}
        accountName={monitorSession.accountName}
        onClose={() => setMonitorSession(null)}
      />
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-900 text-slate-100">
      <Navbar currentTab={currentTab} onSelectTab={(t: any) => setCurrentTab(t)} />

      {currentTab === 'dashboard' && (
        <Dashboard onOpenTerminal={(s) => setActiveSession(s)} />
      )}

      {currentTab === 'admin' && <Admin />}
      {currentTab === 'sessions' && <MySessions onOpenTerminal={setActiveSession} />}

      {currentTab === 'audit' && (
        <Audit onOpenMonitor={(s) => setMonitorSession(s)} />
      )}
    </div>
  );
};

export const App: React.FC = () => <Suspense fallback={<div role="status" className="min-h-screen bg-slate-950 p-8 text-slate-300">Loading...</div>}><Application /></Suspense>;
