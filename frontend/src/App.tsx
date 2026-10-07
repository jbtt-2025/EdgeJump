import React, { useState } from 'react';
import { useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Terminal } from './pages/Terminal';
import { Admin } from './pages/Admin';
import { Audit } from './pages/Audit';
import { LiveMonitor } from './pages/LiveMonitor';
import { Shield } from 'lucide-react';

export const App: React.FC = () => {
  const { user, loading } = useAuth();
  const [currentTab, setCurrentTab] = useState<'dashboard' | 'admin' | 'audit'>('dashboard');

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

      {currentTab === 'audit' && (
        <Audit onOpenMonitor={(s) => setMonitorSession(s)} />
      )}
    </div>
  );
};
