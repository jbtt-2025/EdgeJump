import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { Eye, ArrowLeft, Server, User, AlertOctagon } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';

interface LiveMonitorProps {
  sessionId: string;
  assetName: string;
  accountName: string;
  onClose: () => void;
}

export const LiveMonitor: React.FC<LiveMonitorProps> = ({
  sessionId,
  assetName,
  accountName,
  onClose,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [terminating, setTerminating] = useState(false);
  const { hasPermission } = useAuth();

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new XTerm({
      cursorBlink: false,
      disableStdin: true, // Strictly Read-Only for auditors
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      fontSize: 14,
      theme: {
        background: '#090d16',
        foreground: '#cbd5e1',
        selectionBackground: '#1e3a8a',
      },
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(new WebLinksAddon());

    term.open(containerRef.current);
    fitAddon.fit();

    term.writeln('\x1b[35m[Live Monitor]\x1b[0m 正在接入在线会话只读旁路监视流...');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/admin/sessions/${sessionId}/monitor`;
    const ws = new WebSocket(wsUrl);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      term.writeln('\x1b[32m[Live Monitor]\x1b[0m 旁路通道已建立，正在实时同步远端终端画面。\r\n');
    };

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'resize') {
            term.resize(msg.cols, msg.rows);
          }
        } catch {
          term.write(event.data);
        }
      } else if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
      }
    };

    ws.onclose = () => {
      term.writeln('\r\n\x1b[33m[Live Monitor]\x1b[0m 会话已断开或结束。');
    };

    return () => {
      ws.onclose = null;
      ws.close();
      term.dispose();
    };
  }, [sessionId]);

  const handleTerminate = async () => {
    if (confirm('确认强制终止此会话？')) {
      setTerminating(true);
      try {
        await api.terminateSession(sessionId);
        onClose();
      } catch (err: any) {
        alert(err.message);
      } finally {
        setTerminating(false);
      }
    }
  };

  return (
    <div className="h-dvh flex flex-col bg-slate-950 overflow-hidden">
      <div className="bg-slate-900 border-b border-slate-800 px-4 py-2 flex items-center justify-between text-xs text-slate-300">
        <div className="flex items-center space-x-4">
          <button
            onClick={onClose}
            className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition font-medium"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>返回审计中心</span>
          </button>

          <div className="flex items-center space-x-1.5 font-medium text-white">
            <Server className="w-3.5 h-3.5 text-blue-400" />
            <span>{assetName}</span>
          </div>

          <div className="flex items-center space-x-1 font-mono text-slate-400">
            <User className="w-3.5 h-3.5" />
            <span>{accountName}</span>
          </div>

          <span className="flex items-center space-x-1 bg-purple-950/80 border border-purple-800 text-purple-300 px-2 py-0.5 rounded">
            <Eye className="w-3.5 h-3.5" />
            <span>只读旁路监视中 (不可输入)</span>
          </span>
        </div>

        {hasPermission('session.terminate') && <button
          onClick={handleTerminate}
          disabled={terminating}
          className="flex items-center space-x-1 px-2.5 py-1 bg-red-950 hover:bg-red-900 border border-red-800 text-red-300 rounded transition font-medium"
        >
          <AlertOctagon className="w-3.5 h-3.5" />
          <span>强制切断会话</span>
        </button>}
      </div>

      <div className="flex-1 min-h-0 overflow-auto relative" ref={containerRef} />
    </div>
  );
};
