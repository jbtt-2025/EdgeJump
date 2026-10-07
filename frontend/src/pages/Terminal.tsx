import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { api } from '../api/client';
import { attachZmodem, ZmodemSessionHandler } from '../terminal/zmodem';
import {
  XCircle,
  Clock,
  Server,
  User,
  Upload,
  Download,
  Loader2,
  FileUp,
} from 'lucide-react';

interface TerminalProps {
  sessionId: string;
  ticket: string;
  assetName: string;
  accountName: string;
  onClose: () => void;
}

export const Terminal: React.FC<TerminalProps> = ({
  sessionId,
  ticket,
  assetName,
  accountName,
  onClose,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const zmodemHandlerRef = useRef<ZmodemSessionHandler | null>(null);

  const [connected, setConnected] = useState(false);
  const [disconnected, setDisconnected] = useState(false);
  const [seconds, setSeconds] = useState(0);

  // Zmodem (lrzsz) transfer status
  const [zmodemStatus, setZmodemStatus] = useState<{
    active: boolean;
    type?: 'upload' | 'download';
    fileName?: string;
    percent?: number;
  }>({ active: false });

  useEffect(() => {
    const timer = setInterval(() => {
      setSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatDuration = (totalSeconds: number) => {
    const mins = Math.floor(totalSeconds / 60);
    const secs = totalSeconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  useEffect(() => {
    if (!containerRef.current) return;

    // Initialize xterm
    const term = new XTerm({
      cursorBlink: true,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      fontSize: 14,
      theme: {
        background: '#0a0f1d',
        foreground: '#e2e8f0',
        cursor: '#60a5fa',
        selectionBackground: '#1e3a8a',
      },
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(new WebLinksAddon());

    term.open(containerRef.current);
    fitAddon.fit();

    terminalRef.current = term;
    fitAddonRef.current = fitAddon;

    term.writeln('\x1b[34m[EdgeJump]\x1b[0m 正在建立安全加密 WebSocket 通道...');

    // Connect WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/sessions/${sessionId}/ws?ticket=${encodeURIComponent(
      ticket
    )}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    ws.binaryType = 'arraybuffer';

    // Attach Zmodem (lrzsz) protocol sentry
    const zmodemHandler = attachZmodem(term, ws, (status) => {
      setZmodemStatus(status);
    });
    zmodemHandlerRef.current = zmodemHandler;

    ws.onopen = () => {
      setConnected(true);
      term.writeln('\x1b[32m[EdgeJump]\x1b[0m WebSocket 已连接，正在通过 DO 建立 SSH 会话...');
      term.writeln('\x1b[90m[EdgeJump] 提示: 支持 lrzsz 传输，运行 rz 上传文件，运行 sz <文件名> 下载文件。\x1b[0m\r\n');

      // Send initial terminal dimensions
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    };

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'status') {
            term.writeln(`\x1b[36m[SSH]\x1b[0m ${msg.message}`);
          } else if (msg.type === 'error') {
            term.writeln(`\r\n\x1b[31m[SSH Error]\x1b[0m ${msg.message}`);
          }
        } catch {
          term.write(event.data);
        }
      } else if (event.data instanceof ArrayBuffer) {
        // Feed binary data to Zmodem Sentry to detect ZMODEM handshake or render to terminal
        zmodemHandler.consume(event.data);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      setDisconnected(true);
      term.writeln('\r\n\x1b[33m[EdgeJump]\x1b[0m SSH 会话已结束，连接已断开。');
    };

    ws.onerror = () => {
      term.writeln('\r\n\x1b[31m[EdgeJump]\x1b[0m WebSocket 传输异常。');
    };

    // Forward terminal input to WebSocket (suppress if active ZMODEM transfer)
    const onDataDisposable = term.onData((data) => {
      if (zmodemHandler.hasActiveSession()) {
        return; // suppress keyboard input during file transfer
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });

    // Window resize handler
    const handleResize = () => {
      fitAddon.fit();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      onDataDisposable.dispose();
      ws.close();
      term.dispose();
    };
  }, [sessionId, ticket]);

  const handleDisconnect = async () => {
    try {
      await api.disconnectSession(sessionId);
    } catch {}
    wsRef.current?.close();
    onClose();
  };

  const handleTriggerRz = () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(new TextEncoder().encode('rz\r'));
    }
  };

  const handleTriggerSz = () => {
    const fileName = prompt('请输入远端要下载的文件名/路径 (例如: backup.tar.gz):');
    if (fileName && fileName.trim() && wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(new TextEncoder().encode(`sz ${fileName.trim()}\r`));
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-slate-950 overflow-hidden">
      {/* Terminal Status Bar */}
      <div className="bg-slate-900 border-b border-slate-800 px-4 py-2 flex items-center justify-between text-xs text-slate-300">
        <div className="flex items-center space-x-5">
          <div className="flex items-center space-x-1.5 font-medium text-white">
            <Server className="w-3.5 h-3.5 text-blue-400" />
            <span>{assetName}</span>
          </div>

          <div className="flex items-center space-x-1 font-mono text-slate-400">
            <User className="w-3.5 h-3.5" />
            <span>{accountName}</span>
          </div>

          <div className="flex items-center space-x-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                connected ? 'bg-emerald-500 animate-pulse' : disconnected ? 'bg-red-500' : 'bg-amber-500'
              }`}
            />
            <span>{connected ? '在线' : disconnected ? '已断开' : '连接中...'}</span>
          </div>

          <div className="flex items-center space-x-1 text-slate-400">
            <Clock className="w-3.5 h-3.5" />
            <span className="font-mono">{formatDuration(seconds)}</span>
          </div>

          {/* ZMODEM Active Transfer Indicator */}
          {zmodemStatus.active && (
            <div className="flex items-center space-x-1.5 px-2.5 py-0.5 bg-blue-950/80 border border-blue-700/60 text-blue-300 rounded-full animate-pulse text-[11px]">
              <Loader2 className="w-3 h-3 animate-spin text-blue-400" />
              <span>
                {zmodemStatus.type === 'upload' ? '正在上传 (rz)' : '正在下载 (sz)'}
                {zmodemStatus.fileName ? `: ${zmodemStatus.fileName}` : ''}
                {typeof zmodemStatus.percent === 'number' ? ` (${zmodemStatus.percent}%)` : ''}
              </span>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-2">
          {/* lrzsz Helper Buttons */}
          <button
            onClick={handleTriggerRz}
            disabled={!connected || zmodemStatus.active}
            title="发送 rz 命令上传文件到当前目录"
            className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded transition font-medium disabled:opacity-50"
          >
            <Upload className="w-3.5 h-3.5 text-blue-400" />
            <span>上传文件 (rz)</span>
          </button>

          <button
            onClick={handleTriggerSz}
            disabled={!connected || zmodemStatus.active}
            title="发送 sz 命令下载远端文件"
            className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded transition font-medium disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span>下载文件 (sz)</span>
          </button>

          <button
            onClick={handleDisconnect}
            className="flex items-center space-x-1 px-2.5 py-1 bg-red-950/70 hover:bg-red-900 border border-red-800 text-red-300 rounded transition font-medium ml-2"
          >
            <XCircle className="w-3.5 h-3.5" />
            <span>断开会话</span>
          </button>
        </div>
      </div>

      {/* xterm Canvas */}
      <div className="flex-1 w-full h-full relative" ref={containerRef} />
    </div>
  );
};
