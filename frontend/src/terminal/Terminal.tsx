import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { api } from '../api/client';

interface TerminalProps { sessionId: string; ticket: string; assetName: string; accountName: string; onClose: () => void }

export function Terminal(props: TerminalProps) {
  const container = useRef<HTMLDivElement>(null);
  const screen = useRef<HTMLDivElement>(null);
  const socket = useRef<WebSocket | null>(null);
  const [session, setSession] = useState({ sessionId: props.sessionId, ticket: props.ticket });
  const [status, setStatus] = useState('连接中');
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setSeconds((seconds) => seconds + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const term = new XTerm({ cursorBlink: true, fontSize: 14, fontFamily: 'Consolas, monospace', theme: { background: '#020617', foreground: '#e2e8f0' } });
    const fit = new FitAddon(); term.loadAddon(fit); term.loadAddon(new WebLinksAddon());
    term.open(container.current!); fit.fit();
    setStatus('连接中');
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${location.host}/api/sessions/${session.sessionId}/ws?ticket=${encodeURIComponent(session.ticket)}`);
    socket.current = ws; ws.binaryType = 'arraybuffer';
    const resize = () => {
      fit.fit();
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
    };
    ws.onopen = () => { resize(); term.focus(); };
    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) { term.write(new Uint8Array(event.data)); return; }
      if (typeof event.data === 'string') {
        try {
          const message = JSON.parse(event.data);
          if (message.type === 'status') { setStatus(message.status === 'active' ? '在线' : message.message); return; }
        } catch { /* terminal output */ }
        term.write(event.data);
      }
    };
    ws.onclose = () => { setStatus('已断开'); term.writeln('\r\n[EdgeJump] 会话已结束。'); };
    ws.onerror = () => setError('连接失败，请检查网络或重新连接。');
    const input = term.onData((data) => { if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data)); });
    const observer = new ResizeObserver(resize); observer.observe(container.current!);
    return () => { observer.disconnect(); input.dispose(); ws.onclose = null; ws.close(); term.dispose(); };
  }, [session.sessionId, session.ticket]);

  async function reconnect() {
    setBusy(true); setError('');
    try {
      const previous = await api.getMySession(session.sessionId);
      const next = ['active', 'connecting'].includes(previous.status)
        ? await api.resumeSession(previous.id) : await api.createSession(previous.assetId, previous.accountId);
      setSession(next); setSeconds(0);
    } catch (error) { setError((error as Error).message); }
    finally { setBusy(false); }
  }
  async function disconnect() {
    setBusy(true); setError('');
    try { await api.disconnectSession(session.sessionId); socket.current?.close(); props.onClose(); }
    catch (error) { setError((error as Error).message); }
    finally { setBusy(false); }
  }
  async function paste() {
    try {
      const text = await navigator.clipboard.readText();
      if (/\r|\n/.test(text) && !confirm('剪贴板包含多行，粘贴可能执行多条命令。继续粘贴？')) return;
      if (socket.current?.readyState === WebSocket.OPEN) socket.current.send(new TextEncoder().encode(text));
    } catch { setError('无法读取剪贴板，请使用 Ctrl+Shift+V 粘贴。'); }
  }

  return <div ref={screen} className="h-dvh bg-slate-950 text-slate-200 flex flex-col">
    <header className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border-b border-slate-700 text-sm">
      <div className="flex gap-5 items-center"><strong>{props.assetName}</strong><span className="font-mono">{props.accountName}</span><span role="status" className={status === '在线' ? 'text-emerald-400' : 'text-amber-300'}>{status}</span><span className="font-mono">{Math.floor(seconds / 60)}:{String(seconds % 60).padStart(2, '0')}</span></div>
      <div className="flex gap-2">
        <button onClick={paste} disabled={status !== '在线'} className="px-3 py-2 rounded bg-slate-800 disabled:opacity-50">粘贴</button>
        <button onClick={() => { void (document.fullscreenElement ? document.exitFullscreen() : screen.current?.requestFullscreen()); }} className="px-3 py-2 rounded bg-slate-800">全屏</button>
        {status === '已断开' && <button disabled={busy} onClick={reconnect} className="px-3 py-2 rounded bg-blue-600">重新连接</button>}
        <button disabled={busy} onClick={disconnect} className="px-3 py-2 rounded bg-red-950 text-red-300">断开会话</button>
        {status === '已断开' && <button onClick={props.onClose} className="px-3 py-2 rounded bg-slate-800">返回资产</button>}
      </div>
    </header>
    {error && <p role="alert" className="p-3 text-red-300">{error}</p>}
    <div ref={container} aria-label="SSH 终端" className="flex-1 min-h-0 p-2" />
  </div>;
}
