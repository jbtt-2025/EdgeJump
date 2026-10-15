import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { api } from '../api/client';
import type { RecordingManifest, TerminalEvent } from '../../../src/shared/types';

export function Replay({ sessionId, onClose }: { sessionId: string; onClose: () => void }) {
  const container = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const events = useRef<TerminalEvent[]>([]);
  const manifest = useRef<RecordingManifest | null>(null);
  const nextChunk = useRef(1);
  const cursor = useRef(0);
  const position = useRef(0);
  const generation = useRef(0);
  const operation = useRef(0);
  const running = useRef(false);
  const fetching = useRef<Promise<void> | null>(null);
  const [duration, setDuration] = useState(0);
  const [time, setTime] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function ensureThrough(target: number, current = generation.current) {
    const task = (fetching.current ?? Promise.resolve()).then(async () => {
      while (current === generation.current && manifest.current && nextChunk.current <= manifest.current.chunkCount &&
        (!events.current.length || events.current.at(-1)!.t <= target)) {
        const chunk = await api.getRecordingChunk(sessionId, nextChunk.current);
        if (current !== generation.current) return;
        events.current.push(...chunk); nextChunk.current++;
      }
    });
    const queued = task.catch(() => {});
    fetching.current = queued;
    try { await task; } finally { if (fetching.current === queued) fetching.current = null; }
  }

  function paint(target: number, reset = false) {
    if (reset) { terminal.current?.reset(); cursor.current = 0; }
    while (cursor.current < events.current.length && events.current[cursor.current].t <= target) {
      const event = events.current[cursor.current++];
      if (event.type === 'stdout' && typeof event.data === 'string') terminal.current?.write(event.data);
      if ((event.type === 'resize' || event.type === 'connect') && event.cols && event.rows) terminal.current?.resize(event.cols, event.rows);
    }
    position.current = target; setTime(target);
  }

  useEffect(() => {
    const current = ++generation.current;
    operation.current++;
    events.current = []; manifest.current = null; nextChunk.current = 1;
    cursor.current = 0; position.current = 0; fetching.current = null;
    setLoading(true); setError(''); setPlaying(false); setTime(0);
    const term = new Terminal({ disableStdin: true, cols: 80, rows: 24, fontSize: 14, theme: { background: '#020617' } });
    terminal.current = term; term.open(container.current!);
    (async () => {
      try {
        const result = await api.getSessionRecording(sessionId);
        if (current !== generation.current) return;
        manifest.current = result.manifest;
        setDuration(Math.max(0, result.manifest.endedAt - result.manifest.startedAt));
        await ensureThrough(0, current); if (current === generation.current) paint(0);
      } catch (error) { if (current === generation.current) setError((error as Error).message); }
      finally { if (current === generation.current) setLoading(false); }
    })();
    return () => { generation.current++; operation.current++; term.dispose(); };
  }, [sessionId]);

  useEffect(() => {
    if (!playing || loading || error) return;
    const current = generation.current;
    const action = ++operation.current;
    let last = performance.now();
    const timer = setInterval(async () => {
      if (running.current) return;
      running.current = true;
      const now = performance.now();
      const target = Math.min(duration, position.current + (now - last) * speed);
      last = now;
      try { await ensureThrough(target, current); if (current === generation.current && action === operation.current) paint(target); }
      catch (error) { if (current === generation.current && action === operation.current) { setError((error as Error).message); setPlaying(false); } }
      finally { running.current = false; }
      if (target >= duration && action === operation.current) setPlaying(false);
    }, 40);
    return () => { clearInterval(timer); if (action === operation.current) operation.current++; };
  }, [playing, speed, loading, duration, error]);

  async function seek(target: number) {
    const current = generation.current;
    const action = ++operation.current;
    setPlaying(false); setLoading(true);
    try {
      await ensureThrough(target, current);
      const term = terminal.current;
      if (term && current === generation.current) await new Promise<void>((resolve) => term.write('', resolve));
      if (current === generation.current && action === operation.current) paint(target, true);
    }
    catch (error) { if (current === generation.current && action === operation.current) setError((error as Error).message); }
    finally { if (current === generation.current && action === operation.current) setLoading(false); }
  }

  const clock = (milliseconds: number) => `${Math.floor(milliseconds / 60000)}:${String(Math.floor(milliseconds / 1000) % 60).padStart(2, '0')}`;
  return <section aria-label="会话回放" className="fixed inset-0 z-50 bg-slate-950 text-slate-200 flex flex-col p-5 gap-4">
    <div className="flex justify-between items-center"><h1 className="text-xl font-semibold">会话回放</h1><button onClick={onClose} className="px-4 py-2 bg-slate-800 rounded-lg">关闭回放</button></div>
    {error && <p role="alert" className="text-red-300">{error}</p>}
    <div className="flex flex-wrap items-center gap-4 text-sm">
      <button disabled={loading || !!error} onClick={() => time >= duration ? void seek(0).then(() => setPlaying(true)) : setPlaying(!playing)} className="px-4 py-2 bg-blue-600 rounded-lg disabled:opacity-50">{playing ? '暂停' : '播放'}</button>
      <label>速度 <select aria-label="回放速度" value={speed} onChange={(event) => setSpeed(Number(event.target.value))} className="ml-2 bg-slate-800 rounded px-3 py-2">{[1, 2, 4].map((value) => <option key={value} value={value}>{value}x</option>)}</select></label>
      <span className="font-mono">{clock(time)} / {clock(duration)}</span>
      <span className="text-emerald-400">{loading ? '正在读取录像…' : error ? '' : '完整性校验通过'}</span>
    </div>
    <input aria-label="回放时间轴" type="range" min={0} max={duration || 1} step={1} value={time} disabled={loading || !!error} onChange={(event) => void seek(Number(event.target.value))} />
    <div ref={container} className="flex-1 overflow-auto border border-slate-700 rounded-lg p-3" />
  </section>;
}
