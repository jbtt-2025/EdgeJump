import React, { useState } from 'react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ShieldCheck } from 'lucide-react';
import { isDemoDeployment } from '../../../src/shared/account-policy';

export function MfaSettings({ onDone }: { onDone?: () => void }) {
  const { user, refreshUser, logout, deployType } = useAuth();
  const [setup, setSetup] = useState<Awaited<ReturnType<typeof api.setupMfa>> | null>(null);
  const [code, setCode] = useState('');
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [disabling, setDisabling] = useState(false);
  const [password, setPassword] = useState('');
  const [disabled, setDisabled] = useState(false);

  async function start() {
    setBusy(true); setError(''); setDisabled(false);
    try { setSetup(await api.setupMfa()); } catch (error) { setError((error as Error).message); }
    finally { setBusy(false); }
  }
  async function disable(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      await api.disableMfa(password, code);
      setDisabling(false); setCode(''); setDisabled(true);
      await refreshUser();
    } catch (error) { setError((error as Error).message); }
    finally { setPassword(''); setBusy(false); }
  }
  async function confirm(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try { await api.confirmMfa(code); setSetup(null); await refreshUser(); onDone?.(); }
    catch (error) { setError((error as Error).message); }
    finally { setBusy(false); }
  }

  if (isDemoDeployment(deployType)) return <main className="min-h-screen bg-slate-950 p-6 flex items-center justify-center text-slate-200">
    <section className="w-full max-w-xl bg-slate-900 border border-slate-700 rounded-xl p-7 space-y-5">
      <h1 className="text-2xl font-semibold">账户安全</h1>
      <p>演示模式使用共享账号，通过用户名和密码直接登录，不开放 MFA 设置。</p>
      <button onClick={onDone} className="text-blue-400">返回</button>
    </section>
  </main>;

  return <main className="min-h-screen bg-slate-950 p-6 flex items-center justify-center text-slate-200">
    <section className="w-full max-w-xl bg-slate-900 border border-slate-700 rounded-xl p-7 space-y-5">
      <ShieldCheck className="text-blue-400 w-8 h-8" />
      <h1 className="text-2xl font-semibold">双因素认证</h1>
      {user?.mfaPending && <p>为账户设置验证器后即可继续使用 EdgeJump。</p>}
      {error && <p role="alert" className="text-red-300">{error}</p>}
      {disabled && <p role="status" className="text-amber-300">已关闭双因素认证。你可以随时重新启用。</p>}
      {user?.mfaEnabled ? <div className="space-y-4">
        <p className="text-emerald-400">已启用 TOTP 验证器。</p>
        {user.mfaRequired ? <p className="text-sm text-slate-400">系统策略要求此账户启用双因素认证，无法关闭。</p> : disabling ?
          <form onSubmit={disable} className="space-y-4">
            <p className="text-sm text-amber-300">关闭后，登录将只验证密码，现有恢复码会失效。</p>
            <label className="block space-y-2">当前密码
              <input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} className="block w-full bg-slate-800 border border-slate-600 rounded-lg p-3" />
            </label>
            <label className="block space-y-2">6 位动态验证码
              <input autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={(event) => setCode(event.target.value)} className="block w-full bg-slate-800 border border-slate-600 rounded-lg p-3 font-mono" />
            </label>
            <div className="flex gap-4">
              <button disabled={busy} className="bg-red-700 rounded-lg px-4 py-2 disabled:opacity-50">确认关闭</button>
              <button type="button" disabled={busy} onClick={() => { setDisabling(false); setPassword(''); setCode(''); setError(''); }} className="text-slate-400">取消</button>
            </div>
          </form> : <button onClick={() => { setDisabling(true); setCode(''); setError(''); }} className="text-red-300 underline">关闭双因素认证</button>}
      </div> : !setup ?
        <button disabled={busy} className="bg-blue-600 rounded-lg px-4 py-2 disabled:opacity-50" onClick={start}>设置验证器</button> :
        <form onSubmit={confirm} className="space-y-5">
          <p>在验证器应用中手动添加账户 <strong>{user?.username}</strong>，填写以下密钥。</p>
          <label className="block space-y-2">TOTP 密钥
            <input readOnly value={setup.secret} className="block w-full bg-slate-950 rounded p-3 font-mono select-all" />
          </label>
          <a href={setup.uri} className="inline-block text-blue-400 underline">在验证器中打开</a>
          <div>
            <h2 className="font-semibold mb-2">恢复码</h2>
            <p className="text-sm text-slate-400 mb-3">仅显示这一次。请保存到密码管理器，每个恢复码只能使用一次。</p>
            <div className="grid grid-cols-2 gap-2 font-mono bg-slate-950 rounded-lg p-4">{setup.recoveryCodes.map((code) => <code key={code}>{code}</code>)}</div>
          </div>
          <label className="flex gap-2 items-center"><input type="checkbox" checked={saved} onChange={(event) => setSaved(event.target.checked)} required />我已保存恢复码</label>
          <label className="block space-y-2">6 位动态验证码
            <input autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={(event) => setCode(event.target.value)} className="block w-full bg-slate-800 border border-slate-600 rounded-lg p-3 font-mono" />
          </label>
          <button disabled={busy || !saved} className="bg-blue-600 rounded-lg px-4 py-2 disabled:opacity-50">验证并启用</button>
        </form>}
      <div className="flex gap-4 text-sm">
        {!user?.mfaPending && <button onClick={onDone} className="text-slate-400">返回</button>}
        <button onClick={logout} className="text-slate-400">退出登录</button>
      </div>
    </section>
  </main>;
}
