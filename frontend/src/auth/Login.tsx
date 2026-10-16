import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api, ApiError } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User, Key, AlertCircle } from 'lucide-react';
import { getAccountPolicy } from '../../../src/shared/account-policy';

type LoginError = { title: string; message: string; code?: string; requestId?: string };

function describeError(error: unknown, title: string): LoginError {
  return {
    title,
    message: error instanceof Error ? error.message : '操作失败，请稍后重试。',
    ...(error instanceof ApiError ? { code: error.code, requestId: error.requestId } : {}),
  };
}

export const Login: React.FC = () => {
  const { login } = useAuth();
  const [bootstrapNeeded, setBootstrapNeeded] = useState(false);
  const [isBootstrapMode, setIsBootstrapMode] = useState(false);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');

  const [mfaRequired, setMfaRequired] = useState(false);
  const [challengeToken, setChallengeToken] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [error, setError] = useState<LoginError | null>(null);
  const [loading, setLoading] = useState(false);
  const [deployType, setDeployType] = useState('production');
  const [checkingBootstrap, setCheckingBootstrap] = useState(true);
  const [bootstrapStatusFailed, setBootstrapStatusFailed] = useState(false);
  const errorRef = useRef<HTMLDivElement>(null);
  const policy = getAccountPolicy(deployType);

  useEffect(() => {
    if (error) {
      errorRef.current?.focus({ preventScroll: true });
      errorRef.current?.scrollIntoView({ block: 'nearest' });
    }
  }, [error]);

  const checkBootstrapStatus = useCallback(async () => {
    setCheckingBootstrap(true);
    setBootstrapStatusFailed(false);
    setError(null);
    try {
      const res = await api.getBootstrapStatus();
      if (res.deployType) setDeployType(res.deployType);
      setBootstrapNeeded(res.bootstrapNeeded);
      setIsBootstrapMode(res.bootstrapNeeded);
    } catch (error) {
      setBootstrapStatusFailed(true);
      setError(describeError(error, '无法检查初始化状态'));
    } finally {
      setCheckingBootstrap(false);
    }
  }, []);

  useEffect(() => { void checkBootstrapStatus(); }, [checkBootstrapStatus]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBootstrapStatusFailed(false);
    setLoading(true);
    let administratorCreated = false;

    try {
      if (isBootstrapMode) {
        await api.bootstrap({
          bootstrapToken,
          username,
          password,
          displayName: displayName || username,
          email: email || undefined,
        });
        administratorCreated = true;
        setBootstrapNeeded(false);
        setIsBootstrapMode(false);
        setBootstrapToken('');
      }

      const res = mfaRequired ? await api.completeMfa(challengeToken, totpCode || undefined, recoveryCode || undefined) : await api.login({
        username,
        password,
        totpCode: totpCode || undefined,
        recoveryCode: recoveryCode || undefined,
      });

      if (res.mfaRequired) {
        setChallengeToken((res as { challengeToken?: string }).challengeToken ?? '');
        setPassword('');
        setMfaRequired(true);
        setLoading(false);
        return;
      }

      const me = await api.getMe();
      login(me.user, me.permissions, me.deployType);
    } catch (err: unknown) {
      const completed = err instanceof ApiError && ['BOOTSTRAP_COMPLETED', 'BOOTSTRAP_AUDIT_FAILED'].includes(err.code ?? '');
      if (completed) {
        setBootstrapNeeded(false);
        setIsBootstrapMode(false);
        setBootstrapToken('');
      }
      setError(describeError(err, administratorCreated ? '管理员已创建，自动登录失败' : completed ? '系统已初始化' : isBootstrapMode ? '初始化失败' : '登录失败'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-dvh shrink-0 overflow-y-auto bg-slate-950">
      <div className="min-h-full flex items-center justify-center px-4 py-8">
      <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-blue-600/20 text-blue-400 rounded-xl mb-3">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">EdgeJump 堡垒机</h1>
          <p className="text-slate-400 text-sm mt-1">
            {isBootstrapMode ? '首次部署超级管理员初始化' : mfaRequired ? '双因子安全认证 (MFA)' : '统一身份认证'}
          </p>
        </div>

        {deployType === 'demo' && (
          <div className="mb-4 bg-amber-950/40 border border-amber-800/60 text-amber-300 px-3.5 py-2.5 rounded-lg text-xs leading-relaxed flex items-start space-x-2">
            <span className="font-semibold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-200 shrink-0 text-[11px]">演示模式</span>
            <span>公开体验环境：管理员密码与录像保留时间已受保护锁定，其余功能均可自由体验。</span>
          </div>
        )}

        {error && (
          <div ref={errorRef} role="alert" tabIndex={-1} className="mb-6 bg-red-950/60 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm flex items-start space-x-2 focus:outline-none">
            <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
            <div className="min-w-0 space-y-2 leading-relaxed">
              <p className="font-semibold text-red-200">{error.title}</p>
              <p>{error.message}</p>
              {error.requestId && <p className="break-all text-slate-300">请求编号：<code className="select-all">{error.requestId}</code></p>}
              {bootstrapStatusFailed && <button type="button" disabled={checkingBootstrap} onClick={() => void checkBootstrapStatus()} className="font-medium underline underline-offset-4">重新检查</button>}
            </div>
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          {isBootstrapMode && (
            <div>
              <label htmlFor="bootstrap-token" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Bootstrap Token</label>
              <div className="relative">
                <Key className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                <input
                  id="bootstrap-token"
                  type="password"
                  required
                  placeholder="Worker Secret BOOTSTRAP_TOKEN"
                  value={bootstrapToken}
                  onChange={(e) => setBootstrapToken(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          )}

          {!mfaRequired && (
            <>
              <div>
                <label htmlFor="login-username" className="block text-xs font-semibold text-slate-300 uppercase mb-1">用户名</label>
                <div className="relative">
                  <User className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input
                    id="login-username"
                    type="text"
                    required
                    minLength={isBootstrapMode ? policy.bootstrapUsernameMinLength : undefined}
                    autoComplete="username"
                    placeholder="请输入用户名"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                {isBootstrapMode && policy.bootstrapUsernameMinLength > 1 && <p className="mt-1 text-sm text-slate-400">至少 {policy.bootstrapUsernameMinLength} 个字符</p>}
              </div>

              {isBootstrapMode && (
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">显示名称</label>
                  <input
                    type="text"
                    placeholder="管理员姓名"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              )}

              <div>
                <label htmlFor="login-password" className="block text-xs font-semibold text-slate-300 uppercase mb-1">密码</label>
                <div className="relative">
                  <Lock className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input
                    id="login-password"
                    type="password"
                    required
                    minLength={isBootstrapMode ? policy.passwordMinLength : undefined}
                    autoComplete={isBootstrapMode ? 'new-password' : 'current-password'}
                    placeholder="请输入密码"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                {isBootstrapMode && policy.passwordMinLength > 1 && <p className="mt-1 text-sm text-slate-400">至少 {policy.passwordMinLength} 个字符</p>}
              </div>
            </>
          )}

          {mfaRequired && (
            <>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">6 位动态验证码</label>
                <input
                  type="text"
                  placeholder="000000"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-center tracking-widest text-lg font-mono text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="pt-2">
                <label className="block text-xs text-slate-400 mb-1">或使用应急恢复码</label>
                <input
                  type="text"
                  placeholder="Recovery Code"
                  value={recoveryCode}
                  onChange={(e) => setRecoveryCode(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </>
          )}

          <button
            type="submit"
            disabled={loading || checkingBootstrap}
            className="w-full mt-4 bg-blue-600 hover:bg-blue-500 text-white font-medium py-2.5 rounded-lg transition text-sm disabled:opacity-50"
          >
            {checkingBootstrap ? '正在检查初始化状态...' : loading ? '处理中...' : isBootstrapMode ? '初始化系统' : mfaRequired ? '完成验证' : '立即登录'}
          </button>
        </form>

        {bootstrapNeeded && !isBootstrapMode && (
          <div className="mt-4 text-center">
            <button
              onClick={() => setIsBootstrapMode(true)}
              className="text-xs text-blue-400 hover:underline"
            >
              系统未初始化？点击进入首次配置
            </button>
          </div>
        )}
      </div>
      </div>
    </div>
  );
};
