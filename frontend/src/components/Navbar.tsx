import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Server, Shield, Terminal, Clock, LogOut, User as UserIcon } from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab }) => {
  const { user, logout, hasPermission } = useAuth();

  if (!user) return null;

  return (
    <header className="bg-slate-800 border-b border-slate-700 px-6 py-3 flex items-center justify-between select-none">
      <div className="flex items-center space-x-6">
        <div className="flex items-center space-x-2 text-blue-400 font-bold text-lg cursor-pointer" onClick={() => onSelectTab('dashboard')}>
          <Shield className="w-6 h-6" />
          <span>EdgeJump</span>
        </div>

        <nav className="flex items-center space-x-2">
          <button
            onClick={() => onSelectTab('dashboard')}
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-sm font-medium transition ${
              currentTab === 'dashboard' ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-700'
            }`}
          >
            <Server className="w-4 h-4" />
            <span>资产控制台</span>
          </button>

          {(hasPermission('asset.read') || hasPermission('authorization.read')) && (
            <button
              onClick={() => onSelectTab('admin')}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-sm font-medium transition ${
                currentTab === 'admin' ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-700'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span>堡垒机管理</span>
            </button>
          )}

          {(hasPermission('session.view_all') || hasPermission('audit.read')) && (
            <button
              onClick={() => onSelectTab('audit')}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-sm font-medium transition ${
                currentTab === 'audit' ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-700'
              }`}
            >
              <Clock className="w-4 h-4" />
              <span>会话与审计</span>
            </button>
          )}
        </nav>
      </div>

      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 text-sm text-slate-300">
          <UserIcon className="w-4 h-4 text-slate-400" />
          <span>{user.displayName || user.username}</span>
          <span className="text-xs bg-slate-700 text-slate-400 px-2 py-0.5 rounded">
            {user.roles?.[0] ? user.roles[0].replace('role_', '') : 'user'}
          </span>
        </div>

        <button
          onClick={logout}
          title="退出登录"
          className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-slate-700 rounded transition"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
