import React, { createContext, useContext, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { MeResponse } from '../../../src/shared/types';

export type User = MeResponse['user'];

interface AuthContextType {
  user: User | null;
  permissions: Set<string>;
  deployType: string;
  loading: boolean;
  login: (userData: any, perms: string[], deployType?: string) => void;
  logout: () => Promise<void>;
  hasPermission: (perm: string) => boolean;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  permissions: new Set(),
  deployType: 'production',
  loading: true,
  login: () => {},
  logout: async () => {},
  hasPermission: () => false,
  refreshUser: async () => {},
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [permissions, setPermissions] = useState<Set<string>>(new Set());
  const [deployType, setDeployType] = useState<string>('production');
  const [loading, setLoading] = useState<boolean>(true);

  const refreshUser = async () => {
    try {
      const res = await api.getMe();
      setUser(res.user);
      setPermissions(new Set(res.permissions));
      if (res.deployType) setDeployType(res.deployType);
    } catch {
      setUser(null);
      setPermissions(new Set());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshUser();
  }, []);

  const login = (userData: any, perms: string[], dt?: string) => {
    setUser(userData);
    setPermissions(new Set(perms));
    if (dt) setDeployType(dt);
  };

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
      setPermissions(new Set());
    }
  };

  const hasPermission = (perm: string) => {
    if (permissions.has('*')) return true;
    if (permissions.has(perm)) return true;
    const prefix = perm.split('.')[0] + '.*';
    return permissions.has(prefix);
  };

  return (
    <AuthContext.Provider value={{ user, permissions, deployType, loading, login, logout, hasPermission, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
