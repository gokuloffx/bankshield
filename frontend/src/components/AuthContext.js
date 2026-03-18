import React, { createContext, useContext, useState, useEffect } from 'react';
import { me, logout as apiLogout } from '../api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    me()
      .then(r => { if (r.data.logged_in) setUser(r.data); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const login = (userData) => setUser(userData);

  const logout = async () => {
    try { await apiLogout(); } catch {}
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
