import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './components/AuthContext';

import Login      from './pages/Login';
import Dashboard  from './pages/Dashboard';
import Scanner    from './pages/Scanner';
import Quarantine from './pages/Quarantine';
import Logs       from './pages/Logs';
import Alerts     from './pages/Alerts';
import ModelInfo  from './pages/ModelInfo';

function PrivateRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return (
    <div style={{
      minHeight:'100vh', display:'flex', alignItems:'center',
      justifyContent:'center', background:'#0a0e1a', gap:16
    }}>
      <div className="loading-spinner" style={{width:36,height:36}}></div>
      <span style={{color:'#94a3b8',fontSize:15}}>Loading CyberGuard ML…</span>
    </div>
  );
  return user ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/dashboard"  element={<PrivateRoute><Dashboard  /></PrivateRoute>} />
          <Route path="/scan"       element={<PrivateRoute><Scanner    /></PrivateRoute>} />
          <Route path="/quarantine" element={<PrivateRoute><Quarantine /></PrivateRoute>} />
          <Route path="/logs"       element={<PrivateRoute><Logs       /></PrivateRoute>} />
          <Route path="/alerts"     element={<PrivateRoute><Alerts     /></PrivateRoute>} />
          <Route path="/model"      element={<PrivateRoute><ModelInfo  /></PrivateRoute>} />
          <Route path="*"           element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
