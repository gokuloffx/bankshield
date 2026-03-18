import axios from 'axios';

// In production (Netlify), REACT_APP_API_URL points to your Vercel backend
// In development, proxy to localhost:5000
const BASE_URL = process.env.REACT_APP_API_URL
  ? `${process.env.REACT_APP_API_URL}/api`
  : '/api';

const api = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
});

// ── Auth ──────────────────────────────────────────────────────────────────────
export const login    = (data)     => api.post('/auth/login', data);
export const logout   = ()         => api.post('/auth/logout');
export const me       = ()         => api.get('/auth/me');

// ── Scan ──────────────────────────────────────────────────────────────────────
export const scanFile = (file) => {
  const fd = new FormData();
  fd.append('file', file);
  return api.post('/scan', fd, { headers: { 'Content-Type': 'multipart/form-data' } });
};

export const simulateAttack = () => api.post('/simulate_attack');
export const simulateMulti  = (count=5) => api.post('/simulate_multi', { count });

// ── Logs ──────────────────────────────────────────────────────────────────────
export const getLogs = () => api.get('/logs');

// ── Quarantine ────────────────────────────────────────────────────────────────
export const getQuarantine    = ()    => api.get('/quarantine');
export const restoreFile      = (id)  => api.post(`/quarantine/${id}/restore`);
export const deleteQuarantine = (id)  => api.delete(`/quarantine/${id}/delete`);

// ── Stats & Model ─────────────────────────────────────────────────────────────
export const getStats        = () => api.get('/stats');
export const getModelInfo    = () => api.get('/model/info');
export const getAdvancedStats= () => api.get('/advanced_stats');

export default api;
