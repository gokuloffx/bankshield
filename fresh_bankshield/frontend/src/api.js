import axios from 'axios';

const BASE = process.env.REACT_APP_API_URL
  ? `${process.env.REACT_APP_API_URL}/api`
  : '/api';

const api = axios.create({ baseURL: BASE, withCredentials: true });

export const login             = (d)      => api.post('/auth/login', d);
export const logout            = ()       => api.post('/auth/logout');
export const me                = ()       => api.get('/auth/me');
export const scanFile          = (file)   => { const fd=new FormData(); fd.append('file',file); return api.post('/scan',fd,{headers:{'Content-Type':'multipart/form-data'}}); };
export const simulateMulti     = (count=5)=> api.post('/simulate_multi',{count});
export const getLogs           = ()       => api.get('/logs');
export const getQuarantine     = ()       => api.get('/quarantine');
export const restoreFile       = (id)     => api.post(`/quarantine/${id}/restore`);
export const deleteQuarantine  = (id)     => api.delete(`/quarantine/${id}/delete`);
export const getStats          = ()       => api.get('/stats');
export const getAdvancedStats  = ()       => api.get('/advanced_stats');
export const getModelInfo      = ()       => api.get('/model/info');

export default api;
