import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import { AttackBadge, ATTACK_META } from '../components/AttackBadge';
import { getLogs } from '../api';

export default function Logs() {
  const [logs,    setLogs]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter,  setFilter]  = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [search,  setSearch]  = useState('');
  const navigate = useNavigate();

  const load = useCallback(async () => {
    try { const r = await getLogs(); setLogs(r.data); }
    catch (e) { if (e.response?.status === 401) navigate('/login'); }
    finally { setLoading(false); }
  }, [navigate]);

  useEffect(() => { load(); }, [load]);

  const filtered = logs.filter(l => {
    const matchPred   = filter === 'all' || l.prediction.toLowerCase() === filter;
    const matchType   = typeFilter === 'all' || l.attack_type === typeFilter;
    const matchSearch = !search
      || l.filename.toLowerCase().includes(search.toLowerCase())
      || l.file_hash?.includes(search)
      || (l.attack_type||'').toLowerCase().includes(search.toLowerCase());
    return matchPred && matchType && matchSearch;
  });

  // Count by attack type for the summary bar
  const typeCounts = logs.reduce((acc, l) => {
    if (l.attack_type) acc[l.attack_type] = (acc[l.attack_type]||0)+1;
    return acc;
  }, {});

  return (
    <Layout title="Threat Scan Logs" subtitle="Complete history of all file scans with attack type">
      {/* Attack type summary */}
      <div style={{display:'flex',gap:10,flexWrap:'wrap',marginBottom:20}}>
        {Object.entries(ATTACK_META).map(([name,m])=>(
          <div key={name} style={{
            display:'flex',alignItems:'center',gap:8,padding:'10px 16px',
            background:'var(--bg-card)',border:`1px solid ${typeCounts[name]?m.border:'var(--border)'}`,
            borderRadius:10,cursor:'pointer',transition:'all 0.15s',
            outline: typeFilter===name?`2px solid ${m.color}`:'none'
          }} onClick={()=>setTypeFilter(typeFilter===name?'all':name)}>
            <span style={{fontSize:18}}>{m.icon}</span>
            <div>
              <div style={{fontSize:12,fontWeight:700,color:m.color}}>{name}</div>
              <div style={{fontSize:20,fontWeight:800,color:'var(--text-primary)',lineHeight:1}}>
                {typeCounts[name]||0}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">📋 Scan History</div>
            <div className="card-subtitle">{filtered.length} / {logs.length} records shown</div>
          </div>
          <div style={{display:'flex',gap:8,alignItems:'center',flexWrap:'wrap'}}>
            <input className="form-input"
              style={{width:200,padding:'7px 12px',fontSize:13}}
              placeholder="🔍 Search…"
              value={search} onChange={e=>setSearch(e.target.value)}/>
            {['all','safe','malware'].map(f=>(
              <button key={f} className={`btn btn-sm ${filter===f?'btn-primary':'btn-outline'}`}
                onClick={()=>setFilter(f)}>
                {f==='all'?'All':f==='safe'?'✅ Safe':'☣️ Malware'}
              </button>
            ))}
            <button className="btn btn-outline btn-sm" onClick={load}>🔄</button>
          </div>
        </div>

        {loading ? (
          <div style={{display:'flex',justifyContent:'center',padding:40}}>
            <div className="loading-spinner" style={{width:32,height:32}}></div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📋</div>
            <div className="empty-state-title">No logs found</div>
            <div className="empty-state-sub">{search?'No results match your search.':'No files scanned yet.'}</div>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Filename</th>
                  <th>Result</th>
                  <th>Attack Type</th>
                  <th>Confidence</th>
                  <th>Entropy</th>
                  <th>Size</th>
                  <th>Scanned By</th>
                  <th>Time</th>
                  <th>Quarantined</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(log=>(
                  <tr key={log.id}>
                    <td style={{color:'var(--text-muted)',fontSize:12}}>{log.id}</td>
                    <td>
                      <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:11}}>{log.filename}</div>
                      <div style={{fontSize:10,color:'var(--text-muted)'}}>{log.file_hash?.substring(0,14)}…</div>
                    </td>
                    <td>
                      <span className={`badge ${log.prediction==='Malware'?'badge-danger':'badge-success'}`}>
                        {log.prediction==='Malware'?'☣️ Malware':'✅ Safe'}
                      </span>
                    </td>
                    <td>
                      {log.attack_type
                        ? <AttackBadge type={log.attack_type} size="sm"/>
                        : <span style={{color:'var(--text-muted)',fontSize:11}}>—</span>
                      }
                    </td>
                    <td>
                      <div style={{display:'flex',alignItems:'center',gap:6}}>
                        <div className="progress-bar-wrap" style={{width:44,height:5}}>
                          <div className={`progress-bar ${log.prediction==='Malware'?'red':'green'}`}
                            style={{width:`${log.confidence}%`}}></div>
                        </div>
                        <span style={{fontSize:12}}>{log.confidence?.toFixed(1)}%</span>
                      </div>
                    </td>
                    <td style={{fontFamily:'JetBrains Mono,monospace',fontSize:12}}>{log.entropy?.toFixed(3)}</td>
                    <td style={{fontSize:12}}>{((log.file_size||0)/1024).toFixed(1)} KB</td>
                    <td style={{fontSize:12}}>{log.scanned_by}</td>
                    <td style={{fontSize:12}}>{new Date(log.scan_time).toLocaleString()}</td>
                    <td>
                      {log.is_quarantined
                        ? <span className="badge badge-danger">🔒 Yes</span>
                        : <span className="badge badge-success">✅ No</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}
