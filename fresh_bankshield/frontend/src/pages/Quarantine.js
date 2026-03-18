import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import { AttackBadge, ATTACK_META } from '../components/AttackBadge';
import { getQuarantine, restoreFile, deleteQuarantine } from '../api';

export default function Quarantine() {
  const [records,  setRecords]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [actionId, setActionId] = useState(null);
  const [typeFilter, setTypeFilter] = useState('all');
  const navigate = useNavigate();

  const load = useCallback(async () => {
    try { const r = await getQuarantine(); setRecords(r.data); }
    catch (e) { if (e.response?.status === 401) navigate('/login'); }
    finally { setLoading(false); }
  }, [navigate]);

  useEffect(() => { load(); }, [load]);

  const handleRestore = async (id) => {
    if (!window.confirm('Mark this file as restored from quarantine?')) return;
    setActionId(id);
    try { await restoreFile(id); await load(); }
    catch { alert('Action failed.'); }
    finally { setActionId(null); }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Permanently delete this file? Cannot be undone.')) return;
    setActionId(id);
    try { await deleteQuarantine(id); await load(); }
    catch { alert('Delete failed.'); }
    finally { setActionId(null); }
  };

  const typeCounts = records.reduce((acc,r) => {
    if (r.attack_type) acc[r.attack_type] = (acc[r.attack_type]||0)+1;
    return acc;
  }, {});

  const filtered = typeFilter === 'all'
    ? records
    : records.filter(r => r.attack_type === typeFilter);

  return (
    <Layout title="Quarantine Vault" subtitle="Isolated malicious files — attack types identified">
      {/* Stats */}
      <div className="stats-grid" style={{gridTemplateColumns:'repeat(3,1fr)'}}>
        {[
          {label:'Total Quarantined', value:records.length, variant:'red',   icon:'🔒'},
          {label:'Active Threats',    value:records.filter(r=>r.status==='quarantined').length, variant:'red', icon:'☣️'},
          {label:'Restored',          value:records.filter(r=>r.status==='restored').length, variant:'green', icon:'♻️'},
        ].map(s=>(
          <div key={s.label} className={`stat-card ${s.variant}`}>
            <div className="stat-icon">{s.icon}</div>
            <div className="stat-label">{s.label}</div>
            <div className={`stat-value ${s.variant}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Attack type filter pills */}
      <div style={{display:'flex',gap:8,flexWrap:'wrap',margin:'16px 0'}}>
        <button
          className={`btn btn-sm ${typeFilter==='all'?'btn-primary':'btn-outline'}`}
          onClick={()=>setTypeFilter('all')}>All Types</button>
        {Object.entries(ATTACK_META).map(([name,m])=>(
          typeCounts[name] ? (
            <button key={name}
              onClick={()=>setTypeFilter(typeFilter===name?'all':name)}
              style={{
                display:'flex',alignItems:'center',gap:5,padding:'5px 12px',
                borderRadius:20,fontSize:12,fontWeight:700,cursor:'pointer',
                background: typeFilter===name?m.bg:'transparent',
                color: typeFilter===name?m.color:'var(--text-secondary)',
                border:`1px solid ${typeFilter===name?m.border:'var(--border-light)'}`,
              }}>
              {m.icon} {name} <span style={{
                background:m.bg,color:m.color,borderRadius:10,
                padding:'1px 6px',fontSize:10,marginLeft:2
              }}>{typeCounts[name]}</span>
            </button>
          ) : null
        ))}
      </div>

      <div className="card mt-4">
        <div className="card-header">
          <div>
            <div className="card-title">🔒 Quarantined Files</div>
            <div className="card-subtitle">{filtered.length} files isolated — attack types shown</div>
          </div>
          <button className="btn btn-outline btn-sm" onClick={load}>🔄 Refresh</button>
        </div>

        {loading ? (
          <div style={{display:'flex',justifyContent:'center',padding:40}}>
            <div className="loading-spinner" style={{width:32,height:32}}></div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🛡️</div>
            <div className="empty-state-title">No Quarantined Files</div>
            <div className="empty-state-sub">System is clean. No malware detected yet.</div>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Filename</th>
                  <th>Attack Type</th>
                  <th>Confidence</th>
                  <th>Entropy</th>
                  <th>Quarantined At</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r,i)=>{
                  const meta = r.attack_type ? ATTACK_META[r.attack_type] : null;
                  return (
                    <tr key={r.id} style={{
                      borderLeft: meta?`3px solid ${meta.color}`:'none'
                    }}>
                      <td style={{color:'var(--text-muted)',fontSize:12}}>{i+1}</td>
                      <td>
                        <div style={{display:'flex',alignItems:'center',gap:8}}>
                          <span style={{fontSize:18}}>{meta?.icon||'☣️'}</span>
                          <div>
                            <div style={{fontFamily:'JetBrains Mono,monospace',fontSize:11}}>{r.filename}</div>
                            <div style={{fontSize:10,color:'var(--text-muted)'}}>{r.quarantine_path?.split(/[\\/]/).pop()}</div>
                          </div>
                        </div>
                      </td>
                      <td>
                        {r.attack_type
                          ? <AttackBadge type={r.attack_type}/>
                          : <span style={{color:'var(--text-muted)',fontSize:11}}>Unknown</span>}
                      </td>
                      <td>
                        <div style={{display:'flex',alignItems:'center',gap:6}}>
                          <div className="progress-bar-wrap" style={{width:50,height:5}}>
                            <div className="progress-bar red" style={{width:`${r.confidence}%`}}></div>
                          </div>
                          <span style={{fontSize:12}}>{r.confidence?.toFixed(1)}%</span>
                        </div>
                      </td>
                      <td style={{fontFamily:'JetBrains Mono,monospace',fontSize:12}}>{r.entropy?.toFixed(3)}</td>
                      <td style={{fontSize:12}}>{new Date(r.quarantined_at).toLocaleString()}</td>
                      <td>
                        <span className={`badge ${r.status==='quarantined'?'badge-danger':'badge-success'}`}>
                          {r.status==='quarantined'?'🔒 Quarantined':'♻️ Restored'}
                        </span>
                      </td>
                      <td>
                        <div style={{display:'flex',gap:6}}>
                          {r.status==='quarantined'&&(
                            <button className="btn btn-outline btn-sm"
                              onClick={()=>handleRestore(r.id)} disabled={actionId===r.id}>
                              ♻️ Restore
                            </button>
                          )}
                          <button className="btn btn-danger btn-sm"
                            onClick={()=>handleDelete(r.id)} disabled={actionId===r.id}>
                            🗑️ Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}
