import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import { AttackBadge, AttackCard, ATTACK_META } from '../components/AttackBadge';
import { getLogs } from '../api';

export default function Alerts() {
  const [alerts,    setAlerts]    = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [dismissed, setDismissed] = useState(new Set());
  const [typeFilter,setTypeFilter]= useState('all');
  const navigate = useNavigate();

  const load = useCallback(async () => {
    try {
      const r = await getLogs();
      setAlerts(r.data.filter(l=>l.prediction==='Malware'));
    } catch (e) { if (e.response?.status === 401) navigate('/login'); }
    finally { setLoading(false); }
  }, [navigate]);

  useEffect(() => { load(); }, [load]);

  const getSeverity = (conf) => {
    if (conf >= 90) return {label:'CRITICAL', color:'#ef4444', bg:'rgba(239,68,68,0.1)'};
    if (conf >= 75) return {label:'HIGH',     color:'#f97316', bg:'rgba(249,115,22,0.1)'};
    return              {label:'MEDIUM',  color:'#f59e0b', bg:'rgba(245,158,11,0.1)'};
  };

  const typeCounts = alerts.reduce((acc,a)=>{
    if (a.attack_type) acc[a.attack_type] = (acc[a.attack_type]||0)+1;
    return acc;
  },{});

  const visible = alerts.filter(a =>
    !dismissed.has(a.id) &&
    (typeFilter==='all' || a.attack_type===typeFilter)
  );

  return (
    <Layout title="Security Alerts" subtitle="Real-time banking threat alerts — SWIFT, ATM, Payment Gateway, Core Banking">
      {/* Stats */}
      <div className="stats-grid" style={{gridTemplateColumns:'repeat(4,1fr)'}}>
        {[
          {label:'Total Alerts',    value:alerts.length,                               variant:'red',    icon:'🚨'},
          {label:'Critical (≥90%)', value:alerts.filter(a=>a.confidence>=90).length,   variant:'red',    icon:'☣️'},
          {label:'Active Alerts',   value:visible.length,                              variant:'orange', icon:'⚠️'},
          {label:'Attack Types',    value:Object.keys(typeCounts).length,              variant:'blue',   icon:'🔎'},
        ].map(s=>(
          <div key={s.label} className={`stat-card ${s.variant}`}>
            <div className="stat-icon">{s.icon}</div>
            <div className="stat-label">{s.label}</div>
            <div className={`stat-value ${s.variant}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Attack type breakdown */}
      {Object.keys(typeCounts).length > 0 && (
        <div style={{display:'flex',gap:10,flexWrap:'wrap',margin:'16px 0'}}>
          <button className={`btn btn-sm ${typeFilter==='all'?'btn-primary':'btn-outline'}`}
            onClick={()=>setTypeFilter('all')}>All</button>
          {Object.entries(typeCounts).map(([name,count])=>{
            const m = ATTACK_META[name];
            if (!m) return null;
            return (
              <button key={name} onClick={()=>setTypeFilter(typeFilter===name?'all':name)}
                style={{
                  display:'flex',alignItems:'center',gap:5,padding:'5px 12px',
                  borderRadius:20,fontSize:12,fontWeight:700,cursor:'pointer',
                  background:typeFilter===name?m.bg:'transparent',
                  color:typeFilter===name?m.color:'var(--text-secondary)',
                  border:`1px solid ${typeFilter===name?m.border:'var(--border-light)'}`,
                }}>
                {m.icon} {name} ({count})
              </button>
            );
          })}
        </div>
      )}

      <div className="card mt-4">
        <div className="card-header">
          <div>
            <div className="card-title">⚠️ Security Alerts</div>
            <div className="card-subtitle">{visible.length} active alerts — attack types identified</div>
          </div>
          <div style={{display:'flex',gap:8}}>
            <button className="btn btn-outline btn-sm"
              onClick={()=>setDismissed(new Set(alerts.map(a=>a.id)))}>
              Dismiss All
            </button>
            <button className="btn btn-outline btn-sm" onClick={load}>🔄</button>
          </div>
        </div>

        {loading ? (
          <div style={{display:'flex',justifyContent:'center',padding:40}}>
            <div className="loading-spinner" style={{width:32,height:32}}></div>
          </div>
        ) : visible.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🛡️</div>
            <div className="empty-state-title">No Active Alerts</div>
            <div className="empty-state-sub">
              {alerts.length>0?'All alerts dismissed.':'No malware detected. System is secure.'}
            </div>
          </div>
        ) : (
          <div style={{display:'flex',flexDirection:'column',gap:12}}>
            {visible.map(alert=>{
              const sev  = getSeverity(alert.confidence);
              const meta = alert.attack_type ? ATTACK_META[alert.attack_type] : null;
              return (
                <div key={alert.id} style={{
                  background:sev.bg,
                  border:`1px solid ${sev.color}40`,
                  borderLeft:`4px solid ${sev.color}`,
                  borderRadius:10, padding:'16px 20px',
                  animation:'fadeIn 0.3s ease'
                }}>
                  <div style={{display:'flex',alignItems:'flex-start',gap:14}}>
                    <div style={{fontSize:28,flexShrink:0}}>{meta?.icon||'☣️'}</div>
                    <div style={{flex:1}}>
                      {/* Title row */}
                      <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:8,flexWrap:'wrap'}}>
                        <span style={{
                          background:sev.color,color:'#fff',fontSize:10,fontWeight:700,
                          padding:'2px 8px',borderRadius:20,letterSpacing:1
                        }}>{sev.label}</span>
                        {alert.attack_type && <AttackBadge type={alert.attack_type}/>}
                        <span style={{fontWeight:700,fontSize:14}}>
                          {alert.attack_type||'Malware'} Detected — {alert.filename}
                        </span>
                      </div>

                      {/* Attack description */}
                      {meta && (
                        <div style={{
                          fontSize:12,color:meta.color,fontWeight:500,
                          marginBottom:8,padding:'4px 0'
                        }}>
                          {meta.icon} {meta.desc}
                        </div>
                      )}

                      {/* Details */}
                      <div style={{fontSize:12,color:'var(--text-muted)',display:'flex',gap:16,flexWrap:'wrap'}}>
                        <span>🎯 Confidence: <strong style={{color:'var(--text-secondary)'}}>{alert.confidence?.toFixed(1)}%</strong></span>
                        <span>🔬 Entropy: <strong style={{color:'var(--text-secondary)'}}>{alert.entropy?.toFixed(3)}</strong></span>
                        <span>📁 Size: <strong style={{color:'var(--text-secondary)'}}>{((alert.file_size||0)/1024).toFixed(1)} KB</strong></span>
                        <span>🔒 Quarantined: <strong style={{color:alert.is_quarantined?'var(--accent-green)':'var(--accent-red)'}}>
                          {alert.is_quarantined?'Yes':'No'}
                        </strong></span>
                        <span>🕒 {new Date(alert.scan_time).toLocaleString()}</span>
                      </div>
                    </div>

                    <button className="btn btn-outline btn-sm" style={{flexShrink:0}}
                      onClick={()=>setDismissed(d=>new Set([...d,alert.id]))}>
                      ✕
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Layout>
  );
}
