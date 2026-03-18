import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip } from 'recharts';
import Layout from '../components/Layout';
import { getModelInfo } from '../api';

export default function ModelInfo() {
  const [info, setInfo]       = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const load = useCallback(async () => {
    try { const r = await getModelInfo(); setInfo(r.data); }
    catch (e) { if (e.response?.status === 401) navigate('/login'); }
    finally { setLoading(false); }
  }, [navigate]);

  useEffect(() => { load(); }, [load]);

  if (loading) return (
    <Layout title="ML Model Info">
      <div style={{ display:'flex', justifyContent:'center', padding:80 }}>
        <div className="loading-spinner" style={{width:40,height:40}}></div>
      </div>
    </Layout>
  );

  const radarData = info ? [
    { metric: 'Accuracy',  value: info.accuracy  },
    { metric: 'Precision', value: info.precision },
    { metric: 'Recall',    value: info.recall    },
    { metric: 'F1-Score',  value: info.f1_score  },
  ] : [];

  const topFeatures = [
    { name: 'high_entropy_code',       importance: 18.6, color: 'var(--accent-red)' },
    { name: 'dll_characteristics',     importance: 16.8, color: 'var(--accent-blue)' },
    { name: 'timestamp_valid',         importance: 14.6, color: 'var(--accent-orange)' },
    { name: 'entropy',                 importance: 14.4, color: 'var(--accent-cyan)' },
    { name: 'file_size',               importance: 12.3, color: 'var(--accent-green)' },
    { name: 'imports_crypto',          importance:  8.1, color: 'var(--accent-purple)' },
    { name: 'imports_network',         importance:  6.4, color: '#f97316' },
    { name: 'suspicious_section_name', importance:  4.2, color: '#ec4899' },
  ];

  return (
    <Layout title="ML Model Info" subtitle="Random Forest classifier details & performance">
      {/* Model stats */}
      <div className="stats-grid">
        {[
          { label: 'Accuracy',     value: `${info?.accuracy}%`,  variant: 'green',  icon: '🎯' },
          { label: 'Precision',    value: `${info?.precision}%`, variant: 'blue',   icon: '📏' },
          { label: 'Recall',       value: `${info?.recall}%`,    variant: 'blue',   icon: '🔁' },
          { label: 'F1-Score',     value: `${info?.f1_score}%`,  variant: 'green',  icon: '⚡' },
        ].map(s => (
          <div key={s.label} className={`stat-card ${s.variant}`}>
            <div className="stat-icon">{s.icon}</div>
            <div className="stat-label">{s.label}</div>
            <div className={`stat-value ${s.variant}`}>{s.value}</div>
          </div>
        ))}
      </div>

      <div className="grid-2 mt-6">
        {/* Model details */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">🤖 Model Configuration</div>
          </div>
          {[
            { label: 'Algorithm',          value: 'Random Forest Classifier' },
            { label: 'Number of Trees',    value: `${info?.n_estimators} estimators` },
            { label: 'Max Features',       value: 'sqrt (auto)' },
            { label: 'Dataset',            value: info?.dataset },
            { label: 'Training Classes',   value: info?.classes?.join(' / ') },
            { label: 'Feature Count',      value: `${info?.features?.length} features` },
          ].map(item => (
            <div key={item.label} style={{
              display:'flex', justifyContent:'space-between',
              padding:'11px 0', borderBottom:'1px solid var(--border)',
              fontSize:13, alignItems:'center'
            }}>
              <span style={{color:'var(--text-muted)'}}>{item.label}</span>
              <span style={{fontWeight:600, color:'var(--text-primary)'}}>{item.value}</span>
            </div>
          ))}
        </div>

        {/* Radar chart */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">📡 Performance Radar</div>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#1e2d4d" />
              <PolarAngleAxis dataKey="metric" tick={{ fontSize:12, fill:'#94a3b8' }} />
              <Radar
                dataKey="value" stroke="#3b82f6" fill="#3b82f6"
                fillOpacity={0.25} strokeWidth={2}
              />
              <Tooltip
                contentStyle={{ background:'#141c2f', border:'1px solid #1e2d4d', borderRadius:8, fontSize:12 }}
                formatter={v => [`${v}%`]}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Feature importance */}
      <div className="card mt-6">
        <div className="card-header">
          <div>
            <div className="card-title">📊 Feature Importance</div>
            <div className="card-subtitle">Top features used by Random Forest for classification</div>
          </div>
        </div>
        <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
          {topFeatures.map((f, i) => (
            <div key={f.name} style={{ display:'flex', alignItems:'center', gap:14 }}>
              <span style={{
                width:22, height:22, background:f.color, borderRadius:'50%',
                display:'flex', alignItems:'center', justifyContent:'center',
                fontSize:11, fontWeight:700, color:'#fff', flexShrink:0
              }}>{i+1}</span>
              <span style={{ fontFamily:'JetBrains Mono,monospace', fontSize:12, color:'var(--text-secondary)', width:200, flexShrink:0 }}>
                {f.name}
              </span>
              <div style={{ flex:1 }}>
                <div className="progress-bar-wrap">
                  <div className="progress-bar blue" style={{ width:`${(f.importance/20)*100}%`, background:f.color }}></div>
                </div>
              </div>
              <span style={{ fontWeight:700, fontSize:13, width:50, textAlign:'right', color: f.color }}>
                {f.importance}%
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* All features list */}
      <div className="card mt-6">
        <div className="card-header">
          <div className="card-title">🔬 All Extracted Features ({info?.features?.length})</div>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8 }}>
          {info?.features?.map(f => (
            <div key={f} style={{
              background:'var(--bg-secondary)', border:'1px solid var(--border)',
              borderRadius:6, padding:'8px 12px',
              fontFamily:'JetBrains Mono,monospace', fontSize:11,
              color:'var(--text-secondary)'
            }}>
              {f}
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
