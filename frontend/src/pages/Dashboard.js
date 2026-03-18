import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer
} from 'recharts';
import Layout from '../components/Layout';
import { getStats } from '../api';
import axios from 'axios';

const api = axios.create({ baseURL: '/api', withCredentials: true });

const MALWARE_COLORS = {
  Trojan:     '#ef4444',
  Ransomware: '#f97316',
  Backdoor:   '#8b5cf6',
  Worm:       '#06b6d4',
  Spyware:    '#f59e0b',
};
const PIE_COLORS     = ['#10b981','#ef4444'];
const HEATMAP_COLORS = ['#0f1628','#1a3a2a','#1a6b1a','#f59e0b','#ef4444'];

/* ─── Tooltip ────────────────────────────────────────────────────────────── */
const DarkTip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:'#0f1628', border:'1px solid #1e2d4d', borderRadius:8, padding:'10px 14px', fontSize:12 }}>
      {label && <div style={{ fontWeight:700, marginBottom:5, color:'#e2e8f0' }}>{label}</div>}
      {payload.map((p,i) => (
        <div key={i} style={{ color:p.color||'#94a3b8', marginBottom:2 }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

/* ─── NIST Gauge ─────────────────────────────────────────────────────────── */
function RiskGauge({ score, level, color }) {
  const r = 52, cx = 68, cy = 68, circ = 2*Math.PI*r;
  const arc = circ * 0.75, fill = arc * (score/100);
  return (
    <div style={{ textAlign:'center' }}>
      <svg width={136} height={100} viewBox="0 0 136 100">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e2d4d" strokeWidth={10}
          strokeDasharray={`${arc} ${circ}`} strokeDashoffset={-(circ*0.125)}
          strokeLinecap="round" transform={`rotate(135 ${cx} ${cy})`} />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${fill} ${circ}`} strokeDashoffset={-(circ*0.125)}
          strokeLinecap="round" transform={`rotate(135 ${cx} ${cy})`}
          style={{ transition:'stroke-dasharray 0.7s ease' }} />
        <text x={cx} y={cy-3} textAnchor="middle" fill="#e2e8f0" fontSize={22} fontWeight={800}>{score}</text>
        <text x={cx} y={cy+14} textAnchor="middle" fill={color} fontSize={11} fontWeight={700}>{level}</text>
      </svg>
      <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:2 }}>NIST Risk Score</div>
    </div>
  );
}

/* ─── Heatmap cell ───────────────────────────────────────────────────────── */
function HCell({ value, max }) {
  const i   = max === 0 ? 0 : Math.round((value / max) * 4);
  const bg  = HEATMAP_COLORS[Math.min(i, 4)];
  const txt = i >= 3 ? '#fff' : '#94a3b8';
  return (
    <td style={{
      background:bg, color:txt, fontWeight:600, fontSize:12,
      textAlign:'center', padding:'5px 8px',
      border:'2px solid #0a0e1a', borderRadius:3, minWidth:48
    }}>{value}</td>
  );
}

/* ─── Live event row ─────────────────────────────────────────────────────── */
function LiveRow({ event, isNew }) {
  return (
    <div style={{
      display:'flex', alignItems:'center', gap:10, padding:'9px 16px',
      borderBottom:'1px solid rgba(30,45,77,0.5)', fontSize:12,
      background: isNew ? 'rgba(239,68,68,0.07)' : 'transparent',
      transition:'background 1.5s ease',
      animation: isNew ? 'slideDown 0.3s ease' : undefined
    }}>
      <span style={{ fontSize:16 }}>{event.prediction==='Malware' ? '☣️' : '✅'}</span>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{
          color:'var(--text-primary)', fontWeight:500, overflow:'hidden',
          textOverflow:'ellipsis', whiteSpace:'nowrap',
          fontFamily:'JetBrains Mono, monospace', fontSize:11
        }}>{event.filename}</div>
        <div style={{ color:'var(--text-muted)', fontSize:10, marginTop:1 }}>
          {event.malware_type && (
            <span style={{ color:MALWARE_COLORS[event.malware_type]||'#f97316', fontWeight:700, marginRight:6 }}>
              {event.malware_type}
            </span>
          )}
          {event.industry} · {new Date(event.scan_time).toLocaleTimeString()}
        </div>
      </div>
      <span style={{
        padding:'2px 8px', borderRadius:20, fontSize:10, fontWeight:700,
        background: event.prediction==='Malware' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
        color:       event.prediction==='Malware' ? '#f87171' : '#34d399',
        border: `1px solid ${event.prediction==='Malware' ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)'}`
      }}>
        {event.prediction==='Malware' ? `${event.confidence?.toFixed(0)}%` : 'Safe'}
      </span>
    </div>
  );
}

/* ═══════════════════════ DASHBOARD ═══════════════════════════════════════ */
export default function Dashboard() {
  const [stats,    setStats]    = useState(null);
  const [adv,      setAdv]      = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [liveNew,  setLiveNew]  = useState(new Set());
  const prevIds    = useRef(new Set());
  const navigate   = useNavigate();

  const loadAll = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([getStats(), api.get('/advanced_stats')]);
      setStats(s.data);
      const adData = a.data;
      // detect new events
      const nowIds = new Set(adData.live_events.map(e => e.id));
      const fresh  = new Set([...nowIds].filter(id => !prevIds.current.has(id)));
      prevIds.current = nowIds;
      if (fresh.size) setLiveNew(fresh);
      setAdv(adData);
    } catch (e) { if (e.response?.status === 401) navigate('/login'); }
    finally { setLoading(false); }
  }, [navigate]);

  useEffect(() => {
    loadAll();
    const t = setInterval(loadAll, 5000);
    return () => clearInterval(t);
  }, [loadAll]);

  useEffect(() => {
    if (!liveNew.size) return;
    const t = setTimeout(() => setLiveNew(new Set()), 3000);
    return () => clearTimeout(t);
  }, [liveNew]);

  const simulateMulti = async (count) => {
    try { await api.post('/simulate_multi', { count }); await loadAll(); }
    catch {}
  };

  /* ── Early returns ─────────────────────────────────────────────────── */
  if (loading) return (
    <Layout title="SOC Dashboard — BankShield AI" subtitle="Live threat monitoring">
      <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:300, gap:12 }}>
        <div className="loading-spinner" style={{ width:32, height:32 }}></div>
        <span style={{ color:'var(--text-muted)' }}>Loading live dashboard…</span>
      </div>
    </Layout>
  );

  const risk         = adv?.risk_score    || { score:0, level:'Low', color:'#10b981' };
  const csf          = adv?.csf_metrics   || {};
  const imp          = adv?.impact        || {};
  const hmap         = adv?.heatmap       || [];
  const malTypes     = adv?.malware_types || [];
  const industryData = adv?.industry_data || [];
  const liveEvents   = adv?.live_events   || [];
  const pieData      = [
    { name:'Safe',    value: adv?.safe_count    || 0 },
    { name:'Malware', value: adv?.malware_count || 0 },
  ];
  const weeks  = ['Week 1','Week 2','Week 3','Week 4'];
  const hmMax  = hmap.reduce((m, r) => Math.max(m, ...weeks.map(w => r[w] || 0)), 0);

  return (
    <Layout
      title="Live Security Dashboard"
      subtitle={`⚡ Auto-refresh every 5s · ${adv?.total_scans || 0} total scans processed`}
      actions={
        <div style={{ display:'flex', gap:8 }}>
          <button className="btn btn-outline btn-sm" onClick={loadAll}>🔄 Refresh</button>
          <button className="btn btn-danger btn-sm" onClick={() => simulateMulti(10)}>⚡ Simulate 10 Attacks (All Types)</button>
        </div>
      }
    >

      {/* ── 1. KPI CARDS ───────────────────────────────────────────────── */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:12, marginBottom:20 }}>
        {[
          { label:'Total Scans',     value: adv?.total_scans    || 0, v:'blue',   icon:'📁' },
          { label:'Total Risks',     value: adv?.malware_count  || 0, v:'red',    icon:'☣️' },
          { label:'Severe Detections',value:adv?.severe_count   || 0, v:'red',    icon:'🚨' },
          { label:'Safe Files',      value: adv?.safe_count     || 0, v:'green',  icon:'✅' },
          { label:'Quarantined',     value: stats?.quarantined  || 0, v:'orange', icon:'🔒' },
          { label:'Detection Rate',  value:`${imp.detection_rate||0}%`,v:'blue',  icon:'🎯' },
        ].map(c => (
          <div key={c.label} className={`stat-card ${c.v}`}>
            <div className="stat-icon">{c.icon}</div>
            <div className="stat-label">{c.label}</div>
            <div className={`stat-value ${c.v}`} style={{ fontSize:26 }}>{c.value}</div>
          </div>
        ))}
      </div>

      {/* ── 2. NIST GAUGE + MALWARE TYPES + PIE ────────────────────────── */}
      <div style={{ display:'grid', gridTemplateColumns:'210px 1fr 290px', gap:16, marginBottom:20 }}>

        {/* NIST Gauge */}
        <div className="card" style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:8 }}>
          <div style={{ fontSize:11, fontWeight:700, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:1 }}>
            Overall Risk Score
          </div>
          <RiskGauge score={risk.score} level={risk.level} color={risk.color} />
          <div style={{
            padding:'4px 14px', borderRadius:20,
            background:`${risk.color}22`, color:risk.color,
            border:`1px solid ${risk.color}44`, fontSize:12, fontWeight:700
          }}>{risk.level} Risk</div>
        </div>

        {/* Malware Type Breakdown */}
        <div className="card">
          <div className="card-header" style={{ marginBottom:10 }}>
            <div>
              <div className="card-title">Malware Type Breakdown</div>
              <div className="card-subtitle">
                {malTypes.map(t=>`${t.name}: ${t.pct}%`).join(' · ')}
              </div>
            </div>
          </div>
          {malTypes.every(t => t.value === 0) ? (
            <div className="empty-state" style={{ padding:'18px 0' }}>
              <div style={{ fontSize:28 }}>🛡️</div>
              <div className="empty-state-title" style={{ marginTop:6, fontSize:13 }}>No malware detected yet</div>
              <div className="empty-state-sub">Click "Simulate Attacks" to populate</div>
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <BarChart data={malTypes} layout="vertical" barSize={13}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4d" horizontal={false}/>
                  <XAxis type="number" stroke="#64748b" tick={{ fontSize:10 }}/>
                  <YAxis dataKey="name" type="category" stroke="#64748b" tick={{ fontSize:11 }} width={82}/>
                  <Tooltip content={<DarkTip/>}/>
                  <Bar dataKey="value" name="Count" radius={[0,4,4,0]}>
                    {malTypes.map(t => <Cell key={t.name} fill={MALWARE_COLORS[t.name]||'#3b82f6'}/>)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div style={{ display:'flex', flexWrap:'wrap', gap:8, marginTop:8 }}>
                {malTypes.map(t => (
                  <span key={t.name} style={{ fontSize:11, display:'flex', alignItems:'center', gap:4 }}>
                    <span style={{ width:7, height:7, borderRadius:'50%', background:MALWARE_COLORS[t.name], display:'inline-block' }}></span>
                    <span style={{ color:'var(--text-muted)' }}>{t.name}</span>
                    <strong style={{ color:MALWARE_COLORS[t.name] }}>{t.pct}%</strong>
                  </span>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Threat Pie + mini impact */}
        <div className="card">
          <div className="card-title" style={{ marginBottom:6, fontSize:14 }}>Threat Distribution</div>
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={38} outerRadius={60}
                paddingAngle={3} dataKey="value">
                {pieData.map((_,i) => <Cell key={i} fill={PIE_COLORS[i]}/>)}
              </Pie>
              <Tooltip content={<DarkTip/>}/>
              <Legend wrapperStyle={{ fontSize:11 }} iconSize={8}/>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:6, marginTop:6 }}>
            {[
              { l:'Avg Confidence', v:`${imp.avg_confidence||0}%`,    c:'#ef4444' },
              { l:'Quarantine Rate',v:`${imp.quarantine_rate||0}%`,   c:'#f59e0b' },
              { l:'Severe Rate',    v:`${imp.severe_rate||0}%`,       c:'#ef4444' },
              { l:'Avg Entropy',    v:(imp.avg_entropy||0).toFixed(2),c:'#06b6d4' },
            ].map(m => (
              <div key={m.l} style={{
                background:'var(--bg-secondary)', borderRadius:6,
                padding:'7px 9px', border:'1px solid var(--border)'
              }}>
                <div style={{ fontSize:9, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:0.4 }}>{m.l}</div>
                <div style={{ fontSize:15, fontWeight:800, color:m.c, marginTop:2 }}>{m.v}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── 3. LIVE FEED + CSF RADAR ────────────────────────────────────── */}
      <div className="grid-2" style={{ marginBottom:20 }}>

        {/* Live monitoring feed */}
        <div className="card" style={{ padding:0, overflow:'hidden' }}>
          <div style={{
            padding:'13px 18px', borderBottom:'1px solid var(--border)',
            display:'flex', alignItems:'center', justifyContent:'space-between'
          }}>
            <div style={{ display:'flex', alignItems:'center', gap:8 }}>
              <span style={{
                width:8, height:8, borderRadius:'50%', background:'#ef4444',
                display:'inline-block', animation:'pulse 1.5s infinite'
              }}></span>
              <div>
                <div style={{ fontSize:14, fontWeight:700 }}>🔴 Live Monitoring Feed</div>
                <div style={{ fontSize:11, color:'var(--text-muted)' }}>Auto-refreshing · real-time events</div>
              </div>
            </div>
            <span style={{ fontSize:11, color:'var(--text-muted)' }}>{liveEvents.length} events</span>
          </div>
          <div style={{ maxHeight:310, overflowY:'auto' }}>
            {liveEvents.length === 0 ? (
              <div className="empty-state" style={{ padding:'40px 20px' }}>
                <div style={{ fontSize:32 }}>📡</div>
                <div className="empty-state-title" style={{ marginTop:8 }}>Monitoring Active</div>
                <div className="empty-state-sub">Waiting for scan events…<br/>Click "Simulate Attacks" to test</div>
              </div>
            ) : liveEvents.map(ev => (
              <LiveRow key={ev.id} event={ev} isNew={liveNew.has(ev.id)}/>
            ))}
          </div>
        </div>

        {/* NIST CSF Maturity */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">🛡️ NIST CSF Maturity Metrics</div>
              <div className="card-subtitle">Identify · Protect · Detect · Respond · Recover</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={210}>
            <RadarChart data={Object.entries(csf).map(([k,v]) => ({ metric:k, value:v }))}>
              <PolarGrid stroke="#1e2d4d"/>
              <PolarAngleAxis dataKey="metric" tick={{ fontSize:12, fill:'#94a3b8' }}/>
              <Radar dataKey="value" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.25} strokeWidth={2}/>
              <Tooltip content={<DarkTip/>} formatter={v => [`${v}%`]}/>
            </RadarChart>
          </ResponsiveContainer>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginTop:4 }}>
            {Object.entries(csf).map(([k,v]) => (
              <div key={k} style={{
                flex:'1 1 70px', background:'var(--bg-secondary)', borderRadius:6,
                padding:'7px 10px', border:'1px solid var(--border)'
              }}>
                <div style={{ fontSize:9, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:0.5 }}>{k}</div>
                <div style={{
                  fontSize:16, fontWeight:800, marginTop:2,
                  color: v>=70 ? '#10b981' : v>=40 ? '#f59e0b' : '#ef4444'
                }}>{v}%</div>
                <div className="progress-bar-wrap" style={{ marginTop:4, height:4 }}>
                  <div className="progress-bar" style={{
                    width:`${v}%`, height:'100%', borderRadius:10,
                    background: v>=70 ? '#10b981' : v>=40 ? '#f59e0b' : '#ef4444',
                    transition:'width 0.5s ease'
                  }}></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── 4. INDUSTRY CHART + 7-DAY TREND ─────────────────────────────── */}
      <div className="grid-2" style={{ marginBottom:20 }}>

        {/* Industry attack distribution */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">🏭 Industry Attack Distribution</div>
              <div className="card-subtitle">Sectors targeted — color = risk level</div>
            </div>
          </div>
          {industryData.every(d => d.attacks === 0) ? (
            <div className="empty-state" style={{ padding:'30px 0' }}>
              <div style={{ fontSize:32 }}>🏭</div>
              <div className="empty-state-title" style={{ marginTop:8 }}>No industry data yet</div>
              <div className="empty-state-sub">Simulate attacks to populate chart</div>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={industryData.slice(0,6)}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4d"/>
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize:10 }} angle={-25} textAnchor="end" height={50}/>
                <YAxis stroke="#64748b" tick={{ fontSize:10 }}/>
                <Tooltip content={<DarkTip/>}/>
                <Bar dataKey="attacks" name="Attacks" radius={[4,4,0,0]}>
                  {industryData.slice(0,6).map((d,i) => (
                    <Cell key={i} fill={ d.risk>=60?'#ef4444':d.risk>=30?'#f59e0b':'#10b981' }/>
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* 7-day trend */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">📈 7-Day Scan Trend</div>
          </div>
          {(stats?.daily_trend||[]).length === 0 ? (
            <div className="empty-state" style={{ padding:'30px 0' }}>
              <div style={{ fontSize:32 }}>📈</div>
              <div className="empty-state-title" style={{ marginTop:8 }}>No trend data yet</div>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={stats.daily_trend}>
                <defs>
                  <linearGradient id="gB" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="gR" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4d"/>
                <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize:10 }}/>
                <YAxis stroke="#64748b" tick={{ fontSize:10 }}/>
                <Tooltip content={<DarkTip/>}/>
                <Legend wrapperStyle={{ fontSize:11 }}/>
                <Area type="monotone" dataKey="count"   name="Total Scans" stroke="#3b82f6" fill="url(#gB)" strokeWidth={2}/>
                <Area type="monotone" dataKey="malware" name="Malware"      stroke="#ef4444" fill="url(#gR)" strokeWidth={2}/>
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── 5. COMPANY RISK HEATMAP ──────────────────────────────────────── */}
      <div className="card" style={{ marginBottom:20 }}>
        <div className="card-header">
          <div>
            <div className="card-title">🔥 Company Risk Heatmap (Department × Week)</div>
            <div className="card-subtitle" style={{ display:'flex', alignItems:'center', gap:14, flexWrap:'wrap' }}>
              Risk color coding:&nbsp;
              {[['None','#0f1628'],['Low','#1a6b1a'],['Medium','#f59e0b'],['High','#ef4444']].map(([l,c])=>(
                <span key={l} style={{ display:'inline-flex', alignItems:'center', gap:4 }}>
                  <span style={{ width:10, height:10, background:c, borderRadius:2, border:'1px solid #1e2d4d', display:'inline-block' }}></span>
                  <span style={{ color:'var(--text-muted)', fontSize:11 }}>{l}</span>
                </span>
              ))}
            </div>
          </div>
        </div>
        {hmap.length === 0 ? (
          <div className="empty-state" style={{ padding:'28px 0' }}>
            <div style={{ fontSize:32 }}>🔥</div>
            <div className="empty-state-title" style={{ marginTop:8 }}>Heatmap loads after first scan</div>
          </div>
        ) : (
          <div style={{ overflowX:'auto' }}>
            <table style={{ borderCollapse:'separate', borderSpacing:3, width:'100%' }}>
              <thead>
                <tr>
                  <th style={{ textAlign:'left', fontSize:11, color:'var(--text-muted)', padding:'4px 8px', fontWeight:600 }}>Department</th>
                  {weeks.map(w => <th key={w} style={{ fontSize:11, color:'var(--text-muted)', padding:'4px 8px', fontWeight:600, textAlign:'center' }}>{w}</th>)}
                  <th style={{ fontSize:11, color:'var(--text-muted)', padding:'4px 8px', fontWeight:600, textAlign:'center' }}>Total</th>
                </tr>
              </thead>
              <tbody>
                {hmap.map(row => (
                  <tr key={row.dept}>
                    <td style={{ fontSize:12, fontWeight:600, color:'var(--text-secondary)', padding:'4px 8px', whiteSpace:'nowrap' }}>
                      {row.dept}
                    </td>
                    {weeks.map(w => <HCell key={w} value={row[w]||0} max={hmMax}/>)}
                    <td style={{
                      padding:'5px 8px', fontWeight:800, fontSize:14, textAlign:'center',
                      color: row.total>=(hmMax*0.7)?'#ef4444':row.total>=(hmMax*0.4)?'#f59e0b':'#10b981'
                    }}>{row.total}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── 6. IMPACT METRICS ────────────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">📊 Impact Metrics Summary</div>
          <div className="card-subtitle">Aggregated system-wide security metrics</div>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:12 }}>
          {[
            { label:'Detection Rate',   val:`${imp.detection_rate||0}%`,  icon:'🎯', color:'#3b82f6', desc:'% files flagged malware' },
            { label:'Avg ML Confidence',val:`${imp.avg_confidence||0}%`,  icon:'🔬', color:'#ef4444', desc:'Model confidence on threats' },
            { label:'Quarantine Rate',  val:`${imp.quarantine_rate||0}%`, icon:'🔒', color:'#f59e0b', desc:'Threats auto-isolated' },
            { label:'Severe Rate',      val:`${imp.severe_rate||0}%`,     icon:'🚨', color:'#ef4444', desc:'Critical detections ≥85%' },
            { label:'Avg File Entropy', val:(imp.avg_entropy||0).toFixed(3),icon:'📐',color:'#06b6d4', desc:'Mean entropy of threats' },
          ].map(m => (
            <div key={m.label} style={{
              background:'var(--bg-secondary)', border:'1px solid var(--border)',
              borderRadius:10, padding:'16px', position:'relative', overflow:'hidden'
            }}>
              <div style={{ position:'absolute', top:12, right:12, fontSize:24, opacity:0.12 }}>{m.icon}</div>
              <div style={{ fontSize:10, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:0.5, marginBottom:7 }}>{m.label}</div>
              <div style={{ fontSize:28, fontWeight:800, color:m.color, marginBottom:5 }}>{m.val}</div>
              <div style={{ fontSize:10, color:'var(--text-muted)' }}>{m.desc}</div>
              <div className="progress-bar-wrap" style={{ marginTop:10, height:4 }}>
                <div style={{
                  height:'100%', borderRadius:10, background:m.color, opacity:0.7,
                  width: m.val.toString().includes('%') ? m.val : '50%',
                  transition:'width 0.5s ease'
                }}></div>
              </div>
            </div>
          ))}
        </div>
      </div>

    </Layout>
  );
}
