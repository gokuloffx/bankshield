import React, { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import { AttackBadge, AttackCard, ATTACK_META } from '../components/AttackBadge';
import { scanFile, simulateAttack } from '../api';

const DISPLAY_FEATURES = [
  { key:'file_size',          label:'File Size',          fmt: v=>`${(v/1024).toFixed(1)} KB` },
  { key:'entropy',            label:'Entropy',            fmt: v=>v.toFixed(4) },
  { key:'num_sections',       label:'PE Sections',        fmt: v=>v },
  { key:'num_imports',        label:'Imports',            fmt: v=>v },
  { key:'is_packed',          label:'Packed',             fmt: v=>v?'Yes ⚠️':'No' },
  { key:'imports_crypto',     label:'Crypto Imports',     fmt: v=>v?'Yes ⚠️':'No' },
  { key:'imports_network',    label:'Net Imports',        fmt: v=>v?'Yes ⚠️':'No' },
  { key:'imports_registry',   label:'Registry Imports',   fmt: v=>v?'Yes ⚠️':'No' },
  { key:'high_entropy_code',  label:'High Entropy',       fmt: v=>v?'Yes ⚠️':'No' },
  { key:'timestamp_valid',    label:'Timestamp Valid',    fmt: v=>v?'Yes ✅':'No ❌' },
  { key:'suspicious_section_name', label:'Susp. Sections',fmt: v=>v?'Yes ⚠️':'No' },
  { key:'has_debug',          label:'Debug Info',         fmt: v=>v?'Yes':'No' },
];

// Maps which features caused this attack type classification
const ATTACK_INDICATORS = {
  Ransomware: ['imports_crypto','high_entropy_code','is_packed','entropy'],
  Trojan:     ['num_imports','suspicious_section_name','imports_network','imports_registry'],
  Backdoor:   ['is_packed','imports_network','imports_registry','suspicious_section_name'],
  Worm:       ['imports_network','num_imports'],
  Spyware:    ['imports_registry','is_packed','high_entropy_code'],
};

export default function Scanner() {
  const [dragging,   setDragging]   = useState(false);
  const [file,       setFile]       = useState(null);
  const [scanning,   setScanning]   = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [result,     setResult]     = useState(null);
  const [error,      setError]      = useState('');
  const fileRef  = useRef();
  const navigate = useNavigate();

  const handleFile = (f) => { setFile(f); setResult(null); setError(''); };

  const handleDrop = useCallback(e => {
    e.preventDefault(); setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, []);

  const handleScan = async () => {
    if (!file) return;
    setScanning(true); setError(''); setResult(null);
    try {
      const r = await scanFile(file);
      setResult(r.data);
    } catch (e) {
      if (e.response?.status === 401) { navigate('/login'); return; }
      setError(e.response?.data?.error || 'Scan failed.');
    } finally { setScanning(false); }
  };

  const handleSimulate = async () => {
    setSimulating(true); setError(''); setResult(null); setFile(null);
    try {
      const r = await simulateAttack();
      setResult(r.data);
    } catch (e) {
      if (e.response?.status === 401) { navigate('/login'); return; }
      setError('Simulation failed.');
    } finally { setSimulating(false); }
  };

  const isMalware  = result?.prediction === 'Malware';
  const attackType = result?.attack_type;
  const meta       = attackType ? ATTACK_META[attackType] : null;
  const indicators = attackType ? ATTACK_INDICATORS[attackType] || [] : [];

  return (
    <Layout
      title="Banking Threat Scanner"
      subtitle="Upload files to detect banking malware — Ransomware, Trojans, Backdoors targeting financial systems"
      actions={
        <button className="btn btn-danger" onClick={handleSimulate} disabled={simulating}>
          {simulating
            ? <><span className="loading-spinner" style={{width:14,height:14}}></span> Simulating…</>
            : '⚡ Simulate Attack'}
        </button>
      }
    >
      <div className="grid-2">
        {/* ── Upload zone ── */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">🔍 Upload & Scan File</div>
              <div className="card-subtitle">Detects malware AND identifies the attack type</div>
            </div>
          </div>

          <div
            className={`upload-zone${dragging ? ' drag-over' : ''}`}
            onDragOver={e=>{e.preventDefault();setDragging(true);}}
            onDragLeave={()=>setDragging(false)}
            onDrop={handleDrop}
            onClick={()=>fileRef.current?.click()}
          >
            <input ref={fileRef} type="file" hidden
              onChange={e=>e.target.files[0]&&handleFile(e.target.files[0])}/>
            <div className="upload-icon">{file?'📄':'📂'}</div>
            {file ? (
              <>
                <div className="upload-title" style={{color:'var(--accent-blue)'}}>{file.name}</div>
                <div className="upload-sub">{(file.size/1024).toFixed(1)} KB — Ready to scan</div>
              </>
            ) : (
              <>
                <div className="upload-title">Drop file here or click to browse</div>
                <div className="upload-sub">Targets: Core Banking · SWIFT · ATM Network · Payment Gateway · Card Data</div>
              </>
            )}
            <button className="btn btn-primary" onClick={e=>{e.stopPropagation();fileRef.current?.click();}}>
              📁 Choose File
            </button>
          </div>

          {error && <div className="alert alert-danger mt-4">⚠️ {error}</div>}

          {file && (
            <button className="btn btn-primary" disabled={scanning} onClick={handleScan}
              style={{marginTop:16,width:'100%',justifyContent:'center',padding:'13px'}}>
              {scanning
                ? <><span className="loading-spinner" style={{width:16,height:16}}></span> Analyzing…</>
                : '🔬 Scan File Now'}
            </button>
          )}

          {/* Attack type legend */}
          <div style={{marginTop:20,padding:'14px',background:'var(--bg-secondary)',borderRadius:8,border:'1px solid var(--border)'}}>
            <div style={{fontSize:11,fontWeight:700,color:'var(--text-muted)',marginBottom:10,textTransform:'uppercase',letterSpacing:1}}>
              🔎 DETECTABLE ATTACK TYPES
            </div>
            {Object.entries(ATTACK_META).map(([name, m]) => (
              <div key={name} style={{display:'flex',alignItems:'flex-start',gap:10,marginBottom:8}}>
                <span style={{
                  width:28,height:28,background:m.bg,border:`1px solid ${m.border}`,
                  borderRadius:6,display:'flex',alignItems:'center',justifyContent:'center',
                  fontSize:14,flexShrink:0
                }}>{m.icon}</span>
                <div>
                  <div style={{fontSize:12,fontWeight:700,color:m.color}}>{name}</div>
                  <div style={{fontSize:11,color:'var(--text-muted)',marginTop:1}}>{m.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Result Panel ── */}
        <div>
          {result ? (
            <div className={`result-card ${isMalware?'malware':'safe'}`}>
              {/* Header */}
              <div className="result-header">
                <div className="result-icon">{isMalware ? (meta?.icon||'☣️') : '✅'}</div>
                <div>
                  <div className="result-label"
                    style={{color:isMalware?'var(--accent-red)':'var(--accent-green)'}}>
                    {isMalware ? '⚠️ MALWARE DETECTED' : '✅ FILE IS SAFE'}
                  </div>
                  <div className="result-conf">
                    Confidence: <strong>{result.confidence}%</strong>
                    &nbsp;·&nbsp;{result.filename}
                  </div>
                </div>
              </div>

              {/* Severity tier + Attack Type */}
              {isMalware && (
                <div style={{display:'flex',flexDirection:'column',gap:8,marginBottom:14}}>
                  {result.severity && (
                    <div style={{
                      display:'flex',alignItems:'center',gap:10,padding:'10px 14px',
                      background:`${result.severity.color}15`,
                      border:`1px solid ${result.severity.color}40`,borderRadius:8
                    }}>
                      <span style={{fontSize:20}}>
                        {result.severity.level==='Critical'?'🔴':result.severity.level==='High'?'🟠':result.severity.level==='Medium'?'🟡':'🟢'}
                      </span>
                      <div>
                        <div style={{fontWeight:700,color:result.severity.color,fontSize:14}}>
                          {result.severity.level} Severity ({result.severity.tier})
                        </div>
                        <div style={{fontSize:11,color:'var(--text-muted)',marginTop:1}}>
                          {result.severity.desc}
                        </div>
                      </div>
                      <div style={{marginLeft:'auto',textAlign:'right'}}>
                        <div style={{fontSize:10,color:'var(--text-muted)'}}>Malware Probability</div>
                        <div style={{fontSize:18,fontWeight:800,color:result.severity.color}}>
                          {result.malware_probability}%
                        </div>
                      </div>
                    </div>
                  )}
                  {attackType && <AttackCard type={attackType}/>}
                </div>
              )}

              {isMalware && (
                <div className="alert alert-danger">
                  🔒 ⚠️ Banking threat isolated! File quarantined and logged per RBI incident response protocol.
                </div>
              )}
              {result.message && <div className="alert alert-warning">{result.message}</div>}

              {/* Meta info */}
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:16}}>
                {[
                  {label:'Attack Type',  value: attackType ? <AttackBadge type={attackType}/> : '—'},
                  {label:'Banking Target', value: result.banking_target || '—'},
                  {label:'File Hash',    value: result.file_hash?.substring(0,16)+'…'},
                  {label:'File Size',    value: `${((result.file_size||0)/1024).toFixed(1)} KB`},
                  {label:'Quarantined',  value: result.is_quarantined?'Yes 🔒':'No'},
                ].map(item=>(
                  <div key={item.label} style={{
                    background:'var(--bg-secondary)',border:'1px solid var(--border)',
                    borderRadius:6,padding:'10px 12px'
                  }}>
                    <div style={{fontSize:10,color:'var(--text-muted)',textTransform:'uppercase',letterSpacing:0.5,marginBottom:4}}>
                      {item.label}
                    </div>
                    <div style={{fontSize:13,fontWeight:600}}>{item.value}</div>
                  </div>
                ))}
              </div>

              {/* Indicator features for this attack type */}
              {isMalware && indicators.length > 0 && result.features && (
                <div style={{
                  background:'var(--bg-secondary)',border:`1px solid ${meta?.border||'var(--border)'}`,
                  borderRadius:8,padding:'12px 14px',marginBottom:14
                }}>
                  <div style={{fontSize:11,fontWeight:700,color:meta?.color||'#ef4444',marginBottom:8,textTransform:'uppercase',letterSpacing:0.5}}>
                    {meta?.icon} Key indicators for {attackType}
                  </div>
                  <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
                    {indicators.map(feat=>(
                      <span key={feat} style={{
                        padding:'3px 9px',borderRadius:20,fontSize:11,fontWeight:600,
                        background:result.features[feat]?`${meta?.bg}`:'var(--bg-hover)',
                        color:result.features[feat]?meta?.color:'var(--text-muted)',
                        border:`1px solid ${result.features[feat]?(meta?.border||'var(--border)'):'var(--border)'}`
                      }}>
                        {result.features[feat] ? '✓' : '✗'} {feat.replace(/_/g,' ')}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* All features grid */}
              <div style={{fontSize:12,fontWeight:700,color:'var(--text-secondary)',marginBottom:8}}>
                📊 EXTRACTED FEATURES
              </div>
              <div className="feature-grid">
                {DISPLAY_FEATURES.map(f=>(
                  <div className="feature-item" key={f.key}
                    style={{borderColor: isMalware&&indicators.includes(f.key)?meta?.border:'var(--border)'}}>
                    <div className="feature-name">{f.label}</div>
                    <div className="feature-value" style={{
                      color: f.fmt(result.features[f.key])?.toString().includes('⚠️')
                        ? 'var(--accent-orange)'
                        : f.fmt(result.features[f.key])?.toString().includes('❌')
                        ? 'var(--accent-red)'
                        : 'var(--text-primary)'
                    }}>{f.fmt(result.features[f.key])}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="card" style={{height:'100%',display:'flex',flexDirection:'column',justifyContent:'center'}}>
              <div className="empty-state">
                <div className="empty-state-icon">🔍</div>
                <div className="empty-state-title">No Scan Results Yet</div>
                <div className="empty-state-sub">
                  Upload a file to scan it. The system will detect if it's malware
                  and identify the exact attack type — Trojan, Ransomware, Backdoor, Worm, or Spyware.
                </div>
                <div style={{marginTop:20}}>
                  <button className="btn btn-outline" onClick={handleSimulate} disabled={simulating}>
                    ⚡ Try Attack Simulation
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
