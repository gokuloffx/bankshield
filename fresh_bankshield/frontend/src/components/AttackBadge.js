import React from 'react';

export const ATTACK_META = {
  Trojan:     { icon: '🐴', color: '#ef4444', bg: 'rgba(239,68,68,0.12)',     border: 'rgba(239,68,68,0.3)',   desc: 'Disguises as legit file, injects into processes' },
  Ransomware: { icon: '💰', color: '#f97316', bg: 'rgba(249,115,22,0.12)',    border: 'rgba(249,115,22,0.3)',  desc: 'Encrypts files and demands payment' },
  Backdoor:   { icon: '🚪', color: '#8b5cf6', bg: 'rgba(139,92,246,0.12)',    border: 'rgba(139,92,246,0.3)',  desc: 'Opens hidden remote access to system' },
  Worm:       { icon: '🪱', color: '#06b6d4', bg: 'rgba(6,182,212,0.12)',     border: 'rgba(6,182,212,0.3)',   desc: 'Self-replicates and spreads via network' },
  Spyware:    { icon: '🕵️', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)',    border: 'rgba(245,158,11,0.3)',  desc: 'Silently harvests data and keystrokes' },
};

export function AttackBadge({ type, size = 'md' }) {
  if (!type) return null;
  const m = ATTACK_META[type] || { icon:'☣️', color:'#ef4444', bg:'rgba(239,68,68,0.12)', border:'rgba(239,68,68,0.3)' };
  const pad   = size === 'sm' ? '2px 7px'  : size === 'lg' ? '5px 14px' : '3px 10px';
  const fsize = size === 'sm' ? 10         : size === 'lg' ? 13         : 11;
  const isize = size === 'sm' ? 11         : size === 'lg' ? 15         : 12;
  return (
    <span style={{
      display:'inline-flex', alignItems:'center', gap:4,
      padding:pad, borderRadius:20, fontSize:fsize, fontWeight:700,
      background:m.bg, color:m.color, border:`1px solid ${m.border}`,
      whiteSpace:'nowrap'
    }}>
      <span style={{fontSize:isize}}>{m.icon}</span>
      {type}
    </span>
  );
}

export function AttackCard({ type }) {
  if (!type) return null;
  const m = ATTACK_META[type];
  if (!m) return null;
  return (
    <div style={{
      display:'flex', alignItems:'center', gap:10, padding:'10px 14px',
      background:m.bg, border:`1px solid ${m.border}`, borderRadius:8
    }}>
      <span style={{fontSize:24}}>{m.icon}</span>
      <div>
        <div style={{fontWeight:700, color:m.color, fontSize:14}}>{type} Detected</div>
        <div style={{fontSize:11, color:'var(--text-muted)', marginTop:1}}>{m.desc}</div>
      </div>
    </div>
  );
}
