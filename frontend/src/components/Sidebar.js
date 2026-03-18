import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

const NAV = [
  { label: 'Overview', items: [
    { to: '/dashboard', icon: '🏦', text: 'SOC Dashboard' },
    { to: '/scan',      icon: '🔍', text: 'File Scanner' },
  ]},
  { label: 'Threat Management', items: [
    { to: '/quarantine', icon: '🛡️', text: 'Quarantine Vault' },
    { to: '/logs',       icon: '📋', text: 'Scan Logs' },
    { to: '/alerts',     icon: '⚠️',  text: 'Threat Alerts' },
  ]},
  { label: 'Intelligence', items: [
    { to: '/model',  icon: '🤖', text: 'ML Model Info' },
  ]},
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🏦</div>
        <h1>BankShield AI</h1>
        <p>Banking Threat Detection</p>
      </div>

      <nav className="sidebar-nav">
        {NAV.map(section => (
          <div key={section.label}>
            <div className="nav-section-label">{section.label}</div>
            {section.items.map(item => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              >
                <span className="nav-icon">{item.icon}</span>
                {item.text}
                {item.badge && <span className="nav-badge">{item.badge}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="user-card">
          <div className="user-avatar">
            {user?.username?.[0]?.toUpperCase() || 'A'}
          </div>
          <div>
            <div className="user-name">{user?.username || 'Admin'}</div>
            <div className="user-role">{user?.role || 'SOC Analyst'}</div>
          </div>
          <button className="logout-btn" onClick={handleLogout} title="Logout">⏏</button>
        </div>
      </div>
    </aside>
  );
}
