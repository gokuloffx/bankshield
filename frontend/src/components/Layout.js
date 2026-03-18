import React from 'react';
import Sidebar from './Sidebar';

export default function Layout({ title, subtitle, children, actions }) {
  return (
    <div className="app-layout">
      <Sidebar />
      <div className="main-content">
        <header className="topbar">
          <div>
            <div className="topbar-title">{title}</div>
            {subtitle && <div className="topbar-subtitle">{subtitle}</div>}
          </div>
          <div className="topbar-right">
            {actions}
            <div className="status-badge online">
              <span className="status-dot"></span>
              System Online
            </div>
          </div>
        </header>
        <div className="page-body">
          {children}
        </div>
      </div>
    </div>
  );
}
