/**
 * AppLayout.tsx
 * Root application shell: sidebar + header + main content area.
 */
import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import type { MonitoringStatus } from '../../types';

const MONITORING_STATUS: MonitoringStatus = 'demo';
const ALERT_COUNT = 7;

export function AppLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth < 768 : false
  );

  return (
    <div
      style={{
        display: 'flex',
        height: '100vh',
        overflow: 'hidden',
        background: '#0B1220',
      }}
    >
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((v) => !v)}
      />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <Header monitoringStatus={MONITORING_STATUS} alertCount={ALERT_COUNT} />

        <main className="app-main-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
