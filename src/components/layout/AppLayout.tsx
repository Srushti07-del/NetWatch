/**
 * AppLayout.tsx
 * Root application shell: sidebar + header + main content area.
 */
import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import type { MonitoringStatus } from '../../types';

const MONITORING_STATUS: MonitoringStatus = 'active';
const ALERT_COUNT = 7;

export function AppLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

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

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <Header monitoringStatus={MONITORING_STATUS} alertCount={ALERT_COUNT} />

        <main
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '24px',
            background: '#0B1220',
          }}
        >
          <Outlet />
        </main>
      </div>
    </div>
  );
}
