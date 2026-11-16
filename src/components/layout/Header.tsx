/**
 * Header.tsx
 * Top application header with page title, status, and user menu.
 */
import { Bell, ChevronRight, User } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import type { MonitoringStatus } from '../../types';

const PAGE_META: Record<string, { title: string; description: string }> = {
  '/':              { title: 'Overview',         description: 'Network status at a glance' },
  '/live-traffic':  { title: 'Live Traffic',     description: 'Real-time packet and flow inspection' },
  '/devices':       { title: 'Devices',           description: 'Discovered network endpoints' },
  '/connections':   { title: 'Connections',       description: 'Active and historical network flows' },
  '/threats':       { title: 'Threat Detection', description: 'Security events and anomaly alerts' },
  '/analytics':     { title: 'Analytics',         description: 'Traffic patterns and trend analysis' },
  '/settings':      { title: 'Settings',          description: 'Application and monitoring configuration' },
};

interface HeaderProps {
  monitoringStatus: MonitoringStatus;
  alertCount: number;
}

const STATUS_LABEL: Record<MonitoringStatus, string> = {
  active:     'Active',
  paused:     'Paused',
  error:      'Error',
  connecting: 'Connecting',
};

const STATUS_COLOR: Record<MonitoringStatus, string> = {
  active:     '#10B981',
  paused:     '#F59E0B',
  error:      '#EF4444',
  connecting: '#3B82F6',
};

export function Header({ monitoringStatus, alertCount }: HeaderProps) {
  const location = useLocation();
  const meta = PAGE_META[location.pathname] ?? { title: 'NetWatch', description: '' };
  const color = STATUS_COLOR[monitoringStatus];

  return (
    <header
      style={{
        height: 60,
        background: '#0B1220',
        borderBottom: '1px solid #1E2D45',
        display: 'flex',
        alignItems: 'center',
        padding: '0 24px',
        gap: 16,
        flexShrink: 0,
      }}
    >
      {/* Page title */}
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>NetWatch</span>
          <ChevronRight size={12} color="#64748B" />
          <span style={{ color: '#F1F5F9', fontSize: 12, fontWeight: 500 }}>{meta.title}</span>
        </div>
        <h1 style={{ margin: 0, fontSize: 17, fontWeight: 700, color: '#F1F5F9', lineHeight: 1 }}>
          {meta.title}
        </h1>
      </div>

      {/* Monitoring status */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 7,
          background: '#141F30',
          border: '1px solid #1E2D45',
          borderRadius: 8,
          padding: '5px 12px',
        }}
      >
        <div
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: color,
            boxShadow: `0 0 6px ${color}99`,
            animation: monitoringStatus === 'active' ? 'pulse 2s infinite' : 'none',
          }}
        />
        <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>
          {STATUS_LABEL[monitoringStatus]}
        </span>
      </div>

      {/* Notifications */}
      <button
        style={{
          position: 'relative',
          width: 36,
          height: 36,
          borderRadius: 8,
          background: '#141F30',
          border: '1px solid #1E2D45',
          color: '#94A3B8',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          cursor: 'pointer',
        }}
        aria-label={`${alertCount} alerts`}
      >
        <Bell size={16} />
        {alertCount > 0 && (
          <span
            style={{
              position: 'absolute',
              top: 6,
              right: 6,
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: '#EF4444',
              border: '2px solid #0B1220',
            }}
          />
        )}
      </button>

      {/* User menu */}
      <button
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          background: '#141F30',
          border: '1px solid #1E2D45',
          borderRadius: 8,
          padding: '5px 12px 5px 8px',
          cursor: 'pointer',
        }}
        aria-label="User menu"
      >
        <div
          style={{
            width: 26,
            height: 26,
            borderRadius: '50%',
            background: 'rgba(66, 214, 197, 0.2)',
            border: '1px solid rgba(66, 214, 197, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <User size={13} color="#42D6C5" />
        </div>
        <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Analyst</span>
      </button>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </header>
  );
}
