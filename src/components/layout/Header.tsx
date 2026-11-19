/**
 * Header.tsx
 * Top application header with status and user menu.
 */
import { Bell, User } from 'lucide-react';
import type { MonitoringStatus } from '../../types';

interface HeaderProps {
  monitoringStatus: MonitoringStatus;
  alertCount: number;
}

const STATUS_LABEL: Record<MonitoringStatus, string> = {
  active:     'API',
  demo:       'Demo',
  paused:     'Paused',
  error:      'Error',
  connecting: 'Connecting',
};

const STATUS_COLOR: Record<MonitoringStatus, string> = {
  active:     '#3B82F6',
  demo:       '#42D6C5',
  paused:     '#F59E0B',
  error:      '#EF4444',
  connecting: '#3B82F6',
};

export function Header({ monitoringStatus, alertCount }: HeaderProps) {
  const color = STATUS_COLOR[monitoringStatus];

  return (
    <header className="app-header">
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
          flexShrink: 0,
        }}
      >
        <div
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: color,
            boxShadow: `0 0 6px ${color}99`,
            animation: (monitoringStatus === 'active' || monitoringStatus === 'demo') ? 'pulse 2s infinite' : 'none',
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
        <span className="header-user-label" style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Analyst</span>
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
