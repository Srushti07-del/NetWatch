/**
 * SecurityEvents.tsx
 * Compact list of recent security events with severity badges.
 */
import { AlertCircle, AlertTriangle, CheckCircle, Info, XCircle } from 'lucide-react';
import type { SecurityEvent, Severity } from '../../types';
import { timeAgo } from '../../lib/formatters';

interface SecurityEventsProps {
  events: SecurityEvent[];
}

const SEVERITY_CONFIG: Record<
  Severity,
  { icon: React.ReactNode; color: string; bg: string; border: string; label: string }
> = {
  critical: {
    icon: <XCircle size={14} />,
    color: '#EF4444',
    bg: 'rgba(239, 68, 68, 0.08)',
    border: 'rgba(239, 68, 68, 0.2)',
    label: 'Critical',
  },
  high: {
    icon: <AlertCircle size={14} />,
    color: '#F97316',
    bg: 'rgba(249, 115, 22, 0.08)',
    border: 'rgba(249, 115, 22, 0.2)',
    label: 'High',
  },
  medium: {
    icon: <AlertTriangle size={14} />,
    color: '#F59E0B',
    bg: 'rgba(245, 158, 11, 0.08)',
    border: 'rgba(245, 158, 11, 0.2)',
    label: 'Medium',
  },
  low: {
    icon: <Info size={14} />,
    color: '#3B82F6',
    bg: 'rgba(59, 130, 246, 0.08)',
    border: 'rgba(59, 130, 246, 0.2)',
    label: 'Low',
  },
  info: {
    icon: <CheckCircle size={14} />,
    color: '#64748B',
    bg: 'rgba(100, 116, 139, 0.08)',
    border: 'rgba(100, 116, 139, 0.2)',
    label: 'Info',
  },
};

export function SecurityEvents({ events }: SecurityEventsProps) {
  return (
    <div
      style={{
        background: '#141F30',
        border: '1px solid #1E2D45',
        borderRadius: 12,
        overflow: 'hidden',
      }}
    >
      <div style={{ padding: '20px 20px 16px', borderBottom: '1px solid #1E2D45' }}>
        <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
          Recent Security Events
        </h3>
        <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
          Illustrative sample events — not live threat data
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {events.map((event, i) => {
          const cfg = SEVERITY_CONFIG[event.severity];
          return (
            <div
              key={event.id}
              style={{
                padding: '14px 20px',
                borderBottom: i < events.length - 1 ? '1px solid #1E2D45' : 'none',
                display: 'flex',
                gap: 12,
                alignItems: 'flex-start',
                opacity: event.resolved ? 0.55 : 1,
              }}
            >
              {/* Severity icon */}
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: cfg.bg,
                  border: `1px solid ${cfg.border}`,
                  color: cfg.color,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  marginTop: 1,
                }}
              >
                {cfg.icon}
              </div>

              {/* Content */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                  <span
                    style={{
                      color: event.resolved ? '#94A3B8' : '#F1F5F9',
                      fontSize: 13,
                      fontWeight: 600,
                      lineHeight: 1.3,
                    }}
                  >
                    {event.title}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    {event.resolved && (
                      <span
                        style={{
                          fontSize: 10,
                          color: '#10B981',
                          background: 'rgba(16, 185, 129, 0.1)',
                          padding: '1px 6px',
                          borderRadius: 3,
                          fontWeight: 600,
                        }}
                      >
                        Resolved
                      </span>
                    )}
                    <span
                      style={{
                        fontSize: 10,
                        color: cfg.color,
                        background: cfg.bg,
                        border: `1px solid ${cfg.border}`,
                        padding: '1px 7px',
                        borderRadius: 3,
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      {cfg.label}
                    </span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 5, flexWrap: 'wrap' }}>
                  <span style={{ color: '#64748B', fontSize: 11, fontFamily: 'monospace' }}>
                    {event.sourceIp}
                  </span>
                  <span style={{ color: '#64748B', fontSize: 11 }}>·</span>
                  <span style={{ color: '#64748B', fontSize: 11 }}>
                    {timeAgo(event.timestamp)}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
