/**
 * MetricCard.tsx
 * Individual KPI card for the overview dashboard.
 */
import type { ReactNode } from 'react';
import { TrendingDown, TrendingUp } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string;
  icon: ReactNode;
  iconColor?: string;
  iconBg?: string;
  supporting?: string;
  trend?: number; // positive = up, negative = down (percentage)
  trendLabel?: string;
}

export function MetricCard({
  title,
  value,
  icon,
  iconColor = '#42D6C5',
  iconBg = 'rgba(66, 214, 197, 0.1)',
  supporting,
  trend,
  trendLabel,
}: MetricCardProps) {
  const hasTrend = trend !== undefined;
  const trendUp = (trend ?? 0) >= 0;

  return (
    <div
      style={{
        background: '#141F30',
        border: '1px solid #1E2D45',
        borderRadius: 12,
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        transition: 'border-color 0.15s',
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = '#2a3f5f';
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = '#1E2D45';
      }}
    >
      {/* Title row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <span style={{ color: '#94A3B8', fontSize: 12.5, fontWeight: 500, letterSpacing: '0.02em' }}>
          {title}
        </span>
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 9,
            background: iconBg,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: iconColor,
            flexShrink: 0,
          }}
        >
          {icon}
        </div>
      </div>

      {/* Value */}
      <div>
        <span
          style={{
            color: '#F1F5F9',
            fontSize: 26,
            fontWeight: 700,
            lineHeight: 1,
            letterSpacing: '-0.5px',
          }}
        >
          {value}
        </span>
      </div>

      {/* Trend + supporting */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        {hasTrend && (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 3,
              color: trendUp ? '#10B981' : '#EF4444',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {trendUp ? <TrendingUp size={13} /> : <TrendingDown size={13} />}
            {trendUp ? '+' : ''}{trend}%
          </span>
        )}
        {supporting && (
          <span style={{ color: '#64748B', fontSize: 12 }}>{supporting}</span>
        )}
        {trendLabel && (
          <span style={{ color: '#64748B', fontSize: 12 }}>{trendLabel}</span>
        )}
      </div>
    </div>
  );
}
