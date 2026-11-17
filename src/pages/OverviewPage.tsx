/**
 * OverviewPage.tsx
 * Full dashboard overview — the main landing page of NetWatch.
 *
 * Data is fetched through the centralized API service and useApi hook
 * rather than importing mock data directly.
 */
import { Activity, AlertTriangle, Cpu, Package } from 'lucide-react';
import { ActivityTable } from '../components/dashboard/ActivityTable';
import { MetricCard } from '../components/dashboard/MetricCard';
import { ProtocolChart } from '../components/dashboard/ProtocolChart';
import { SecurityEvents } from '../components/dashboard/SecurityEvents';
import { TrafficChart } from '../components/dashboard/TrafficChart';
import { api, IS_DEMO_MODE } from '../services/api';
import { useApi } from '../hooks/useApi';
import { formatCompact } from '../lib/formatters';
import type { DashboardMetrics } from '../types';

const EMPTY_METRICS: DashboardMetrics = {
  totalPackets: 0,
  totalPacketsDelta: 0,
  bandwidthUsage: 0,
  bandwidthPeak: 0,
  activeDevices: 0,
  totalDevices: 0,
  securityAlerts: 0,
  criticalAlerts: 0,
};

export function OverviewPage() {
  const metricsResult = useApi(() => api.getDashboardMetrics());
  const trafficResult = useApi(() => api.getTrafficData());
  const protocolResult = useApi(() => api.getProtocolDistribution());
  const packetsResult = useApi(() => api.getRecentPackets(10));
  const securityResult = useApi(() => api.getSecurityEvents());

  const loading =
    metricsResult.loading ||
    trafficResult.loading ||
    protocolResult.loading ||
    packetsResult.loading ||
    securityResult.loading;

  const error =
    metricsResult.error ||
    trafficResult.error ||
    protocolResult.error ||
    packetsResult.error ||
    securityResult.error;

  const refetchAll = () => {
    metricsResult.refetch();
    trafficResult.refetch();
    protocolResult.refetch();
    packetsResult.refetch();
    securityResult.refetch();
  };

  // Graceful defaults for empty datasets
  const metrics = metricsResult.data ?? EMPTY_METRICS;
  const trafficData = trafficResult.data ?? [];
  const protocolData = protocolResult.data ?? [];
  const packets = packetsResult.data ?? [];
  const securityEvents = securityResult.data ?? [];

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24, padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Network Overview
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Monitor network activity, connected devices, and security events.
            </p>
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              background: IS_DEMO_MODE
                ? 'rgba(66, 214, 197, 0.08)'
                : 'rgba(59, 130, 246, 0.08)',
              border: IS_DEMO_MODE
                ? '1px solid rgba(66, 214, 197, 0.2)'
                : '1px solid rgba(59, 130, 246, 0.2)',
              borderRadius: 8,
              padding: '6px 14px',
              flexShrink: 0,
            }}
          >
            <div
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6',
                boxShadow: IS_DEMO_MODE
                  ? '0 0 6px rgba(66, 214, 197, 0.6)'
                  : '0 0 6px rgba(59, 130, 246, 0.6)',
              }}
            />
            <span
              style={{
                color: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {IS_DEMO_MODE ? 'Demo Mode' : 'API Mode'}
            </span>
          </div>
        </div>
        <div style={{ color: '#94A3B8', fontSize: 13, paddingTop: 8 }}>
          Loading dashboard data…
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Network Overview
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Monitor network activity, connected devices, and security events.
            </p>
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              background: IS_DEMO_MODE
                ? 'rgba(66, 214, 197, 0.08)'
                : 'rgba(59, 130, 246, 0.08)',
              border: IS_DEMO_MODE
                ? '1px solid rgba(66, 214, 197, 0.2)'
                : '1px solid rgba(59, 130, 246, 0.2)',
              borderRadius: 8,
              padding: '6px 14px',
              flexShrink: 0,
            }}
          >
            <div
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6',
                boxShadow: IS_DEMO_MODE
                  ? '0 0 6px rgba(66, 214, 197, 0.6)'
                  : '0 0 6px rgba(59, 130, 246, 0.6)',
              }}
            />
            <span
              style={{
                color: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {IS_DEMO_MODE ? 'Demo Mode' : 'API Mode'}
            </span>
          </div>
        </div>
        <div
          style={{
            background: '#141F30',
            border: '1px solid #1E2D45',
            borderRadius: 12,
            padding: 24,
            display: 'flex',
            flexDirection: 'column',
            gap: 12,
            alignItems: 'center',
            textAlign: 'center',
          }}
        >
          <span style={{ color: '#EF4444', fontSize: 13, fontWeight: 600 }}>
            Failed to load dashboard data
          </span>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{error}</span>
          <button
            onClick={refetchAll}
            style={{
              background: '#3B82F6',
              border: 'none',
              borderRadius: 8,
              padding: '8px 16px',
              color: '#F1F5F9',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Page intro */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
            Network Overview
          </h2>
          <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
            Monitor network activity, connected devices, and security events.
          </p>
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            background: IS_DEMO_MODE
              ? 'rgba(66, 214, 197, 0.08)'
              : 'rgba(59, 130, 246, 0.08)',
            border: IS_DEMO_MODE
              ? '1px solid rgba(66, 214, 197, 0.2)'
              : '1px solid rgba(59, 130, 246, 0.2)',
            borderRadius: 8,
            padding: '6px 14px',
            flexShrink: 0,
          }}
        >
          <div
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6',
              boxShadow: IS_DEMO_MODE
                ? '0 0 6px rgba(66, 214, 197, 0.6)'
                : '0 0 6px rgba(59, 130, 246, 0.6)',
            }}
          />
          <span
            style={{
              color: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {IS_DEMO_MODE ? 'Demo Mode' : 'API Mode'}
          </span>
        </div>
      </div>

      {/* Metric cards */}
      <div className="dashboard-metrics-grid">
        <MetricCard
          title="Total Packets"
          value={formatCompact(metrics.totalPackets)}
          icon={<Package size={18} />}
          iconColor="#42D6C5"
          iconBg="rgba(66, 214, 197, 0.1)"
          trend={metrics.totalPacketsDelta}
          trendLabel="vs last hour"
        />
        <MetricCard
          title="Bandwidth Usage"
          value={`${metrics.bandwidthUsage} Mbps`}
          icon={<Activity size={18} />}
          iconColor="#3B82F6"
          iconBg="rgba(59, 130, 246, 0.1)"
          supporting={`Peak: ${metrics.bandwidthPeak} Mbps`}
        />
        <MetricCard
          title="Active Devices"
          value={String(metrics.activeDevices)}
          icon={<Cpu size={18} />}
          iconColor="#8B5CF6"
          iconBg="rgba(139, 92, 246, 0.1)"
          supporting={`${metrics.totalDevices} total registered`}
        />
        <MetricCard
          title="Security Alerts"
          value={String(metrics.securityAlerts)}
          icon={<AlertTriangle size={18} />}
          iconColor="#EF4444"
          iconBg="rgba(239, 68, 68, 0.1)"
          supporting={`${metrics.criticalAlerts} critical`}
          trend={metrics.securityAlerts > 0 ? metrics.securityAlerts : undefined}
        />
      </div>

      {/* Traffic chart + protocol distribution */}
      <div className="dashboard-charts-grid">
        <TrafficChart data={trafficData} />
        <ProtocolChart data={protocolData} />
      </div>

      {/* Activity table + security events */}
      <div className="dashboard-activity-grid">
        <ActivityTable packets={packets} />
        <SecurityEvents events={securityEvents} />
      </div>
    </div>
  );
}
