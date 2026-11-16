/**
 * OverviewPage.tsx
 * Full dashboard overview — the main landing page of NetWatch.
 */
import { Activity, AlertTriangle, Cpu, Package } from 'lucide-react';
import { ActivityTable } from '../components/dashboard/ActivityTable';
import { MetricCard } from '../components/dashboard/MetricCard';
import { ProtocolChart } from '../components/dashboard/ProtocolChart';
import { SecurityEvents } from '../components/dashboard/SecurityEvents';
import { TrafficChart } from '../components/dashboard/TrafficChart';
import { mockMetrics, mockPackets, mockProtocolData, mockSecurityEvents, mockTrafficData } from '../data/mockData';
import { formatCompact } from '../lib/formatters';

export function OverviewPage() {
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
            background: 'rgba(66, 214, 197, 0.08)',
            border: '1px solid rgba(66, 214, 197, 0.2)',
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
              background: '#42D6C5',
              boxShadow: '0 0 6px rgba(66, 214, 197, 0.6)',
            }}
          />
          <span style={{ color: '#42D6C5', fontSize: 12, fontWeight: 600 }}>
            Demo Mode
          </span>
        </div>
      </div>

      {/* Metric cards */}
      <div className="dashboard-metrics-grid">
        <MetricCard
          title="Total Packets"
          value={formatCompact(mockMetrics.totalPackets)}
          icon={<Package size={18} />}
          iconColor="#42D6C5"
          iconBg="rgba(66, 214, 197, 0.1)"
          trend={mockMetrics.totalPacketsDelta}
          trendLabel="vs last hour"
        />
        <MetricCard
          title="Bandwidth Usage"
          value={`${mockMetrics.bandwidthUsage} Mbps`}
          icon={<Activity size={18} />}
          iconColor="#3B82F6"
          iconBg="rgba(59, 130, 246, 0.1)"
          supporting={`Peak: ${mockMetrics.bandwidthPeak} Mbps`}
        />
        <MetricCard
          title="Active Devices"
          value={String(mockMetrics.activeDevices)}
          icon={<Cpu size={18} />}
          iconColor="#8B5CF6"
          iconBg="rgba(139, 92, 246, 0.1)"
          supporting={`${mockMetrics.totalDevices} total registered`}
        />
        <MetricCard
          title="Security Alerts"
          value={String(mockMetrics.securityAlerts)}
          icon={<AlertTriangle size={18} />}
          iconColor="#EF4444"
          iconBg="rgba(239, 68, 68, 0.1)"
          supporting={`${mockMetrics.criticalAlerts} critical`}
          trend={mockMetrics.securityAlerts > 0 ? mockMetrics.securityAlerts : undefined}
        />
      </div>

      {/* Traffic chart + protocol distribution */}
      <div className="dashboard-charts-grid">
        <TrafficChart data={mockTrafficData} />
        <ProtocolChart data={mockProtocolData} />
      </div>

      {/* Activity table + security events */}
      <div className="dashboard-activity-grid">
        <ActivityTable packets={mockPackets} />
        <SecurityEvents events={mockSecurityEvents} />
      </div>
    </div>
  );
}
