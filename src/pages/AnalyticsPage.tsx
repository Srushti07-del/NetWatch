/**
 * AnalyticsPage.tsx
 *
 * Network analytics dashboard.
 * Fetches metrics, traffic, protocol distribution, and packets through the
 * centralized API service and useApi hook.
 * Demo mode uses sample data; API mode uses the configured backend.
 * No synthetic data, no fake time ranges, no live streaming.
 */

import { useCallback, useEffect, useState } from 'react';
import { Activity, ArrowUpRight, Copy, RefreshCw } from 'lucide-react';
import { MetricCard } from '../components/dashboard/MetricCard';
import { TrafficChart } from '../components/dashboard/TrafficChart';
import { ProtocolChart } from '../components/dashboard/ProtocolChart';
import { useApi } from '../hooks/useApi';
import { api, IS_DEMO_MODE } from '../services/api';
import type { NetworkPacket, PacketStatus, TrafficDataPoint } from '../types';
import { formatBytes, formatCompact } from '../lib/formatters';

const TOP_TALKERS_LIMIT = 10;

const STATUS_STYLES: Record<PacketStatus, { bg: string; color: string; label: string }> = {
  allowed:   { bg: 'rgba(16, 185, 129, 0.1)',  color: '#10B981', label: 'Allowed' },
  blocked:   { bg: 'rgba(239, 68, 68, 0.1)',   color: '#EF4444', label: 'Blocked' },
  flagged:   { bg: 'rgba(245, 158, 11, 0.1)',  color: '#F59E0B', label: 'Flagged' },
  monitored: { bg: 'rgba(59, 130, 246, 0.1)',  color: '#3B82F6', label: 'Monitored' },
};

interface IpAggregation {
  packetCount: number;
  totalBytes: number;
}

interface TopTalker {
  ip: string;
  packetCount: number;
  totalBytes: number;
}

interface StatusCount {
  status: PacketStatus;
  count: number;
}

export function AnalyticsPage() {
  const metricsResult = useApi(() => api.getDashboardMetrics());
  const trafficResult = useApi(() => api.getTrafficData());
  const protocolResult = useApi(() => api.getProtocolDistribution());
  const packetsResult = useApi(() => api.getRecentPackets(50));

  // Copy feedback state
  const [copyFeedback, setCopyFeedback] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  // Dismiss copy feedback after a short delay
  useEffect(() => {
    if (!copyFeedback) return;
    const timer = setTimeout(() => setCopyFeedback(null), 3000);
    return () => clearTimeout(timer);
  }, [copyFeedback]);

  // Mode-aware labels
  const modeLabel = IS_DEMO_MODE ? 'Demo Mode' : 'API Mode';
  const modeBadgeBg = IS_DEMO_MODE
    ? 'rgba(66, 214, 197, 0.08)'
    : 'rgba(59, 130, 246, 0.08)';
  const modeBadgeBorder = IS_DEMO_MODE
    ? '1px solid rgba(66, 214, 197, 0.2)'
    : '1px solid rgba(59, 130, 246, 0.2)';
  const modeDotColor = IS_DEMO_MODE ? '#42D6C5' : '#3B82F6';
  const modeDotShadow = IS_DEMO_MODE
    ? '0 0 6px rgba(66, 214, 197, 0.6)'
    : '0 0 6px rgba(59, 130, 246, 0.6)';
  const sampleNote = IS_DEMO_MODE
    ? 'Illustrative sample analytics — not measurements from a live network.'
    : 'Analytics data from the configured API backend.';

  // Derived data (available even during loading as null/empty defaults)
  const metrics = metricsResult.data;
  const trafficData: TrafficDataPoint[] = trafficResult.data ?? [];
  const protocolData = protocolResult.data ?? [];
  const packets: NetworkPacket[] = packetsResult.data ?? [];

  // Derived: Top Talkers — aggregate packets by source and destination IP
  const ipMap = new Map<string, IpAggregation>();
  for (const pkt of packets) {
    for (const ip of [pkt.sourceIp, pkt.destinationIp]) {
      const entry = ipMap.get(ip) ?? { packetCount: 0, totalBytes: 0 };
      entry.packetCount += 1;
      entry.totalBytes += pkt.packetSize;
      ipMap.set(ip, entry);
    }
  }
  const topTalkers: TopTalker[] = Array.from(ipMap.entries())
    .map(([ip, stats]) => ({ ip, ...stats }))
    .sort((a, b) => b.packetCount - a.packetCount)
    .slice(0, TOP_TALKERS_LIMIT);

  // Derived: Packet status distribution
  const statusCounts: Record<PacketStatus, number> = { allowed: 0, blocked: 0, flagged: 0, monitored: 0 };
  for (const pkt of packets) {
    statusCounts[pkt.status] += 1;
  }
  const statusList: StatusCount[] = Object.entries(statusCounts).map(([status, count]) => ({
    status: status as PacketStatus,
    count,
  }));

  // Handlers (defined unconditionally before any early return)
  const handleRefresh = () => {
    metricsResult.refetch();
    trafficResult.refetch();
    protocolResult.refetch();
    packetsResult.refetch();
  };

  const handleCopySummary = useCallback(async () => {
    const text =
      `Total Packets: ${formatCompact(metrics?.totalPackets ?? 0)} | ` +
      `Bandwidth: ${metrics?.bandwidthUsage ?? 0} Mbps | ` +
      `Peak: ${metrics?.bandwidthPeak ?? 0} Mbps | ` +
      `Active Devices: ${metrics?.activeDevices !== null && metrics?.activeDevices !== undefined ? metrics.activeDevices : 'N/A'}`;
    if (!navigator.clipboard) {
      setCopyFeedback({ message: 'Clipboard not available', type: 'error' });
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      setCopyFeedback({ message: 'Copied to clipboard', type: 'success' });
    } catch {
      setCopyFeedback({ message: 'Failed to copy', type: 'error' });
    }
  }, [metrics]);

  // Loading if any dataset is still fetching
  const loading =
    metricsResult.loading ||
    trafficResult.loading ||
    protocolResult.loading ||
    packetsResult.loading;

  // Avoid showing misleading partial values while loading
  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Analytics
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Network traffic patterns, protocol distribution and activity insights.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ color: '#94A3B8', fontSize: 13, paddingTop: 8 }}>Loading analytics…</div>
      </div>
    );
  }

  // Error state — any dataset failure
  if (metricsResult.error || trafficResult.error || protocolResult.error || packetsResult.error) {
    const error =
      metricsResult.error ||
      trafficResult.error ||
      protocolResult.error ||
      packetsResult.error;
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Analytics
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Network traffic patterns, protocol distribution and activity insights.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 24, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
          <span style={{ color: '#EF4444', fontSize: 13, fontWeight: 600 }}>Failed to load analytics</span>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{error}</span>
          <button
            onClick={handleRefresh}
            style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20, minHeight: 0 }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
            Analytics
          </h2>
          <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
            {sampleNote}
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
          <button
            onClick={handleRefresh}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: '#3B82F6',
              border: 'none',
              borderRadius: 8,
              padding: '8px 14px',
              color: '#F1F5F9',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>
          <button
            onClick={handleCopySummary}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: '#1E2D45',
              border: '1px solid #2a3f5f',
              borderRadius: 8,
              padding: '8px 14px',
              color: '#F1F5F9',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <Copy size={14} />
            <span>Copy Summary</span>
          </button>
        </div>
      </div>

      {/* KPI cards */}
      <div className="dashboard-metrics-grid">
        <MetricCard
          title="Total Packets"
          value={formatCompact(metrics?.totalPackets ?? 0)}
          icon={<Activity size={18} />}
          iconColor="#42D6C5"
          iconBg="rgba(66, 214, 197, 0.1)"
          supporting="Packets in current sample"
        />
        <MetricCard
          title="Current Bandwidth"
          value={`${metrics?.bandwidthUsage ?? 0} Mbps`}
          icon={<ArrowUpRight size={18} />}
          iconColor="#3B82F6"
          iconBg="rgba(59, 130, 246, 0.1)"
          supporting={`Peak: ${metrics?.bandwidthPeak ?? 0} Mbps`}
        />
        <MetricCard
          title="Active Devices"
          value={metrics?.activeDevices !== null && metrics?.activeDevices !== undefined ? String(metrics.activeDevices) : "N/A"}
          icon={<Activity size={18} />}
          iconColor="#8B5CF6"
          iconBg="rgba(139, 92, 246, 0.1)"
          supporting={`${metrics?.totalDevices ?? 0} observed private IPs`}
        />
        <MetricCard
          title="Observed Packets"
          value={String(packets.length)}
          icon={<Activity size={18} />}
          iconColor="#F59E0B"
          iconBg="rgba(245, 158, 11, 0.1)"
          supporting="From recent packet sample"
        />
      </div>

      {/* Traffic trend + Protocol distribution */}
      <div className="dashboard-charts-grid">
        {trafficData.length > 0 ? (
          <TrafficChart data={trafficData} />
        ) : (
          <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 40, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center', justifyContent: 'center', color: '#94A3B8', fontSize: 13 }}>
            No traffic data available
          </div>
        )}
        {protocolData.length > 0 ? (
          <ProtocolChart data={protocolData} />
        ) : (
          <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 40, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center', justifyContent: 'center', color: '#94A3B8', fontSize: 13 }}>
            No protocol data available
          </div>
        )}
      </div>

      {/* Top Talkers */}
      <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
              Top Talkers
            </h3>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Observed IPs from recent packet sample — derived, not network-wide
            </p>
          </div>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{packets.length} packets analyzed</span>
        </div>

        {packets.length === 0 ? (
          <div style={{ padding: 48, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
            <span style={{ color: '#94A3B8', fontSize: 13 }}>No packet data available</span>
          </div>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 500 }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1E2D45' }}>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      IP Address
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      Packets
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                      Total Bytes
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topTalkers.map((talker) => (
                    <tr
                      key={talker.ip}
                      style={{ borderTop: '1px solid #1E2D45' }}
                    >
                      <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                        {talker.ip}
                      </td>
                      <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                        {talker.packetCount}
                      </td>
                      <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                        {formatBytes(talker.totalBytes)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {topTalkers.length === 0 && (
              <div style={{ padding: 48, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
                <span style={{ color: '#94A3B8', fontSize: 13 }}>No IP data available</span>
              </div>
            )}
          </>
        )}
      </div>

      {/* Packet Status Distribution */}
      <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
              Packet Status Distribution
            </h3>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Observed packet statuses from recent sample
            </p>
          </div>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{packets.length} packets</span>
        </div>

        {packets.length === 0 ? (
          <div style={{ padding: 48, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
            <span style={{ color: '#94A3B8', fontSize: 13 }}>No packet data available</span>
          </div>
        ) : (
          <div style={{ padding: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12 }}>
            {statusList.map((item) => {
              const style = STATUS_STYLES[item.status];
              return (
                <div
                  key={item.status}
                  style={{
                    background: '#0D1726',
                    border: '1px solid #1E2D45',
                    borderRadius: 10,
                    padding: '16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                    alignItems: 'center',
                    textAlign: 'center',
                  }}
                >
                  <span
                    style={{
                      background: style.bg,
                      color: style.color,
                      fontSize: 10,
                      fontWeight: 700,
                      padding: '4px 8px',
                      borderRadius: 6,
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                    }}
                  >
                    {style.label}
                  </span>
                  <span style={{ color: '#F1F5F9', fontSize: 24, fontWeight: 700 }}>{item.count}</span>
                  <span style={{ color: '#94A3B8', fontSize: 11 }}>
                    {packets.length > 0 ? ((item.count / packets.length) * 100).toFixed(1) : 0}%
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Copy feedback toast */}
      {copyFeedback && (
        <div
          style={{
            position: 'fixed',
            top: 20,
            right: 20,
            zIndex: 100,
            background: copyFeedback.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: copyFeedback.type === 'success' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 8,
            color: copyFeedback.type === 'success' ? '#10B981' : '#EF4444',
            fontSize: 12,
            fontWeight: 600,
            padding: '8px 12px',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          {copyFeedback.message}
        </div>
      )}
    </div>
  );
}
