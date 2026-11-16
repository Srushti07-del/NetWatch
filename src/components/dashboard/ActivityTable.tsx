/**
 * ActivityTable.tsx
 * Recent network activity with sortable columns.
 */
import { useState } from 'react';
import { ChevronDown, ChevronUp, ChevronsUpDown } from 'lucide-react';
import type { NetworkPacket, PacketStatus, Protocol, SortConfig } from '../../types';
import { formatTimestamp } from '../../lib/formatters';

interface ActivityTableProps {
  packets: NetworkPacket[];
}

type SortKey = keyof Pick<NetworkPacket, 'timestamp' | 'sourceIp' | 'destinationIp' | 'protocol' | 'packetSize' | 'status'>;

const PROTOCOL_COLORS: Record<Protocol, { bg: string; color: string }> = {
  TCP:   { bg: 'rgba(59, 130, 246, 0.12)',  color: '#3B82F6' },
  UDP:   { bg: 'rgba(139, 92, 246, 0.12)',  color: '#8B5CF6' },
  DNS:   { bg: 'rgba(245, 158, 11, 0.12)',  color: '#F59E0B' },
  HTTP:  { bg: 'rgba(236, 72, 153, 0.12)',  color: '#EC4899' },
  HTTPS: { bg: 'rgba(66, 214, 197, 0.12)',  color: '#42D6C5' },
  ICMP:  { bg: 'rgba(100, 116, 139, 0.12)', color: '#64748B' },
  ARP:   { bg: 'rgba(100, 116, 139, 0.12)', color: '#64748B' },
  Other: { bg: 'rgba(100, 116, 139, 0.12)', color: '#64748B' },
};

const STATUS_STYLES: Record<PacketStatus, { bg: string; color: string; label: string }> = {
  allowed:   { bg: 'rgba(16, 185, 129, 0.1)',  color: '#10B981', label: 'Allowed' },
  blocked:   { bg: 'rgba(239, 68, 68, 0.1)',   color: '#EF4444', label: 'Blocked' },
  flagged:   { bg: 'rgba(245, 158, 11, 0.1)',  color: '#F59E0B', label: 'Flagged' },
  monitored: { bg: 'rgba(59, 130, 246, 0.1)',  color: '#3B82F6', label: 'Monitored' },
};

function SortIcon({ col, sort }: { col: SortKey; sort: SortConfig<NetworkPacket> | null }) {
  if (!sort || sort.key !== col) return <ChevronsUpDown size={12} color="#64748B" />;
  return sort.direction === 'asc'
    ? <ChevronUp size={12} color="#42D6C5" />
    : <ChevronDown size={12} color="#42D6C5" />;
}

const COLS: { key: SortKey; label: string }[] = [
  { key: 'timestamp',      label: 'Timestamp' },
  { key: 'sourceIp',       label: 'Source IP' },
  { key: 'destinationIp',  label: 'Destination IP' },
  { key: 'protocol',       label: 'Protocol' },
  { key: 'packetSize',     label: 'Size' },
  { key: 'status',         label: 'Status' },
];

export function ActivityTable({ packets }: ActivityTableProps) {
  const [sort, setSort] = useState<SortConfig<NetworkPacket> | null>({
    key: 'timestamp',
    direction: 'desc',
  });

  function handleSort(key: SortKey) {
    setSort((prev) => {
      if (prev?.key === key) {
        return { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
      }
      return { key, direction: 'asc' };
    });
  }

  const sorted = [...packets].sort((a, b) => {
    if (!sort) return 0;
    const aVal = a[sort.key];
    const bVal = b[sort.key];
    const dir = sort.direction === 'asc' ? 1 : -1;
    if (typeof aVal === 'number' && typeof bVal === 'number') return (aVal - bVal) * dir;
    return String(aVal).localeCompare(String(bVal)) * dir;
  });

  return (
    <div
      style={{
        background: '#141F30',
        border: '1px solid #1E2D45',
        borderRadius: 12,
        overflow: 'hidden',
      }}
    >
      <div style={{ padding: '20px 20px 16px' }}>
        <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
          Recent Network Activity
        </h3>
        <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
          Latest captured packets — illustrative sample data
        </p>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 640 }}>
          <thead>
            <tr style={{ borderTop: '1px solid #1E2D45' }}>
              {COLS.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  style={{
                    padding: '10px 16px',
                    textAlign: 'left',
                    color: '#64748B',
                    fontSize: 11,
                    fontWeight: 600,
                    letterSpacing: '0.06em',
                    textTransform: 'uppercase',
                    background: '#0D1726',
                    cursor: 'pointer',
                    userSelect: 'none',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    {col.label}
                    <SortIcon col={col.key} sort={sort} />
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((pkt, i) => {
              const proto = PROTOCOL_COLORS[pkt.protocol] ?? PROTOCOL_COLORS.Other;
              const status = STATUS_STYLES[pkt.status];
              return (
                <tr
                  key={pkt.id}
                  style={{
                    borderTop: '1px solid #1E2D45',
                    background: i % 2 === 0 ? 'transparent' : 'rgba(13, 23, 38, 0.3)',
                  }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLTableRowElement).style.background = 'rgba(66, 214, 197, 0.03)';
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLTableRowElement).style.background =
                      i % 2 === 0 ? 'transparent' : 'rgba(13, 23, 38, 0.3)';
                  }}
                >
                  <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                    {formatTimestamp(pkt.timestamp)}
                  </td>
                  <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                    {pkt.sourceIp}
                  </td>
                  <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                    {pkt.destinationIp}
                  </td>
                  <td style={{ padding: '10px 16px' }}>
                    <span
                      style={{
                        background: proto.bg,
                        color: proto.color,
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '2px 8px',
                        borderRadius: 4,
                        letterSpacing: '0.03em',
                      }}
                    >
                      {pkt.protocol}
                    </span>
                  </td>
                  <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                    {pkt.packetSize} B
                  </td>
                  <td style={{ padding: '10px 16px' }}>
                    <span
                      style={{
                        background: status.bg,
                        color: status.color,
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '2px 8px',
                        borderRadius: 4,
                      }}
                    >
                      {status.label}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
