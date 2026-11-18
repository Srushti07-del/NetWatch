/**
 * LiveTrafficPage.tsx
 *
 * Packet inspection interface for the NetWatch dashboard.
 * Fetches packets through the centralized API service and useApi hook.
 * Demo mode uses sample data; API mode uses the configured backend.
 * No real-time capture, no fake streaming, no invented payloads.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Copy,
  RefreshCw,
  Search,
  X,
} from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api, IS_DEMO_MODE } from '../services/api';
import type { NetworkPacket, PacketStatus, Protocol } from '../types';
import { formatCompact, formatTimestamp } from '../lib/formatters';

const PAGE_SIZE = 15;

const STATUS_STYLES: Record<PacketStatus, { bg: string; color: string; label: string }> = {
  allowed:   { bg: 'rgba(16, 185, 129, 0.1)',  color: '#10B981', label: 'Allowed' },
  blocked:   { bg: 'rgba(239, 68, 68, 0.1)',   color: '#EF4444', label: 'Blocked' },
  flagged:   { bg: 'rgba(245, 158, 11, 0.1)',  color: '#F59E0B', label: 'Flagged' },
  monitored: { bg: 'rgba(59, 130, 246, 0.1)',  color: '#3B82F6', label: 'Monitored' },
};

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

const PROTOCOL_OPTIONS: ReadonlyArray<Protocol | 'All'> = [
  'All', 'TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'ICMP', 'ARP', 'Other',
];

const STATUS_OPTIONS: ReadonlyArray<PacketStatus | 'All'> = [
  'All', 'allowed', 'blocked', 'flagged', 'monitored',
];

interface SortState {
  key: keyof NetworkPacket;
  direction: 'asc' | 'desc';
}

export function LiveTrafficPage() {
  const packetsResult = useApi(() => api.getRecentPackets(100));

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<Protocol | 'All'>('All');
  const [statusFilter, setStatusFilter] = useState<PacketStatus | 'All'>('All');

  // Sort state
  const [sort, setSort] = useState<SortState | null>({
    key: 'timestamp',
    direction: 'desc',
  });

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);

  // Selection state
  const [selectedPacketId, setSelectedPacketId] = useState<string | null>(null);
  const drawerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  // Copy feedback state
  const [copyFeedback, setCopyFeedback] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  // Dismiss copy feedback after a short delay
  useEffect(() => {
    if (!copyFeedback) return;
    const timer = setTimeout(() => setCopyFeedback(null), 3000);
    return () => clearTimeout(timer);
  }, [copyFeedback]);

  // Escape key closes the drawer; manage focus when drawer opens/closes
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedPacketId(null);
      }
    };
    if (selectedPacketId) {
      document.addEventListener('keydown', handleKeyDown);
      const drawer = drawerRef.current;
      if (drawer) {
        drawer.setAttribute('tabindex', '-1');
        drawer.focus();
      }
      return () => {
        document.removeEventListener('keydown', handleKeyDown);
        if (drawer) {
          drawer.removeAttribute('tabindex');
        }
        // Restore focus to the element that opened the drawer
        const trigger = triggerRef.current;
        if (trigger) {
          trigger.focus();
          triggerRef.current = null;
        }
      };
    }
    return undefined;
  }, [selectedPacketId]);

  // Trap Tab focus inside the drawer while it is open
  const handleDrawerKeyDown = useCallback((e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Tab') return;
    e.preventDefault();
    const drawer = drawerRef.current;
    if (!drawer) return;
    const focusables = drawer.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusables.length === 0) return;
    const currentIndex = Array.from(focusables).indexOf(
      document.activeElement as HTMLElement
    );
    let nextIndex: number;
    if (e.shiftKey) {
      nextIndex = currentIndex <= 0 ? focusables.length - 1 : currentIndex - 1;
    } else {
      nextIndex = currentIndex >= focusables.length - 1 ? 0 : currentIndex + 1;
    }
    focusables[nextIndex]?.focus();
  }, []);

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
    ? 'Illustrative sample data — not live traffic.'
    : 'Packet data from the configured API backend.';
  useEffect(() => {
    setCurrentPage(1);
  }, [packetsResult.data, searchQuery, protocolFilter, statusFilter]);

  // Derived: filtered packets
  const filtered = useMemo(() => {
    const packets = packetsResult.data ?? [];
    const q = searchQuery.toLowerCase();
    return packets.filter((pkt) => {
      const matchesSearch =
        pkt.sourceIp.toLowerCase().includes(q) ||
        pkt.destinationIp.toLowerCase().includes(q) ||
        String(pkt.sourcePort).includes(q) ||
        String(pkt.destinationPort).includes(q);
      const matchesProtocol = protocolFilter === 'All' || pkt.protocol === protocolFilter;
      const matchesStatus = statusFilter === 'All' || pkt.status === statusFilter;
      return matchesSearch && matchesProtocol && matchesStatus;
    });
  }, [packetsResult.data, searchQuery, protocolFilter, statusFilter]);

  // Derived: sorted packets
  const sorted = useMemo(() => {
    if (!sort) return [...filtered];
    return [...filtered].sort((a, b) => {
      const aVal = a[sort.key];
      const bVal = b[sort.key];
      const dir = sort.direction === 'asc' ? 1 : -1;
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return (aVal - bVal) * dir;
      }
      return String(aVal).localeCompare(String(bVal)) * dir;
    });
  }, [filtered, sort]);

  // Derived: pagination
  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const clampedPage = Math.min(currentPage, totalPages);
  const start = (clampedPage - 1) * PAGE_SIZE;
  const paginated = sorted.slice(start, start + PAGE_SIZE);

  const packets = packetsResult.data ?? [];

  // Derived: metrics from the complete loaded dataset (not filtered)
  const totalPackets = packets.length;
  const allowedPackets = packets.filter((p) => p.status === 'allowed').length;
  const blockedPackets = packets.filter((p) => p.status === 'blocked').length;
  const flaggedPackets = packets.filter((p) => p.status === 'flagged').length;

  // Derived: selected packet
  const selectedPacket = sorted.find((p) => p.id === selectedPacketId) ?? null;

  // Handlers
  const handleRefresh = packetsResult.refetch;

  const handleClearFilters = useCallback(() => {
    setSearchQuery('');
    setProtocolFilter('All');
    setStatusFilter('All');
  }, []);

  const handleSort = useCallback((key: keyof NetworkPacket) => {
    setSort((prev) => {
      if (prev?.key === key) {
        return { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
      }
      return { key, direction: 'asc' };
    });
  }, []);

  const handleSelect = useCallback((id: string | null, trigger?: HTMLElement | null) => {
    setSelectedPacketId(id);
    if (trigger) {
      triggerRef.current = trigger;
    } else if (!id) {
      triggerRef.current = null;
    }
  }, []);

  const handlePageChange = useCallback((page: number) => {
    setCurrentPage(page);
  }, []);

  // Loading state
  if (packetsResult.loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Live Traffic
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Packet-level network inspection.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ color: '#94A3B8', fontSize: 13, paddingTop: 8 }}>Loading packets…</div>
      </div>
    );
  }

  // Error state
  if (packetsResult.error) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Live Traffic
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Packet-level network inspection.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: IS_DEMO_MODE ? 'rgba(66, 214, 197, 0.08)' : 'rgba(59, 130, 246, 0.08)', border: IS_DEMO_MODE ? '1px solid rgba(66, 214, 197, 0.2)' : '1px solid rgba(59, 130, 246, 0.2)', borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6', boxShadow: IS_DEMO_MODE ? '0 0 6px rgba(66, 214, 197, 0.6)' : '0 0 6px rgba(59, 130, 246, 0.6)' }} />
            <span style={{ color: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6', fontSize: 12, fontWeight: 600 }}>
              {IS_DEMO_MODE ? 'Demo Mode' : 'API Mode'}
            </span>
          </div>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 24, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
          <span style={{ color: '#EF4444', fontSize: 13, fontWeight: 600 }}>Failed to load packets</span>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{packetsResult.error}</span>
          <button onClick={handleRefresh} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Empty state: no data at all
  if (packets.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Live Traffic
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              {sampleNote}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 48, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
          <span style={{ color: '#94A3B8', fontSize: 13 }}>No packets available</span>
          <button onClick={handleRefresh} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
            Refresh
          </button>
        </div>
      </div>
    );
  }

  // Main content
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20, minHeight: 0 }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
            Live Traffic
          </h2>
          <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
            {sampleNote}
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
          <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
        </div>
      </div>

      {/* Summary metrics */}
      <div className="dashboard-metrics-grid">
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Total Packets</span>
          <span style={{ color: '#F1F5F9', fontSize: 24, fontWeight: 700 }}>{formatCompact(totalPackets)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Allowed</span>
          <span style={{ color: '#10B981', fontSize: 24, fontWeight: 700 }}>{formatCompact(allowedPackets)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Blocked</span>
          <span style={{ color: '#EF4444', fontSize: 24, fontWeight: 700 }}>{formatCompact(blockedPackets)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Flagged</span>
          <span style={{ color: '#F59E0B', fontSize: 24, fontWeight: 700 }}>{formatCompact(flaggedPackets)}</span>
        </div>
      </div>

      {/* Filters + controls */}
      <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Search size={14} color="#64748B" />
            <input
              type="text"
              placeholder="Search source/dest IP or port…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                flex: 1,
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
                fontFamily: 'inherit',
              }}
            />
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value as Protocol | 'All')}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
                fontFamily: 'inherit',
                minWidth: 150,
                cursor: 'pointer',
              }}
            >
              {PROTOCOL_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt === 'All' ? 'All Protocols' : opt}
                </option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as PacketStatus | 'All')}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
                fontFamily: 'inherit',
                minWidth: 150,
                cursor: 'pointer',
              }}
            >
              {STATUS_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt === 'All' ? 'All Statuses' : opt.charAt(0).toUpperCase() + opt.slice(1)}
                </option>
              ))}
            </select>
            <button
              onClick={handleClearFilters}
              disabled={searchQuery === '' && protocolFilter === 'All' && statusFilter === 'All'}
              style={{
                background: '#1E2D45',
                border: '1px solid #2a3f5f',
                borderRadius: 8,
                color: '#94A3B8',
                padding: '8px 16px',
                fontSize: 13,
                cursor: 'pointer',
                opacity: (searchQuery === '' && protocolFilter === 'All' && statusFilter === 'All') ? 0.5 : 1,
              }}
            >
              Clear Filters
            </button>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', borderTop: '1px solid #1E2D45', marginTop: 8, paddingTop: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{sorted.length} matching packets</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: '#94A3B8', fontSize: 12 }}>Page {clampedPage} of {totalPages}</span>
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
          </div>
        </div>
      </div>

      {/* Packet table */}
      {sorted.length === 0 ? (
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 48, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
          <span style={{ color: '#94A3B8', fontSize: 13 }}>No packets match your filters</span>
          <button onClick={handleClearFilters} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
            Clear Filters
          </button>
        </div>
      ) : (
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '16px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
                Packet Inspection
              </h3>
              <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
                Select a packet to view full details
              </p>
            </div>
            <span style={{ color: '#94A3B8', fontSize: 12 }}>{paginated.length} of {sorted.length} shown</span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 700 }}>
              <thead>
                <tr style={{ borderTop: '1px solid #1E2D45', borderBottom: '1px solid #1E2D45' }}>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('timestamp')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Timestamp
                        {sort?.key === 'timestamp' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('sourceIp')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Source IP
                        {sort?.key === 'sourceIp' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('sourcePort')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Src Port
                        {sort?.key === 'sourcePort' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('destinationIp')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Destination IP
                        {sort?.key === 'destinationIp' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('destinationPort')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Dst Port
                        {sort?.key === 'destinationPort' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('protocol')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Protocol
                        {sort?.key === 'protocol' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('packetSize')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Size
                        {sort?.key === 'packetSize' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    <button
                      onClick={() => handleSort('status')}
                      type="button"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#F1F5F9',
                        font: 'inherit',
                        fontSize: 11,
                        fontWeight: 600,
                        textAlign: 'left',
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        width: '100%',
                        padding: 0,
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Status
                        {sort?.key === 'status' && (
                          sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                        )}
                      </div>
                    </button>
                  </th>
                  <th style={{ padding: '10px 16px', textAlign: 'center', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {paginated.map((pkt) => {
                  const proto = PROTOCOL_COLORS[pkt.protocol] ?? PROTOCOL_COLORS.Other;
                  const status = STATUS_STYLES[pkt.status];
                  const isSelected = pkt.id === selectedPacketId;
                  return (
                    <tr
                      key={pkt.id}
                      role="button"
                      tabIndex={0}
                      aria-label={`Select packet ${pkt.id} for details`}
                      aria-pressed={isSelected}
                      style={{
                        borderTop: '1px solid #1E2D45',
                        background: isSelected
                          ? 'rgba(66, 214, 197, 0.06)'
                          : 'transparent',
                        cursor: 'pointer',
                      }}
                      onMouseEnter={(e) => {
                        (e.currentTarget as HTMLTableRowElement).style.background = 'rgba(66, 214, 197, 0.03)';
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLTableRowElement).style.background = isSelected
                          ? 'rgba(66, 214, 197, 0.06)'
                          : 'transparent';
                      }}
                      onClick={(e) => handleSelect(pkt.id, e.currentTarget as HTMLElement)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleSelect(pkt.id, e.currentTarget as HTMLElement);
                        }
                      }}
                    >
                      <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                        {formatTimestamp(pkt.timestamp)}
                      </td>
                      <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                        {pkt.sourceIp}
                      </td>
                      <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                        {pkt.sourcePort}
                      </td>
                      <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                        {pkt.destinationIp}
                      </td>
                      <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                        {pkt.destinationPort}
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
                        {formatCompact(pkt.packetSize)} B
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
                      <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleSelect(pkt.id); }}
                          type="button"
                          style={{
                            background: 'transparent',
                            border: 'none',
                            color: '#64748B',
                            cursor: 'pointer',
                            fontSize: 12,
                            padding: '2px 6px',
                            borderRadius: 4,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                          }}
                          aria-label={`View packet ${pkt.id} details`}
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination controls */}
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8, padding: 12, borderTop: '1px solid #1E2D45' }}>
            <button
              onClick={() => handlePageChange(clampedPage - 1)}
              disabled={clampedPage <= 1}
              style={{
                background: '#1E2D45',
                border: '1px solid #2a3f5f',
                borderRadius: 6,
                color: '#94A3B8',
                padding: '6px 12px',
                fontSize: 13,
                cursor: clampedPage <= 1 ? 'not-allowed' : 'pointer',
                opacity: clampedPage <= 1 ? 0.5 : 1,
              }}
            >
              Prev
            </button>
            <span style={{ color: '#94A3B8', fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
              {clampedPage} of {totalPages}
            </span>
            <button
              onClick={() => handlePageChange(clampedPage + 1)}
              disabled={clampedPage >= totalPages}
              style={{
                background: '#1E2D45',
                border: '1px solid #2a3f5f',
                borderRadius: 6,
                color: '#94A3B8',
                padding: '6px 12px',
                fontSize: 13,
                cursor: clampedPage >= totalPages ? 'not-allowed' : 'pointer',
                opacity: clampedPage >= totalPages ? 0.5 : 1,
              }}
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Packet details drawer */}
      {selectedPacket && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.5)',
            zIndex: 100,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setSelectedPacketId(null);
            }
          }}
        >
          <div
            style={{
              width: '420px',
              maxWidth: '92vw',
              background: '#141F30',
              border: '1px solid #1E2D45',
              boxShadow: '-4px 0 24px rgba(0, 0, 0, 0.6)',
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              overflowY: 'auto',
            }}
            role="dialog"
            aria-modal="true"
            aria-label="Packet details"
            ref={drawerRef}
            onKeyDown={handleDrawerKeyDown}
          >
            <div style={{ padding: '20px 24px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 16, fontWeight: 600 }}>
                Packet Details
              </h3>
              <button
                onClick={() => setSelectedPacketId(null)}
                style={{ background: 'transparent', border: 'none', color: '#94A3B8', cursor: 'pointer', padding: 4 }}
                aria-label="Close packet details"
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ padding: 24, display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Packet ID</span>
                <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedPacket.id}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Timestamp</span>
                <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{formatTimestamp(selectedPacket.timestamp)}</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Source IP</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedPacket.sourceIp}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Source Port</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13 }}>{selectedPacket.sourcePort}</span>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Destination IP</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedPacket.destinationIp}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Destination Port</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13 }}>{selectedPacket.destinationPort}</span>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Protocol</span>
                  <span
                    style={{
                      background: PROTOCOL_COLORS[selectedPacket.protocol]?.bg ?? PROTOCOL_COLORS.Other.bg,
                      color: PROTOCOL_COLORS[selectedPacket.protocol]?.color ?? PROTOCOL_COLORS.Other.color,
                      fontSize: 11,
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: 4,
                      display: 'inline-block',
                    }}
                  >
                    {selectedPacket.protocol}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Packet Size</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontVariantNumeric: 'tabular-nums' }}>{formatCompact(selectedPacket.packetSize)} B</span>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Status</span>
                  <span
                    style={{
                      background: STATUS_STYLES[selectedPacket.status].bg,
                      color: STATUS_STYLES[selectedPacket.status].color,
                      fontSize: 11,
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: 4,
                      display: 'inline-block',
                    }}
                  >
                    {STATUS_STYLES[selectedPacket.status].label}
                  </span>
                </div>
                {selectedPacket.ttl !== undefined && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>TTL</span>
                    <span style={{ color: '#F1F5F9', fontSize: 13 }}>{selectedPacket.ttl}</span>
                  </div>
                )}
              </div>
            </div>

            <div style={{ padding: '16px 24px', borderTop: '1px solid #1E2D45', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                onClick={() => setSelectedPacketId(null)}
                style={{
                  background: '#1E2D45',
                  border: '1px solid #2a3f5f',
                  borderRadius: 6,
                  color: '#94A3B8',
                  padding: '8px 16px',
                  fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                Close
              </button>
              <button
                onClick={async () => {
                  if (!selectedPacket) return;
                  const text = `${selectedPacket.id} | ${selectedPacket.sourceIp}:${selectedPacket.sourcePort} -> ${selectedPacket.destinationIp}:${selectedPacket.destinationPort} | ${selectedPacket.protocol} | ${selectedPacket.status}`;
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
                }}
                style={{
                  background: '#3B82F6',
                  border: 'none',
                  borderRadius: 6,
                  color: '#F1F5F9',
                  padding: '8px 16px',
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                <Copy size={14} style={{ marginRight: 6 }} />
                Copy Summary
              </button>
              {copyFeedback && (
                <span
                  style={{
                    fontSize: 12,
                    fontWeight: 600,
                    padding: '6px 10px',
                    borderRadius: 4,
                    background: copyFeedback.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                    color: copyFeedback.type === 'success' ? '#10B981' : '#EF4444',
                    border: copyFeedback.type === 'success' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
                  }}
                >
                  {copyFeedback.message}
                </span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
