/**
 * DevicesPage.tsx
 *
 * Network device inventory dashboard.
 * Fetches devices through the centralized API service and useApi hook.
 * Demo mode uses sample data; API mode uses the configured backend.
 * No real-time discovery, no fake monitoring indicators.
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
import type { Device } from '../types';
import { formatCompact, formatTimestamp } from '../lib/formatters';

const PAGE_SIZE = 10;

const DEVICE_TYPE_OPTIONS: ReadonlyArray<Device['deviceType'] | 'All'> = [
  'All', 'server', 'workstation', 'mobile', 'iot', 'router', 'switch', 'unknown',
];

const STATUS_STYLES: Record<'active' | 'inactive', { bg: string; color: string; label: string }> = {
  active:   { bg: 'rgba(16, 185, 129, 0.1)',  color: '#10B981', label: 'Presence Confirmed' },
  inactive: { bg: 'rgba(100, 116, 139, 0.12)', color: '#94A3B8', label: 'Presence Unconfirmed' },
};

const DEVICE_TYPE_COLORS: Record<Device['deviceType'], { bg: string; color: string }> = {
  server:   { bg: 'rgba(59, 130, 246, 0.12)', color: '#3B82F6' },
  workstation: { bg: 'rgba(139, 92, 246, 0.12)', color: '#8B5CF6' },
  mobile:   { bg: 'rgba(245, 158, 11, 0.12)', color: '#F59E0B' },
  iot:      { bg: 'rgba(236, 72, 153, 0.12)', color: '#EC4899' },
  router:   { bg: 'rgba(66, 214, 197, 0.12)', color: '#42D6C5' },
  switch:   { bg: 'rgba(100, 116, 139, 0.12)', color: '#64748B' },
  unknown:  { bg: 'rgba(100, 116, 139, 0.12)', color: '#64748B' },
};

interface SortState {
  key: keyof Device;
  direction: 'asc' | 'desc';
}

export function DevicesPage() {
  const devicesResult = useApi(() => api.getDevices());

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [deviceTypeFilter, setDeviceTypeFilter] = useState<Device['deviceType'] | 'All'>('All');
  const [statusFilter, setStatusFilter] = useState<'All' | 'active' | 'inactive'>('All');

  // Sort state
  const [sort, setSort] = useState<SortState | null>({
    key: 'hostname',
    direction: 'asc',
  });

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);

  // Selection state
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
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
        setSelectedDeviceId(null);
      }
    };
    if (selectedDeviceId) {
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
        const trigger = triggerRef.current;
        if (trigger) {
          trigger.focus();
          triggerRef.current = null;
        }
      };
    }
    return undefined;
  }, [selectedDeviceId]);

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
    ? 'Illustrative sample data — not live network inventory.'
    : 'Observed device inventory from historical PCAP capture — not live network presence.';

  // Reset page when data or filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [devicesResult.data, searchQuery, deviceTypeFilter, statusFilter]);

  const devices = devicesResult.data ?? [];

  // Derived: filtered devices
  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return devices.filter((dev) => {
      const matchesSearch =
        dev.hostname.toLowerCase().includes(q) ||
        dev.ipAddress.toLowerCase().includes(q) ||
        (dev.macAddress?.toLowerCase().includes(q) ?? false);
      const matchesType = deviceTypeFilter === 'All' || dev.deviceType === deviceTypeFilter;
      const matchesStatus = statusFilter === 'All' || (dev.isActive ? 'active' : 'inactive') === statusFilter;
      return matchesSearch && matchesType && matchesStatus;
    });
  }, [devices, searchQuery, deviceTypeFilter, statusFilter]);

  // Derived: sorted devices
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

  // Derived: metrics from the complete loaded dataset (not filtered)
  const totalDevices = devices.length;
  const activeDevices = devices.filter((d) => d.isActive).length;
  const inactiveDevices = devices.filter((d) => !d.isActive).length;

  // Derived: selected device
  const selectedDevice = sorted.find((d) => d.id === selectedDeviceId) ?? null;

  // Handlers
  const handleRefresh = devicesResult.refetch;

  const handleClearFilters = useCallback(() => {
    setSearchQuery('');
    setDeviceTypeFilter('All');
    setStatusFilter('All');
  }, []);

  const handleSort = useCallback((key: keyof Device) => {
    setSort((prev) => {
      if (prev?.key === key) {
        return { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
      }
      return { key, direction: 'asc' };
    });
  }, []);

  const handleSelect = useCallback((id: string | null, trigger?: HTMLElement | null) => {
    setSelectedDeviceId(id);
    if (trigger) {
      triggerRef.current = trigger;
    } else if (!id) {
      triggerRef.current = null;
    }
  }, []);

  const handlePageChange = useCallback((page: number) => {
    setCurrentPage(page);
  }, []);

  const handleCopySummary = useCallback(async () => {
    if (!selectedDevice) return;
    const text = `${selectedDevice.id} | ${selectedDevice.hostname} | ${selectedDevice.ipAddress} | ${selectedDevice.macAddress ?? 'N/A'} | ${selectedDevice.deviceType} | ${selectedDevice.isActive ? 'Presence Confirmed' : 'Presence Unconfirmed'}`;
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
  }, [selectedDevice]);

  // Loading state
  if (devicesResult.loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Devices
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Network device inventory and monitoring.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ color: '#94A3B8', fontSize: 13, paddingTop: 8 }}>Loading devices…</div>
      </div>
    );
  }

  // Error state
  if (devicesResult.error) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Devices
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Network device inventory and monitoring.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 24, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
          <span style={{ color: '#EF4444', fontSize: 13, fontWeight: 600 }}>Failed to load devices</span>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{devicesResult.error}</span>
          <button onClick={handleRefresh} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Empty dataset state: no data at all
  if (devices.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Devices
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
          <span style={{ color: '#94A3B8', fontSize: 13 }}>No devices available</span>
          <button onClick={handleRefresh} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
            Refresh
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
            Devices
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
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Observed Devices</span>
          <span style={{ color: '#F1F5F9', fontSize: 24, fontWeight: 700 }}>{formatCompact(totalDevices)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Presence Confirmed</span>
          <span style={{ color: '#10B981', fontSize: 24, fontWeight: 700 }}>{formatCompact(activeDevices)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Presence Unconfirmed</span>
          <span style={{ color: '#94A3B8', fontSize: 24, fontWeight: 700 }}>{formatCompact(inactiveDevices)}</span>
        </div>
      </div>

      {/* Filters + controls */}
      <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Search size={14} color="#64748B" />
            <input
              type="text"
              placeholder="Search hostname, IP, or MAC…"
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
              value={deviceTypeFilter}
              onChange={(e) => setDeviceTypeFilter(e.target.value as Device['deviceType'] | 'All')}
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
              {DEVICE_TYPE_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt === 'All' ? 'All Types' : opt.charAt(0).toUpperCase() + opt.slice(1)}
                </option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'All' | 'active' | 'inactive')}
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
              <option value="All">All Presence States</option>
              <option value="active">Presence Confirmed</option>
              <option value="inactive">Presence Unconfirmed</option>
            </select>
            <button
              onClick={handleClearFilters}
              disabled={searchQuery === '' && deviceTypeFilter === 'All' && statusFilter === 'All'}
              style={{
                background: '#1E2D45',
                border: '1px solid #2a3f5f',
                borderRadius: 8,
                color: '#94A3B8',
                padding: '8px 16px',
                fontSize: 13,
                cursor: 'pointer',
                opacity: (searchQuery === '' && deviceTypeFilter === 'All' && statusFilter === 'All') ? 0.5 : 1,
              }}
            >
              Clear Filters
            </button>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', borderTop: '1px solid #1E2D45', marginTop: 8, paddingTop: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{sorted.length} matching devices</span>
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

      {/* Device inventory table */}
      <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {sorted.length === 0 ? (
          <div style={{ padding: 48, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
            <span style={{ color: '#94A3B8', fontSize: 13 }}>No devices match your filters</span>
            <button onClick={handleClearFilters} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
              Clear Filters
            </button>
          </div>
        ) : (
          <>
            <div style={{ padding: '16px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
                  Observed Device Inventory
                </h3>
                <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
                  Private unicast endpoints observed in packet capture. Select a device to view full details.
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
                        onClick={() => handleSort('hostname')}
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
                          Device / Host
                          {sort?.key === 'hostname' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => handleSort('ipAddress')}
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
                          IP Address
                          {sort?.key === 'ipAddress' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => handleSort('macAddress')}
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
                          MAC Address
                          {sort?.key === 'macAddress' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => handleSort('deviceType')}
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
                          Device Type
                          {sort?.key === 'deviceType' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => handleSort('isActive')}
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
                          Presence
                          {sort?.key === 'isActive' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => handleSort('lastSeen')}
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
                          Last Seen
                          {sort?.key === 'lastSeen' && (
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
                  {paginated.map((dev) => {
                    const typeStyle = DEVICE_TYPE_COLORS[dev.deviceType] ?? DEVICE_TYPE_COLORS.unknown;
                    const isSelected = dev.id === selectedDeviceId;
                    return (
                      <tr
                        key={dev.id}
                        role="button"
                        tabIndex={0}
                        aria-label={`Select device ${dev.hostname} for details`}
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
                        onClick={(e) => handleSelect(dev.id, e.currentTarget as HTMLElement)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleSelect(dev.id, e.currentTarget as HTMLElement);
                          }
                        }}
                      >
                        <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, whiteSpace: 'nowrap' }}>
                          {dev.hostname}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                          {dev.ipAddress}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                          {dev.macAddress || '— (Not observed)'}
                        </td>
                        <td style={{ padding: '10px 16px' }}>
                          <span
                            style={{
                              background: typeStyle.bg,
                              color: typeStyle.color,
                              fontSize: 11,
                              fontWeight: 600,
                              padding: '2px 8px',
                              borderRadius: 4,
                              letterSpacing: '0.03em',
                              textTransform: 'uppercase',
                            }}
                          >
                            {dev.deviceType}
                          </span>
                        </td>
                        <td style={{ padding: '10px 16px' }}>
                          <span
                            style={{
                              background: STATUS_STYLES[dev.isActive ? 'active' : 'inactive'].bg,
                              color: STATUS_STYLES[dev.isActive ? 'active' : 'inactive'].color,
                              fontSize: 11,
                              fontWeight: 600,
                              padding: '2px 8px',
                              borderRadius: 4,
                            }}
                          >
                            {STATUS_STYLES[dev.isActive ? 'active' : 'inactive'].label}
                          </span>
                        </td>
                        <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, whiteSpace: 'nowrap' }}>
                          {formatTimestamp(dev.lastSeen)}
                        </td>
                        <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                          <button
                            onClick={(e) => { e.stopPropagation(); handleSelect(dev.id); }}
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
                            aria-label={`View device ${dev.id} details`}
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
          </>
        )}
      </div>

      {/* Device details drawer */}
      {selectedDevice && (
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
              setSelectedDeviceId(null);
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
            aria-label="Device details"
            ref={drawerRef}
            onKeyDown={handleDrawerKeyDown}
          >
            <div style={{ padding: '20px 24px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 16, fontWeight: 600 }}>
                Device Details
              </h3>
              <button
                onClick={() => setSelectedDeviceId(null)}
                style={{ background: 'transparent', border: 'none', color: '#94A3B8', cursor: 'pointer', padding: 4 }}
                aria-label="Close device details"
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ padding: 24, display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Device ID</span>
                <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedDevice.id}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Hostname / IP Endpoint</span>
                <span style={{ color: '#F1F5F9', fontSize: 13 }}>
                  {selectedDevice.hostname === selectedDevice.ipAddress
                    ? `${selectedDevice.hostname} (No DNS PTR recorded)`
                    : selectedDevice.hostname}
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>IP Address</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedDevice.ipAddress}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>MAC Address</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>
                    {selectedDevice.macAddress || '— (Not observed in capture)'}
                  </span>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Device Type</span>
                  <span
                    style={{
                      background: DEVICE_TYPE_COLORS[selectedDevice.deviceType]?.bg ?? DEVICE_TYPE_COLORS.unknown.bg,
                      color: DEVICE_TYPE_COLORS[selectedDevice.deviceType]?.color ?? DEVICE_TYPE_COLORS.unknown.color,
                      fontSize: 11,
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: 4,
                      display: 'inline-block',
                      textTransform: 'uppercase',
                    }}
                  >
                    {selectedDevice.deviceType}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Presence Status</span>
                  <span
                    style={{
                      background: STATUS_STYLES[selectedDevice.isActive ? 'active' : 'inactive'].bg,
                      color: STATUS_STYLES[selectedDevice.isActive ? 'active' : 'inactive'].color,
                      fontSize: 11,
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: 4,
                      display: 'inline-block',
                    }}
                  >
                    {STATUS_STYLES[selectedDevice.isActive ? 'active' : 'inactive'].label}
                  </span>
                  {!selectedDevice.isActive && (
                    <span style={{ color: '#64748B', fontSize: 11 }}>Live status unavailable from offline capture</span>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Last Seen</span>
                <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{formatTimestamp(selectedDevice.lastSeen)}</span>
              </div>
              {selectedDevice.operatingSystem && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Operating System</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13 }}>{selectedDevice.operatingSystem}</span>
                </div>
              )}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Traffic In (Capture)</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontVariantNumeric: 'tabular-nums' }}>{formatCompact(selectedDevice.trafficIn)} B</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Traffic Out (Capture)</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontVariantNumeric: 'tabular-nums' }}>{formatCompact(selectedDevice.trafficOut)} B</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Open Ports</span>
                <span style={{ color: '#F1F5F9', fontSize: 13 }}>
                  {selectedDevice.openPorts.length > 0 ? selectedDevice.openPorts.join(', ') : '—'}
                </span>
              </div>
            </div>

            <div style={{ padding: '16px 24px', borderTop: '1px solid #1E2D45', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                onClick={() => setSelectedDeviceId(null)}
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
                onClick={handleCopySummary}
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
