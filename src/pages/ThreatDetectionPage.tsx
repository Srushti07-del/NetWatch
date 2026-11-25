/**
 * ThreatDetectionPage.tsx
 *
 * Security-event investigation interface.
 * Fetches events through the centralized API service and useApi hook.
 * Demo mode uses sample data; API mode uses the configured backend.
 * No real-time threat engine, no fake event streaming, no invented data.
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
import type { SecurityEvent, Severity } from '../types';
import { formatCompact, formatTimestamp } from '../lib/formatters';

const PAGE_SIZE = 10;

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_STYLES: Record<Severity, { bg: string; color: string; label: string }> = {
  critical: { bg: 'rgba(239, 68, 68, 0.1)', color: '#EF4444', label: 'Critical' },
  high:     { bg: 'rgba(249, 115, 22, 0.1)', color: '#F97316', label: 'High' },
  medium:   { bg: 'rgba(245, 158, 11, 0.1)', color: '#F59E0B', label: 'Medium' },
  low:      { bg: 'rgba(59, 130, 246, 0.1)', color: '#3B82F6', label: 'Low' },
  info:     { bg: 'rgba(100, 116, 139, 0.1)', color: '#64748B', label: 'Info' },
};

const EVENT_TYPE_LABELS: Record<string, string> = {
  port_scan:           'Port Scan',
  brute_force:         'Brute Force',
  anomaly:             'Anomaly',
  policy_violation:    'Policy Violation',
  malware_signature:   'Malware Signature',
  dos_attempt:         'DoS Attempt',
  unauthorized_access: 'Unauthorized Access',
  data_exfiltration:   'Data Exfiltration',
};

const EVENT_TYPE_OPTIONS: ReadonlyArray<string> = [
  'All', 'port_scan', 'brute_force', 'anomaly', 'policy_violation',
  'malware_signature', 'dos_attempt', 'unauthorized_access', 'data_exfiltration',
];

const SEVERITY_OPTIONS: ReadonlyArray<Severity | 'All'> = [
  'All', 'critical', 'high', 'medium', 'low', 'info',
];

const RESOLUTION_OPTIONS: ReadonlyArray<'All' | 'resolved' | 'unresolved'> = [
  'All', 'resolved', 'unresolved',
];

interface SortState {
  key: keyof SecurityEvent | 'severity';
  direction: 'asc' | 'desc';
}

export function ThreatDetectionPage() {
  const eventsResult = useApi((signal) => api.getSecurityEvents(signal));

  // Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'All'>('All');
  const [eventTypeFilter, setEventTypeFilter] = useState<string | 'All'>('All');
  const [resolutionFilter, setResolutionFilter] = useState<'All' | 'resolved' | 'unresolved'>('All');

  // Sort state
  const [sort, setSort] = useState<SortState | null>({
    key: 'timestamp',
    direction: 'desc',
  });

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);

  // Selection state
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
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
        setSelectedEventId(null);
      }
    };
    if (selectedEventId) {
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
  }, [selectedEventId]);

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
    ? 'Illustrative sample security events — not live threat detection.'
    : 'Security event data from the configured API backend.';

  // Reset page when data or filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [eventsResult.data, searchQuery, severityFilter, eventTypeFilter, resolutionFilter]);

  const events = eventsResult.data ?? [];

  // Derived: filtered events
  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return events.filter((evt) => {
      const matchesSearch =
        evt.title.toLowerCase().includes(q) ||
        evt.description.toLowerCase().includes(q) ||
        evt.sourceIp.toLowerCase().includes(q) ||
        (evt.destinationIp ?? '').toLowerCase().includes(q);
      const matchesSeverity = severityFilter === 'All' || evt.severity === severityFilter;
      const matchesType = eventTypeFilter === 'All' || evt.eventType === eventTypeFilter;
      const matchesResolution =
        resolutionFilter === 'All'
          ? true
          : resolutionFilter === 'resolved'
            ? evt.resolved
            : !evt.resolved;
      return matchesSearch && matchesSeverity && matchesType && matchesResolution;
    });
  }, [events, searchQuery, severityFilter, eventTypeFilter, resolutionFilter]);

  // Derived: sorted events (does not mutate original data)
  const sorted = useMemo(() => {
    if (!sort) return [...filtered];
    return [...filtered].sort((a, b) => {
      if (sort.key === 'severity') {
        const aRank = SEVERITY_ORDER[a.severity];
        const bRank = SEVERITY_ORDER[b.severity];
        return sort.direction === 'asc' ? aRank - bRank : bRank - aRank;
      }
      if (sort.key === 'timestamp') {
        const aTime = new Date(a.timestamp).getTime();
        const bTime = new Date(b.timestamp).getTime();
        return sort.direction === 'asc' ? aTime - bTime : bTime - aTime;
      }
      const aVal = a[sort.key];
      const bVal = b[sort.key];
      const dir = sort.direction === 'asc' ? 1 : -1;
      return String(aVal).localeCompare(String(bVal)) * dir;
    });
  }, [filtered, sort]);

  // Derived: pagination
  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const clampedPage = Math.min(currentPage, totalPages);
  const start = (clampedPage - 1) * PAGE_SIZE;
  const paginated = sorted.slice(start, start + PAGE_SIZE);

  // Derived: metrics from the complete loaded dataset (not filtered)
  const totalEvents = events.length;
  const criticalEvents = events.filter((e) => e.severity === 'critical').length;
  const unresolvedEvents = events.filter((e) => !e.resolved).length;
  const resolvedEvents = events.filter((e) => e.resolved).length;

  // Derived: selected event
  const selectedEvent = sorted.find((e) => e.id === selectedEventId) ?? null;

  // Handlers
  const handleRefresh = eventsResult.refetch;

  const handleClearFilters = useCallback(() => {
    setSearchQuery('');
    setSeverityFilter('All');
    setEventTypeFilter('All');
    setResolutionFilter('All');
  }, []);

  const handleSort = useCallback((key: keyof SecurityEvent | 'severity') => {
    setSort((prev) => {
      if (prev?.key === key) {
        return { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
      }
      return { key, direction: 'asc' };
    });
  }, []);

  const handleSelect = useCallback((id: string | null, trigger?: HTMLElement | null) => {
    setSelectedEventId(id);
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
    if (!selectedEvent) return;
    const text = `${selectedEvent.id} | ${selectedEvent.title} | ${selectedEvent.severity} | ${selectedEvent.eventType} | Source: ${selectedEvent.sourceIp} | ${selectedEvent.resolved ? 'Resolved' : 'Unresolved'}`;
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
  }, [selectedEvent]);

  // Loading state
  if (eventsResult.loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Threat Detection
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Security events, suspicious activity and incident investigation.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ color: '#94A3B8', fontSize: 13, paddingTop: 8 }}>Loading events…</div>
      </div>
    );
  }

  // Error state
  if (eventsResult.error) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Threat Detection
            </h2>
            <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
              Security events, suspicious activity and incident investigation.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: modeBadgeBg, border: modeBadgeBorder, borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: modeDotColor, boxShadow: modeDotShadow }} />
            <span style={{ color: modeDotColor, fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 24, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
          <span style={{ color: '#EF4444', fontSize: 13, fontWeight: 600 }}>Failed to load events</span>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{eventsResult.error}</span>
          <button onClick={handleRefresh} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Empty dataset state: no data at all
  if (events.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
              Threat Detection
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
          <span style={{ color: '#94A3B8', fontSize: 13 }}>No events available</span>
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
            Threat Detection
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
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Total Events</span>
          <span style={{ color: '#F1F5F9', fontSize: 24, fontWeight: 700 }}>{formatCompact(totalEvents)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Critical</span>
          <span style={{ color: '#EF4444', fontSize: 24, fontWeight: 700 }}>{formatCompact(criticalEvents)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Unresolved</span>
          <span style={{ color: '#F59E0B', fontSize: 24, fontWeight: 700 }}>{formatCompact(unresolvedEvents)}</span>
        </div>
        <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: '16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500 }}>Resolved</span>
          <span style={{ color: '#10B981', fontSize: 24, fontWeight: 700 }}>{formatCompact(resolvedEvents)}</span>
        </div>
      </div>

      {/* Filters + controls */}
      <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Search size={14} color="#64748B" />
            <input
              type="text"
              placeholder="Search title, description, source IP…"
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
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as Severity | 'All')}
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
              {SEVERITY_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt === 'All' ? 'All Severities' : opt.charAt(0).toUpperCase() + opt.slice(1)}
                </option>
              ))}
            </select>
            <select
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value as string | 'All')}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
                fontFamily: 'inherit',
                minWidth: 180,
                cursor: 'pointer',
              }}
            >
              {EVENT_TYPE_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt === 'All' ? 'All Event Types' : EVENT_TYPE_LABELS[opt]}
                </option>
              ))}
            </select>
            <select
              value={resolutionFilter}
              onChange={(e) => setResolutionFilter(e.target.value as 'All' | 'resolved' | 'unresolved')}
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
              {RESOLUTION_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt === 'All' ? 'All Resolutions' : opt.charAt(0).toUpperCase() + opt.slice(1)}
                </option>
              ))}
            </select>
            <button
              onClick={handleClearFilters}
              disabled={searchQuery === '' && severityFilter === 'All' && eventTypeFilter === 'All' && resolutionFilter === 'All'}
              style={{
                background: '#1E2D45',
                border: '1px solid #2a3f5f',
                borderRadius: 8,
                color: '#94A3B8',
                padding: '8px 16px',
                fontSize: 13,
                cursor: 'pointer',
                opacity: (searchQuery === '' && severityFilter === 'All' && eventTypeFilter === 'All' && resolutionFilter === 'All') ? 0.5 : 1,
              }}
            >
              Clear Filters
            </button>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', borderTop: '1px solid #1E2D45', marginTop: 8, paddingTop: 8 }}>
          <span style={{ color: '#94A3B8', fontSize: 12 }}>{sorted.length} matching events</span>
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

      {/* Event investigation table */}
      <div style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {sorted.length === 0 ? (
          <div style={{ padding: 48, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center', textAlign: 'center' }}>
            <span style={{ color: '#94A3B8', fontSize: 13 }}>No events match your filters</span>
            <button onClick={handleClearFilters} style={{ background: '#3B82F6', border: 'none', borderRadius: 8, padding: '8px 16px', color: '#F1F5F9', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>
              Clear Filters
            </button>
          </div>
        ) : (
          <>
            <div style={{ padding: '16px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 14, fontWeight: 600 }}>
                  Event Investigation
                </h3>
                <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
                  Select an event to view full details
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
                        onClick={() => handleSort('severity')}
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
                          Severity
                          {sort?.key === 'severity' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => handleSort('title')}
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
                          Event Title
                          {sort?.key === 'title' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => handleSort('eventType')}
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
                          Event Type
                          {sort?.key === 'eventType' && (
                            sort.direction === 'asc' ? <ChevronUp size={12} color="#42D6C5" /> : <ChevronDown size={12} color="#42D6C5" />
                          )}
                        </div>
                      </button>
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      Source IP
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      Destination IP
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'left', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      Protocol
                    </th>
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
                      Resolution
                    </th>
                    <th style={{ padding: '10px 16px', textAlign: 'center', color: '#64748B', fontSize: 11, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', background: '#0D1726', whiteSpace: 'nowrap' }}>
                      Action
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {paginated.map((evt) => {
                    const severity = SEVERITY_STYLES[evt.severity];
                    const isSelected = evt.id === selectedEventId;
                    return (
                      <tr
                        key={evt.id}
                        role="button"
                        tabIndex={0}
                        aria-label={`Select event ${evt.title} for details`}
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
                        onClick={(e) => handleSelect(evt.id, e.currentTarget as HTMLElement)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleSelect(evt.id, e.currentTarget as HTMLElement);
                          }
                        }}
                      >
                        <td style={{ padding: '10px 16px' }}>
                          <span
                            style={{
                              background: severity.bg,
                              color: severity.color,
                              fontSize: 11,
                              fontWeight: 600,
                              padding: '2px 8px',
                              borderRadius: 4,
                            }}
                          >
                            {severity.label}
                          </span>
                        </td>
                        <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12 }}>
                          {evt.title}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12 }}>
                          {EVENT_TYPE_LABELS[evt.eventType] ?? evt.eventType}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#F1F5F9', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                          {evt.sourceIp}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                          {evt.destinationIp ?? '—'}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12 }}>
                          {evt.protocol ?? '—'}
                        </td>
                        <td style={{ padding: '10px 16px', color: '#94A3B8', fontSize: 12, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                          {formatTimestamp(evt.timestamp)}
                        </td>
                        <td style={{ padding: '10px 16px' }}>
                          <span
                            style={{
                              background: evt.resolved ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                              color: evt.resolved ? '#10B981' : '#EF4444',
                              fontSize: 11,
                              fontWeight: 600,
                              padding: '2px 8px',
                              borderRadius: 4,
                            }}
                          >
                            {evt.resolved ? 'Resolved' : 'Unresolved'}
                          </span>
                        </td>
                        <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                          <button
                            onClick={(e) => { e.stopPropagation(); handleSelect(evt.id); }}
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
                            aria-label={`View event ${evt.id} details`}
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

      {/* Event details drawer */}
      {selectedEvent && (
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
              setSelectedEventId(null);
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
            aria-label="Event details"
            ref={drawerRef}
            onKeyDown={handleDrawerKeyDown}
          >
            <div style={{ padding: '20px 24px', borderBottom: '1px solid #1E2D45', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 16, fontWeight: 600 }}>
                Event Details
              </h3>
              <button
                onClick={() => setSelectedEventId(null)}
                style={{ background: 'transparent', border: 'none', color: '#94A3B8', cursor: 'pointer', padding: 4 }}
                aria-label="Close event details"
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ padding: 24, display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Event ID</span>
                <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedEvent.id}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Title</span>
                <span style={{ color: '#F1F5F9', fontSize: 13 }}>{selectedEvent.title}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Description</span>
                <span style={{ color: '#F1F5F9', fontSize: 13 }}>{selectedEvent.description}</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Severity</span>
                  <span
                    style={{
                      background: SEVERITY_STYLES[selectedEvent.severity].bg,
                      color: SEVERITY_STYLES[selectedEvent.severity].color,
                      fontSize: 11,
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: 4,
                      display: 'inline-block',
                    }}
                  >
                    {SEVERITY_STYLES[selectedEvent.severity].label}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Event Type</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13 }}>{EVENT_TYPE_LABELS[selectedEvent.eventType] ?? selectedEvent.eventType}</span>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Source IP</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedEvent.sourceIp}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Destination IP</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{selectedEvent.destinationIp ?? '—'}</span>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Protocol</span>
                  <span style={{ color: '#F1F5F9', fontSize: 13 }}>{selectedEvent.protocol ?? '—'}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Resolution</span>
                  <span
                    style={{
                      background: selectedEvent.resolved ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      color: selectedEvent.resolved ? '#10B981' : '#EF4444',
                      fontSize: 11,
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: 4,
                      display: 'inline-block',
                    }}
                  >
                    {selectedEvent.resolved ? 'Resolved' : 'Unresolved'}
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Timestamp</span>
                <span style={{ color: '#F1F5F9', fontSize: 13, fontFamily: 'monospace' }}>{formatTimestamp(selectedEvent.timestamp)}</span>
              </div>
            </div>

            <div style={{ padding: '16px 24px', borderTop: '1px solid #1E2D45', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                onClick={() => setSelectedEventId(null)}
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
