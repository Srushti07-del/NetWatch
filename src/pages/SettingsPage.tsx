/**
 * SettingsPage.tsx
 *
 * Configuration interface for NetWatch.
 *
 * Settings are split into:
 *   - Locally persisted preferences (saved to localStorage).
 *   - Display-only / backend-dependent settings (marked as requiring
 *     backend integration — changes cannot be applied yet).
 *
 * No settings are pretended to affect live capture, detection, or
 * backend behavior unless explicitly backed by the API service.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  CheckCircle,
  Copy,
  Save,
  Shield,
  SlidersHorizontal,
  Wifi,
  X,
} from 'lucide-react';
import { API_BASE_URL, IS_DEMO_MODE } from '../services/api';

const STORAGE_KEY = 'netwatch.settings';

interface LocalSettings {
  tableDensity: 'comfortable' | 'compact';
  notifications: {
    enabled: boolean;
    critical: boolean;
    high: boolean;
    medium: boolean;
  };
  alertThresholds: {
    criticalEvents: number;
    highEvents: number;
    mediumEvents: number;
    packetSizeBytes: number;
  };
  captureFilter: string;
}

const DEFAULT_SETTINGS: LocalSettings = {
  tableDensity: 'comfortable',
  notifications: {
    enabled: true,
    critical: true,
    high: true,
    medium: false,
  },
  alertThresholds: {
    criticalEvents: 10,
    highEvents: 50,
    mediumEvents: 100,
    packetSizeBytes: 1500,
  },
  captureFilter: '',
};

interface StatusBadgeProps {
  label: string;
  type: 'available' | 'backend';
}

function StatusBadge(props: StatusBadgeProps) {
  const { label, type } = props;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        background: type === 'available'
          ? 'rgba(16, 185, 129, 0.1)'
          : 'rgba(245, 158, 11, 0.1)',
        color: type === 'available' ? '#10B981' : '#F59E0B',
        fontSize: 11,
        fontWeight: 600,
        padding: '2px 8px',
        borderRadius: 4,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
      }}
    >
      {type === 'available' ? <CheckCircle size={10} /> : <AlertTriangle size={10} />}
      {label}
    </span>
  );
}

export function SettingsPage() {
  const [settings, setSettings] = useState<LocalSettings>(DEFAULT_SETTINGS);
  const [pendingChanges, setPendingChanges] = useState<Partial<LocalSettings>>({});
  const [saveStatus, setSaveStatus] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        // Strip stale theme property from previously saved settings
        const { theme: _theme, ...rest } = parsed;
        setSettings({ ...DEFAULT_SETTINGS, ...rest });
      }
    } catch {
      // Ignore malformed persisted settings; use defaults.
    }
  }, []);

  const handleSave = useCallback(() => {
    try {
      const next = { ...settings, ...pendingChanges };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      setSettings(next);
      setPendingChanges({});
      setSaveStatus({ message: 'Settings saved locally', type: 'success' });
    } catch {
      setSaveStatus({ message: 'Failed to save settings', type: 'error' });
    }
  }, [settings, pendingChanges]);

  const handleReset = useCallback(() => {
    setPendingChanges({});
    setSaveStatus(null);
  }, []);

  const dismissSaveStatus = useCallback(() => {
    setSaveStatus(null);
  }, []);

  useEffect(() => {
    if (!saveStatus) return;
    const timer = setTimeout(() => setSaveStatus(null), 4000);
    return () => clearTimeout(timer);
  }, [saveStatus]);

  const setField = useCallback((path: string, value: unknown) => {
    setPendingChanges((prev) => {
      const keys = path.split('.');
      const obj: Record<string, unknown> = {};
      let cursor = obj;
      for (let i = 0; i < keys.length - 1; i++) {
        cursor[keys[i]] = {};
        cursor = cursor[keys[i]] as Record<string, unknown>;
      }
      cursor[keys[keys.length - 1]] = value;
      return { ...prev, ...obj } as Partial<LocalSettings>;
    });
  }, []);

  const modeLabel = IS_DEMO_MODE ? 'Demo Mode' : 'API Mode';
  const apiBaseUrl = API_BASE_URL || '(not configured)';

  const hasPendingChanges = Object.keys(pendingChanges).length > 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, padding: 20, minHeight: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h2 style={{ margin: 0, color: '#F1F5F9', fontSize: 20, fontWeight: 700 }}>
            Settings
          </h2>
          <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 13 }}>
            Application configuration and monitoring preferences.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, background: IS_DEMO_MODE ? 'rgba(66, 214, 197, 0.08)' : 'rgba(59, 130, 246, 0.08)', border: IS_DEMO_MODE ? '1px solid rgba(66, 214, 197, 0.2)' : '1px solid rgba(59, 130, 246, 0.2)', borderRadius: 8, padding: '6px 14px' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6', boxShadow: IS_DEMO_MODE ? '0 0 6px rgba(66, 214, 197, 0.6)' : '0 0 6px rgba(59, 130, 246, 0.6)' }} />
            <span style={{ color: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6', fontSize: 12, fontWeight: 600 }}>{modeLabel}</span>
          </div>
          <button
            onClick={handleSave}
            disabled={!hasPendingChanges}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: !hasPendingChanges ? '#1E2D45' : '#3B82F6',
              border: !hasPendingChanges ? '1px solid #2a3f5f' : 'none',
              borderRadius: 8,
              padding: '8px 14px',
              color: '#F1F5F9',
              fontSize: 13,
              fontWeight: 600,
              cursor: !hasPendingChanges ? 'not-allowed' : 'pointer',
              opacity: !hasPendingChanges ? 0.5 : 1,
            }}
          >
            <Save size={14} />
            <span>Save</span>
          </button>
          <button
            onClick={handleReset}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: '#1E2D45',
              border: '1px solid #2a3f5f',
              borderRadius: 8,
              padding: '8px 14px',
              color: '#94A3B8',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <X size={14} />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {saveStatus && (
        <div
          style={{
            background: saveStatus.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: saveStatus.type === 'success' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 8,
            color: saveStatus.type === 'success' ? '#10B981' : '#EF4444',
            fontSize: 12,
            fontWeight: 600,
            padding: '8px 12px',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          {saveStatus.type === 'success' ? <CheckCircle size={14} /> : <AlertTriangle size={14} />}
          {saveStatus.message}
          <button
            onClick={dismissSaveStatus}
            style={{
              background: 'none',
              border: 'none',
              color: saveStatus.type === 'success' ? '#10B981' : '#EF4444',
              cursor: 'pointer',
              padding: 2,
            }}
          >
            <X size={12} />
          </button>
        </div>
      )}

      <section style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D45', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(66, 214, 197, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#42D6C5' }}>
            <Wifi size={16} />
          </div>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 15, fontWeight: 600 }}>
              Network Interface
            </h3>
            <p style={{ margin: '2px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Packet capture interface selection
            </p>
          </div>
        </div>
        <div style={{ padding: 20, display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Capture Interface
            </label>
            <select
              value={settings.captureFilter ? 'custom' : 'default'}
              disabled
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#94A3B8',
                padding: '8px 12px',
                fontSize: 13,
                cursor: 'not-allowed',
              }}
            >
              <option value="default">No interface selected</option>
              <option value="eth0">eth0 (illustrative)</option>
              <option value="wlan0">wlan0 (illustrative)</option>
              <option value="custom">Custom (illustrative)</option>
            </select>
            <span style={{ color: '#EF4444', fontSize: 11 }}>
              Interface discovery requires backend integration.
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'start', gap: 10 }}>
            <StatusBadge label="Requires backend" type="backend" />
            <span style={{ color: '#94A3B8', fontSize: 12, marginLeft: 8 }}>
              Selection does not affect packet capture until a backend discovery endpoint exists.
            </span>
          </div>
        </div>
      </section>

      <section style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D45', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(66, 214, 197, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#42D6C5' }}>
            <SlidersHorizontal size={16} />
          </div>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 15, fontWeight: 600 }}>
              Capture Filters
            </h3>
            <p style={{ margin: '2px 0 0', color: '#94A3B8', fontSize: 12 }}>
              BPF-style capture filter expression
            </p>
          </div>
        </div>
        <div style={{ padding: 20, display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Filter Expression
            </label>
            <input
              type="text"
              value={settings.captureFilter}
              onChange={(e) => setField('captureFilter', e.target.value)}
              placeholder="e.g. tcp port 443 or host 192.168.1.1"
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
            <div style={{ display: 'flex', gap: 8, fontSize: 11 }}>
              <span style={{ color: '#94A3B8' }}>
                {settings.captureFilter.length > 0 ? settings.captureFilter.length + ' chars' : 'Empty'}
              </span>
              <span style={{ color: settings.captureFilter.length > 0 ? '#10B981' : '#EF4444' }}>
                {settings.captureFilter.length > 0 ? 'Valid format' : 'Empty filter'}
              </span>
            </div>
            <p style={{ color: '#94A3B8', fontSize: 12, marginTop: 4 }}>
              Example: tcp port 443, udp port 53, host 10.0.0.1, or
              src net 192.168.0.0/16. Saving stores the expression locally;
              applying it to capture requires backend integration.
            </p>
          </div>
        </div>
      </section>

      <section style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D45', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(245, 158, 11, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#F59E0B' }}>
            <Shield size={16} />
          </div>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 15, fontWeight: 600 }}>
              Alert Thresholds
            </h3>
            <p style={{ margin: '2px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Local alert sensitivity preferences
            </p>
          </div>
        </div>
        <div style={{ padding: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Critical events
            </label>
            <input
              type="number"
              min={1}
              max={1000}
              value={String(settings.alertThresholds.criticalEvents)}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                if (!isNaN(v) && v >= 1 && v <= 1000) {
                  setField('alertThresholds.criticalEvents', v);
                }
              }}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
              }}
            />
            <span style={{ color: '#64748B', fontSize: 11 }}>1 — 1000</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              High events
            </label>
            <input
              type="number"
              min={1}
              max={1000}
              value={String(settings.alertThresholds.highEvents)}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                if (!isNaN(v) && v >= 1 && v <= 1000) {
                  setField('alertThresholds.highEvents', v);
                }
              }}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
              }}
            />
            <span style={{ color: '#64748B', fontSize: 11 }}>1 — 1000</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Medium events
            </label>
            <input
              type="number"
              min={1}
              max={1000}
              value={String(settings.alertThresholds.mediumEvents)}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                if (!isNaN(v) && v >= 1 && v <= 1000) {
                  setField('alertThresholds.mediumEvents', v);
                }
              }}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
              }}
            />
            <span style={{ color: '#64748B', fontSize: 11 }}>1 — 1000</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Max packet size (bytes)
            </label>
            <input
              type="number"
              min={64}
              max={65535}
              value={String(settings.alertThresholds.packetSizeBytes)}
              onChange={(e) => {
                const v = parseInt(e.target.value, 10);
                if (!isNaN(v) && v >= 64 && v <= 65535) {
                  setField('alertThresholds.packetSizeBytes', v);
                }
              }}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
              }}
            />
            <span style={{ color: '#64748B', fontSize: 11 }}>64 — 65535</span>
          </div>
        </div>
      </section>

      <section style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D45', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(59, 130, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3B82F6' }}>
            <Bell size={16} />
          </div>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 15, fontWeight: 600 }}>
              Notification Preferences
            </h3>
            <p style={{ margin: '2px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Local notification display preferences
            </p>
          </div>
        </div>
        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8 }}>
            <span style={{ color: '#F1F5F9', fontSize: 13 }}>
              Enable notifications
            </span>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', margin: 0 }}>
              <input
                type="checkbox"
                checked={settings.notifications.enabled}
                onChange={(e) => setField('notifications.enabled', e.target.checked)}
                style={{ width: 16, height: 16, accentColor: '#42D6C5' }}
              />
              <span style={{ color: '#94A3B8', fontSize: 12 }}>Enabled</span>
            </label>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8 }}>
            <span style={{ color: '#F1F5F9', fontSize: 13 }}>
              Critical alerts
            </span>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', margin: 0 }}>
              <input
                type="checkbox"
                checked={settings.notifications.critical}
                onChange={(e) => setField('notifications.critical', e.target.checked)}
                style={{ width: 16, height: 16, accentColor: '#42D6C5' }}
              />
              <span style={{ color: '#94A3B8', fontSize: 12 }}>Enabled</span>
            </label>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8 }}>
            <span style={{ color: '#F1F5F9', fontSize: 13 }}>
              High-severity alerts
            </span>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', margin: 0 }}>
              <input
                type="checkbox"
                checked={settings.notifications.high}
                onChange={(e) => setField('notifications.high', e.target.checked)}
                style={{ width: 16, height: 16, accentColor: '#42D6C5' }}
              />
              <span style={{ color: '#94A3B8', fontSize: 12 }}>Enabled</span>
            </label>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8 }}>
            <span style={{ color: '#F1F5F9', fontSize: 13 }}>
              Medium-severity alerts
            </span>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', margin: 0 }}>
              <input
                type="checkbox"
                checked={settings.notifications.medium}
                onChange={(e) => setField('notifications.medium', e.target.checked)}
                style={{ width: 16, height: 16, accentColor: '#42D6C5' }}
              />
              <span style={{ color: '#94A3B8', fontSize: 12 }}>Enabled</span>
            </label>
          </div>
          <span style={{ color: '#94A3B8', fontSize: 11, fontStyle: 'italic' }}>
            Stored locally in the browser. Notifications are not delivered
            without a backend notification service.
          </span>
        </div>
      </section>

      <section style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D45', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(59, 130, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3B82F6' }}>
            <Shield size={16} />
          </div>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 15, fontWeight: 600 }}>
              API Connection
            </h3>
            <p style={{ margin: '2px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Backend API configuration (read-only)
            </p>
          </div>
        </div>
        <div style={{ padding: 20, display: 'grid', gridTemplateColumns: '1fr', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Current Mode
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8, padding: '8px 12px' }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: IS_DEMO_MODE ? '#42D6C5' : '#3B82F6', boxShadow: IS_DEMO_MODE ? '0 0 6px rgba(66, 214, 197, 0.6)' : '0 0 6px rgba(59, 130, 246, 0.6)' }} />
              <span style={{ color: '#F1F5F9', fontSize: 13, fontWeight: 600 }}>{modeLabel}</span>
            </div>
            <span style={{ color: '#94A3B8', fontSize: 11 }}>
              {IS_DEMO_MODE ? 'Using illustrative mock data.' : 'Using configured API backend.'}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              API Base URL
            </label>
            <div style={{ display: 'flex', gap: 8, background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8, overflow: 'hidden' }}>
              <span style={{ color: '#94A3B8', fontSize: 12, fontFamily: 'monospace', padding: '8px 12px', flexShrink: 0 }}>{apiBaseUrl}</span>
              <button
                onClick={() => {
                  if (apiBaseUrl === '(not configured)') return;
                  navigator.clipboard.writeText(apiBaseUrl);
                }}
                style={{ background: '#1E2D45', border: 'none', borderRadius: 0, padding: '8px 12px', color: '#94A3B8', cursor: 'pointer' }}
                title="Copy"
              >
                <Copy size={14} />
              </button>
            </div>
            <span style={{ color: '#EF4444', fontSize: 11 }}>
              Vite environment variables are build-time only. They cannot be
              changed from the browser. Edit .env and rebuild to reconfigure.
            </span>
          </div>
        </div>
      </section>

      <section style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D45', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(139, 92, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8B5CF6' }}>
            <Shield size={16} />
          </div>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 15, fontWeight: 600 }}>
              User Preferences
            </h3>
            <p style={{ margin: '2px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Local browser preferences
            </p>
          </div>
        </div>
        <div style={{ padding: 20, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <label style={{ color: '#94A3B8', fontSize: 12, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Table Density
            </label>
            <select
              value={settings.tableDensity}
              onChange={(e) => setField('tableDensity', e.target.value)}
              style={{
                background: '#0D1726',
                border: '1px solid #1E2D45',
                borderRadius: 8,
                color: '#F1F5F9',
                padding: '8px 12px',
                fontSize: 13,
              }}
            >
              <option value="comfortable">Comfortable</option>
              <option value="compact">Compact</option>
            </select>
            <span style={{ color: '#94A3B8', fontSize: 11 }}>Persisted locally in browser</span>
          </div>
        </div>
      </section>

      <section style={{ background: '#141F30', border: '1px solid #1E2D45', borderRadius: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1E2D45', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'rgba(245, 158, 11, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#F59E0B' }}>
            <AlertTriangle size={16} />
          </div>
          <div>
            <h3 style={{ margin: 0, color: '#F1F5F9', fontSize: 15, fontWeight: 600 }}>
              Backend Integration Required
            </h3>
            <p style={{ margin: '2px 0 0', color: '#94A3B8', fontSize: 12 }}>
              Features awaiting FastAPI backend
            </p>
          </div>
        </div>
        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'start', gap: 10, padding: '10px 16px', background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8 }}>
            <AlertTriangle size={14} color="#F59E0B" />
            <div>
              <span style={{ color: '#F1F5F9', fontSize: 13, fontWeight: 600 }}>
                Network Interface Discovery
              </span>
              <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
                No backend endpoint exists to enumerate interfaces.
                Selection is illustrative only.
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'start', gap: 10, padding: '10px 16px', background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8 }}>
            <AlertTriangle size={14} color="#F59E0B" />
            <div>
              <span style={{ color: '#F1F5F9', fontSize: 13, fontWeight: 600 }}>
                Capture Filter Application
              </span>
              <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
                Filter expressions are stored locally but not applied to
                packet capture without backend support.
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'start', gap: 10, padding: '10px 16px', background: '#0D1726', border: '1px solid #1E2D45', borderRadius: 8 }}>
            <AlertTriangle size={14} color="#F59E0B" />
            <div>
              <span style={{ color: '#F1F5F9', fontSize: 13, fontWeight: 600 }}>
                API Reconfiguration
              </span>
              <p style={{ margin: '4px 0 0', color: '#94A3B8', fontSize: 12 }}>
                VITE_API_BASE_URL and VITE_DEMO_MODE are build-time
                variables. Rebuild required to change.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
