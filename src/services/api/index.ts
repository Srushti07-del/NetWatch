/**
 * api.ts
 *
 * NetWatch API service layer.
 *
 * Separation of concerns:
 *   - API configuration (base URL, demo mode flag) from environment variables.
 *   - Mock/demo data providers (used when demo mode is enabled).
 *   - Real HTTP API client (fetch-based, for future FastAPI backend integration).
 *
 * Demo mode (default): uses local mock data, no HTTP requests are made.
 * API mode (VITE_DEMO_MODE=false): uses fetch() against VITE_API_BASE_URL.
 * Errors are always propagated — never silently falls back to mock data.
 */

import {
  mockMetrics,
  mockPackets,
  mockProtocolData,
  mockSecurityEvents,
  mockTrafficData,
  mockDevices,
  mockConnections,
} from '../../data/mockData';
import type {
  Connection,
  DashboardMetrics,
  Device,
  NetworkPacket,
  ProtocolDataPoint,
  SecurityEvent,
  TrafficDataPoint,
} from '../../types';

// ─── Configuration ───────────────────────────────────────────────

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';
export const IS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE !== 'false';

// ─── Mock data providers (demo mode only) ────────────────────────

const delay = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('The operation was aborted.', 'AbortError'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('The operation was aborted.', 'AbortError'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });

const mockProviders = {
  async getDashboardMetrics(signal?: AbortSignal): Promise<DashboardMetrics> {
    await delay(0, signal);
    return mockMetrics;
  },

  async getTrafficData(signal?: AbortSignal): Promise<TrafficDataPoint[]> {
    await delay(0, signal);
    return mockTrafficData;
  },

  async getProtocolDistribution(signal?: AbortSignal): Promise<ProtocolDataPoint[]> {
    await delay(0, signal);
    return mockProtocolData;
  },

  async getRecentPackets(limit = 10, signal?: AbortSignal): Promise<NetworkPacket[]> {
    await delay(0, signal);
    return mockPackets.slice(0, limit);
  },

  async getSecurityEvents(signal?: AbortSignal): Promise<SecurityEvent[]> {
    await delay(0, signal);
    return mockSecurityEvents;
  },

  async getDevices(signal?: AbortSignal): Promise<Device[]> {
    await delay(0, signal);
    return mockDevices;
  },

  async getConnections(signal?: AbortSignal): Promise<Connection[]> {
    await delay(0, signal);
    return mockConnections;
  },
};

// ─── Real HTTP API client (future FastAPI backend) ───────────────

async function request<T>(path: string, signal?: AbortSignal): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url, signal ? { signal } : undefined);
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

// ─── API service ─────────────────────────────────────────────────

export const api = {
  async getDashboardMetrics(signal?: AbortSignal): Promise<DashboardMetrics> {
    if (IS_DEMO_MODE) return mockProviders.getDashboardMetrics(signal);
    return request<DashboardMetrics>('/api/dashboard/metrics', signal);
  },

  async getTrafficData(signal?: AbortSignal): Promise<TrafficDataPoint[]> {
    if (IS_DEMO_MODE) return mockProviders.getTrafficData(signal);
    return request<TrafficDataPoint[]>('/api/traffic', signal);
  },

  async getProtocolDistribution(signal?: AbortSignal): Promise<ProtocolDataPoint[]> {
    if (IS_DEMO_MODE) return mockProviders.getProtocolDistribution(signal);
    return request<ProtocolDataPoint[]>('/api/protocols', signal);
  },

  async getRecentPackets(limit = 10, signal?: AbortSignal): Promise<NetworkPacket[]> {
    if (IS_DEMO_MODE) return mockProviders.getRecentPackets(limit, signal);
    return request<NetworkPacket[]>(`/api/packets?limit=${limit}`, signal);
  },

  async getSecurityEvents(signal?: AbortSignal): Promise<SecurityEvent[]> {
    if (IS_DEMO_MODE) return mockProviders.getSecurityEvents(signal);
    return request<SecurityEvent[]>('/api/security-events', signal);
  },

  async getDevices(signal?: AbortSignal): Promise<Device[]> {
    if (IS_DEMO_MODE) return mockProviders.getDevices(signal);
    return request<Device[]>('/api/devices', signal);
  },

  async getConnections(signal?: AbortSignal): Promise<Connection[]> {
    if (IS_DEMO_MODE) return mockProviders.getConnections(signal);
    return request<Connection[]>('/api/connections', signal);
  },
};
