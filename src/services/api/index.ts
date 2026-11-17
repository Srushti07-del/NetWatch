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

const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const mockProviders = {
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    await delay(0);
    return mockMetrics;
  },

  async getTrafficData(): Promise<TrafficDataPoint[]> {
    await delay(0);
    return mockTrafficData;
  },

  async getProtocolDistribution(): Promise<ProtocolDataPoint[]> {
    await delay(0);
    return mockProtocolData;
  },

  async getRecentPackets(limit = 10): Promise<NetworkPacket[]> {
    await delay(0);
    return mockPackets.slice(0, limit);
  },

  async getSecurityEvents(): Promise<SecurityEvent[]> {
    await delay(0);
    return mockSecurityEvents;
  },

  async getDevices(): Promise<Device[]> {
    await delay(0);
    return mockDevices;
  },

  async getConnections(): Promise<Connection[]> {
    await delay(0);
    return mockConnections;
  },
};

// ─── Real HTTP API client (future FastAPI backend) ───────────────

async function request<T>(path: string): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

// ─── API service ─────────────────────────────────────────────────

export const api = {
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    if (IS_DEMO_MODE) return mockProviders.getDashboardMetrics();
    return request<DashboardMetrics>('/api/dashboard/metrics');
  },

  async getTrafficData(): Promise<TrafficDataPoint[]> {
    if (IS_DEMO_MODE) return mockProviders.getTrafficData();
    return request<TrafficDataPoint[]>('/api/traffic');
  },

  async getProtocolDistribution(): Promise<ProtocolDataPoint[]> {
    if (IS_DEMO_MODE) return mockProviders.getProtocolDistribution();
    return request<ProtocolDataPoint[]>('/api/protocols');
  },

  async getRecentPackets(limit = 10): Promise<NetworkPacket[]> {
    if (IS_DEMO_MODE) return mockProviders.getRecentPackets(limit);
    return request<NetworkPacket[]>(`/api/packets?limit=${limit}`);
  },

  async getSecurityEvents(): Promise<SecurityEvent[]> {
    if (IS_DEMO_MODE) return mockProviders.getSecurityEvents();
    return request<SecurityEvent[]>('/api/security-events');
  },

  async getDevices(): Promise<Device[]> {
    if (IS_DEMO_MODE) return mockProviders.getDevices();
    return request<Device[]>('/api/devices');
  },

  async getConnections(): Promise<Connection[]> {
    if (IS_DEMO_MODE) return mockProviders.getConnections();
    return request<Connection[]>('/api/connections');
  },
};
