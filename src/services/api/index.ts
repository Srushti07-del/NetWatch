/**
 * api.ts
 *
 * NetWatch API service layer.
 * Thin wrappers around fetch for future FastAPI backend integration.
 * Currently returns mock data — swap BASE_URL and remove mock imports when backend is ready.
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

// Future: const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export const api = {
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    await delay(0);
    return Promise.resolve(mockMetrics);
  },

  async getTrafficData(): Promise<TrafficDataPoint[]> {
    await delay(0);
    return Promise.resolve(mockTrafficData);
  },

  async getProtocolDistribution(): Promise<ProtocolDataPoint[]> {
    await delay(0);
    return Promise.resolve(mockProtocolData);
  },

  async getRecentPackets(limit = 10): Promise<NetworkPacket[]> {
    await delay(0);
    return Promise.resolve(mockPackets.slice(0, limit));
  },

  async getSecurityEvents(): Promise<SecurityEvent[]> {
    await delay(0);
    return Promise.resolve(mockSecurityEvents);
  },

  async getDevices(): Promise<Device[]> {
    await delay(0);
    return Promise.resolve(mockDevices);
  },

  async getConnections(): Promise<Connection[]> {
    await delay(0);
    return Promise.resolve(mockConnections);
  },
};
