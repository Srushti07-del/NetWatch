/**
 * mockData.ts
 *
 * Illustrative sample data for NetWatch dashboard development.
 * NOT representative of live network traffic.
 * Replace with real API responses from the FastAPI backend when ready.
 */

import type {
  DashboardMetrics,
  Device,
  NetworkPacket,
  ProtocolDataPoint,
  SecurityEvent,
  TrafficDataPoint,
  Connection,
} from '../types';

// ─── Dashboard Metrics ───────────────────────────────────────────────────────

export const mockMetrics: DashboardMetrics = {
  totalPackets: 1_482_931,
  totalPacketsDelta: 12.4,
  bandwidthUsage: 847,
  bandwidthPeak: 1240,
  activeDevices: 34,
  totalDevices: 41,
  securityAlerts: 7,
  criticalAlerts: 2,
};

// ─── Traffic Time Series ─────────────────────────────────────────────────────

export const mockTrafficData: TrafficDataPoint[] = [
  { time: '00:00', incoming: 120, outgoing: 80 },
  { time: '01:00', incoming: 95, outgoing: 60 },
  { time: '02:00', incoming: 70, outgoing: 45 },
  { time: '03:00', incoming: 55, outgoing: 35 },
  { time: '04:00', incoming: 48, outgoing: 30 },
  { time: '05:00', incoming: 62, outgoing: 42 },
  { time: '06:00', incoming: 110, outgoing: 75 },
  { time: '07:00', incoming: 180, outgoing: 120 },
  { time: '08:00', incoming: 290, outgoing: 195 },
  { time: '09:00', incoming: 420, outgoing: 280 },
  { time: '10:00', incoming: 510, outgoing: 340 },
  { time: '11:00', incoming: 580, outgoing: 390 },
  { time: '12:00', incoming: 620, outgoing: 415 },
  { time: '13:00', incoming: 590, outgoing: 400 },
  { time: '14:00', incoming: 640, outgoing: 430 },
  { time: '15:00', incoming: 710, outgoing: 475 },
  { time: '16:00', incoming: 760, outgoing: 510 },
  { time: '17:00', incoming: 820, outgoing: 550 },
  { time: '18:00', incoming: 700, outgoing: 465 },
  { time: '19:00', incoming: 580, outgoing: 385 },
  { time: '20:00', incoming: 460, outgoing: 305 },
  { time: '21:00', incoming: 350, outgoing: 230 },
  { time: '22:00', incoming: 240, outgoing: 155 },
  { time: '23:00', incoming: 160, outgoing: 105 },
];

// ─── Protocol Distribution ───────────────────────────────────────────────────

export const mockProtocolData: ProtocolDataPoint[] = [
  { protocol: 'HTTPS', value: 48200, percentage: 42.3, color: '#42D6C5' },
  { protocol: 'TCP',   value: 28900, percentage: 25.4, color: '#3B82F6' },
  { protocol: 'UDP',   value: 18100, percentage: 15.9, color: '#8B5CF6' },
  { protocol: 'DNS',   value: 9400,  percentage: 8.3,  color: '#F59E0B' },
  { protocol: 'HTTP',  value: 5600,  percentage: 4.9,  color: '#EC4899' },
  { protocol: 'Other', value: 3800,  percentage: 3.2,  color: '#64748B' },
];

// ─── Dynamic Timestamp Helpers ──────────────────────────────────────────────

const now = Date.now();
const secondsAgo = (s: number) => new Date(now - s * 1000).toISOString();
const minutesAgo = (m: number) => new Date(now - m * 60 * 1000).toISOString();

// ─── Recent Network Activity ─────────────────────────────────────────────────

export const mockPackets: NetworkPacket[] = [
  {
    id: 'pkt-001',
    timestamp: secondsAgo(28),
    sourceIp: '192.168.1.102',
    destinationIp: '8.8.8.8',
    sourcePort: 54231,
    destinationPort: 53,
    protocol: 'DNS',
    packetSize: 72,
    status: 'allowed',
    ttl: 64,
  },
  {
    id: 'pkt-002',
    timestamp: secondsAgo(25),
    sourceIp: '10.0.0.5',
    destinationIp: '172.16.4.22',
    sourcePort: 443,
    destinationPort: 60412,
    protocol: 'HTTPS',
    packetSize: 1480,
    status: 'allowed',
    ttl: 128,
  },
  {
    id: 'pkt-003',
    timestamp: secondsAgo(22),
    sourceIp: '192.168.1.78',
    destinationIp: '203.0.113.45',
    sourcePort: 50122,
    destinationPort: 22,
    protocol: 'TCP',
    packetSize: 540,
    status: 'flagged',
    ttl: 64,
  },
  {
    id: 'pkt-004',
    timestamp: secondsAgo(19),
    sourceIp: '10.0.0.11',
    destinationIp: '1.1.1.1',
    sourcePort: 61033,
    destinationPort: 53,
    protocol: 'DNS',
    packetSize: 88,
    status: 'allowed',
    ttl: 64,
  },
  {
    id: 'pkt-005',
    timestamp: secondsAgo(16),
    sourceIp: '198.51.100.14',
    destinationIp: '192.168.1.1',
    sourcePort: 4421,
    destinationPort: 80,
    protocol: 'HTTP',
    packetSize: 320,
    status: 'blocked',
    ttl: 50,
  },
  {
    id: 'pkt-006',
    timestamp: secondsAgo(13),
    sourceIp: '192.168.1.55',
    destinationIp: '151.101.64.81',
    sourcePort: 52011,
    destinationPort: 443,
    protocol: 'HTTPS',
    packetSize: 1200,
    status: 'allowed',
    ttl: 128,
  },
  {
    id: 'pkt-007',
    timestamp: secondsAgo(10),
    sourceIp: '10.0.0.3',
    destinationIp: '10.0.0.1',
    sourcePort: 68,
    destinationPort: 67,
    protocol: 'UDP',
    packetSize: 300,
    status: 'monitored',
    ttl: 64,
  },
  {
    id: 'pkt-008',
    timestamp: secondsAgo(7),
    sourceIp: '203.0.113.99',
    destinationIp: '192.168.1.1',
    sourcePort: 54322,
    destinationPort: 3389,
    protocol: 'TCP',
    packetSize: 60,
    status: 'blocked',
    ttl: 42,
  },
  {
    id: 'pkt-009',
    timestamp: secondsAgo(4),
    sourceIp: '192.168.1.20',
    destinationIp: '172.217.12.46',
    sourcePort: 55600,
    destinationPort: 443,
    protocol: 'HTTPS',
    packetSize: 870,
    status: 'allowed',
    ttl: 128,
  },
  {
    id: 'pkt-010',
    timestamp: secondsAgo(1),
    sourceIp: '10.0.0.8',
    destinationIp: '192.168.1.102',
    sourcePort: 445,
    destinationPort: 60899,
    protocol: 'TCP',
    packetSize: 1024,
    status: 'flagged',
    ttl: 64,
  },
];

// ─── Security Events ─────────────────────────────────────────────────────────

export const mockSecurityEvents: SecurityEvent[] = [
  {
    id: 'evt-001',
    title: 'Repeated Failed SSH Login Attempts',
    description: 'Sample: Multiple failed SSH authentication attempts observed from external address.',
    severity: 'high',
    sourceIp: '203.0.113.45',
    destinationIp: '192.168.1.5',
    timestamp: minutesAgo(4),
    protocol: 'TCP',
    eventType: 'brute_force',
    resolved: false,
  },
  {
    id: 'evt-002',
    title: 'Sequential Port Scan Detected',
    description: 'Sample: Incremental port sweep across common service ports observed from single source.',
    severity: 'medium',
    sourceIp: '198.51.100.77',
    destinationIp: '192.168.1.1',
    timestamp: minutesAgo(19),
    protocol: 'TCP',
    eventType: 'port_scan',
    resolved: false,
  },
  {
    id: 'evt-003',
    title: 'Unusual Outbound Data Volume',
    description: 'Sample: Elevated outbound traffic volume on non-standard port from internal host.',
    severity: 'critical',
    sourceIp: '192.168.1.78',
    destinationIp: '45.33.32.156',
    timestamp: minutesAgo(41),
    protocol: 'TCP',
    eventType: 'data_exfiltration',
    resolved: false,
  },
  {
    id: 'evt-004',
    title: 'Blocked RDP Access Attempt',
    description: 'Sample: Connection attempt to RDP port from untrusted external source was blocked.',
    severity: 'high',
    sourceIp: '203.0.113.99',
    destinationIp: '192.168.1.10',
    timestamp: minutesAgo(60),
    protocol: 'TCP',
    eventType: 'unauthorized_access',
    resolved: true,
  },
  {
    id: 'evt-005',
    title: 'Traffic Policy Violation',
    description: 'Sample: Unencrypted HTTP traffic to external service, contrary to network policy.',
    severity: 'low',
    sourceIp: '192.168.1.55',
    destinationIp: '198.51.100.14',
    timestamp: minutesAgo(85),
    protocol: 'HTTP',
    eventType: 'policy_violation',
    resolved: true,
  },
  {
    id: 'evt-006',
    title: 'Anomalous DNS Query Pattern',
    description: 'Sample: High-frequency DNS queries to unusual domains from single host.',
    severity: 'medium',
    sourceIp: '192.168.1.102',
    timestamp: minutesAgo(115),
    protocol: 'DNS',
    eventType: 'anomaly',
    resolved: false,
  },
];

// ─── Devices ─────────────────────────────────────────────────────────────────

export const mockDevices: Device[] = [
  {
    id: 'dev-001',
    hostname: 'gateway-01',
    ipAddress: '192.168.1.1',
    macAddress: 'AA:BB:CC:11:22:33',
    deviceType: 'router',
    lastSeen: secondsAgo(15),
    isActive: true,
    openPorts: [22, 80, 443, 8080],
    trafficIn: 524_288_000,
    trafficOut: 314_572_800,
  },
  {
    id: 'dev-002',
    hostname: 'ws-dev-01',
    ipAddress: '192.168.1.102',
    macAddress: 'DD:EE:FF:44:55:66',
    deviceType: 'workstation',
    operatingSystem: 'Windows 11',
    lastSeen: secondsAgo(25),
    isActive: true,
    openPorts: [3389, 445],
    trafficIn: 157_286_400,
    trafficOut: 94_371_840,
  },
  {
    id: 'dev-003',
    hostname: 'srv-db-01',
    ipAddress: '10.0.0.5',
    macAddress: 'GG:HH:II:77:88:99',
    deviceType: 'server',
    operatingSystem: 'Ubuntu 22.04 LTS',
    lastSeen: secondsAgo(5),
    isActive: true,
    openPorts: [22, 5432, 6379],
    trafficIn: 838_860_800,
    trafficOut: 629_145_600,
  },
];

// ─── Connections ─────────────────────────────────────────────────────────────

export const mockConnections: Connection[] = [
  {
    id: 'con-001',
    sourceIp: '192.168.1.102',
    destinationIp: '151.101.64.81',
    sourcePort: 52011,
    destinationPort: 443,
    protocol: 'HTTPS',
    status: 'active',
    established: minutesAgo(7),
    duration: 432,
    bytesTransferred: 2_097_152,
  },
  {
    id: 'con-002',
    sourceIp: '10.0.0.5',
    destinationIp: '172.16.4.22',
    sourcePort: 5432,
    destinationPort: 60412,
    protocol: 'TCP',
    status: 'active',
    established: minutesAgo(22),
    duration: 1320,
    bytesTransferred: 8_388_608,
  },
];
