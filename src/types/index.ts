// ─── Core Domain Types ──────────────────────────────────────────────────────

export type Protocol = 'TCP' | 'UDP' | 'DNS' | 'HTTP' | 'HTTPS' | 'ICMP' | 'ARP' | 'Other';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type PacketStatus = 'allowed' | 'blocked' | 'flagged' | 'monitored';

export type ConnectionStatus = 'active' | 'closed' | 'timeout' | 'refused';

// ─── Network Packet ─────────────────────────────────────────────────────────

export interface NetworkPacket {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: Protocol;
  packetSize: number; // bytes
  status: PacketStatus;
  ttl?: number;
}

// ─── Device ─────────────────────────────────────────────────────────────────

export interface Device {
  id: string;
  hostname: string;
  ipAddress: string;
  macAddress: string;
  deviceType: 'server' | 'workstation' | 'mobile' | 'iot' | 'router' | 'switch' | 'unknown';
  operatingSystem?: string;
  lastSeen: string;
  isActive: boolean;
  openPorts: number[];
  trafficIn: number;  // bytes
  trafficOut: number; // bytes
}

// ─── Connection ──────────────────────────────────────────────────────────────

export interface Connection {
  id: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: Protocol;
  status: ConnectionStatus;
  established: string;
  duration: number; // seconds
  bytesTransferred: number;
}

// ─── Security Event ──────────────────────────────────────────────────────────

export interface SecurityEvent {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  sourceIp: string;
  destinationIp?: string;
  timestamp: string;
  protocol?: Protocol;
  eventType:
    | 'port_scan'
    | 'brute_force'
    | 'anomaly'
    | 'policy_violation'
    | 'malware_signature'
    | 'dos_attempt'
    | 'unauthorized_access'
    | 'data_exfiltration';
  resolved: boolean;
}

// ─── Traffic Data Point ──────────────────────────────────────────────────────

export interface TrafficDataPoint {
  time: string;
  incoming: number; // Mbps
  outgoing: number; // Mbps
}

// ─── Protocol Distribution ───────────────────────────────────────────────────

export interface ProtocolDataPoint {
  protocol: Protocol | string;
  value: number;
  percentage: number;
  color: string;
}

// ─── Dashboard Metrics ───────────────────────────────────────────────────────

export interface DashboardMetrics {
  totalPackets: number;
  totalPacketsDelta: number; // percentage change
  bandwidthUsage: number;    // Mbps
  bandwidthPeak: number;     // Mbps
  activeDevices: number;
  totalDevices: number;
  securityAlerts: number;
  criticalAlerts: number;
}

// ─── UI State ────────────────────────────────────────────────────────────────

export interface SortConfig<T> {
  key: keyof T;
  direction: 'asc' | 'desc';
}

export type MonitoringStatus = 'active' | 'paused' | 'error' | 'connecting' | 'demo';
