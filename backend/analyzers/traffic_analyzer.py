"""Traffic analysis utilities for the NetWatch backend.

Provides shared packet analysis functions for computing dashboard metrics,
traffic time series, and protocol distribution from PCAP captures.
"""

import os
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import PcapNgReader, IP, TCP, UDP, ICMP

from .packet_analyzer import PCAP_PATH, MAX_PACKET_LIMIT, DEFAULT_PACKET_LIMIT

# Protocol color mapping (matches frontend ProtocolChart)
PROTOCOL_COLORS = {
    "TCP": "#3B82F6",
    "UDP": "#8B5CF6",
    "DNS": "#F59E0B",
    "HTTP": "#EC4899",
    "HTTPS": "#42D6C5",
    "ICMP": "#64748B",
    "ARP": "#64748B",
    "Other": "#64748B",
}

# Protocol display names
PROTOCOL_DISPLAY = {
    "TCP": "TCP",
    "UDP": "UDP",
    "DNS": "DNS",
    "HTTP": "HTTP",
    "HTTPS": "HTTPS",
    "ICMP": "ICMP",
    "ARP": "ARP",
    "Other": "Other",
}


def analyze_capture(pcap_path=None):
    """Perform full analysis of a PCAP capture.

    Args:
        pcap_path: Path to the PCAP/PCAPNG capture file. Defaults to PCAP_PATH.

    Returns:
        Dictionary with keys:
        - "packets": list of packet dicts (NetworkPacket format)
        - "total_packets": int
        - "total_bytes": int
        - "duration_seconds": float
        - "start_time": datetime | None
        - "end_time": datetime | None
        - "protocol_counts": dict[protocol, count]
        - "protocol_bytes": dict[protocol, total_bytes]
        - "hourly_traffic": dict[hour_str, {"incoming": bytes, "outgoing": bytes}]
        - "unique_ips": set of IP addresses
        - "first_timestamp": float | None
        - "last_timestamp": float | None
    """
    if pcap_path is None:
        pcap_path = PCAP_PATH

    if not os.path.exists(pcap_path):
        return None

    reader = None
    try:
        reader = PcapNgReader(pcap_path)

        protocol_counts = defaultdict(int)
        protocol_bytes = defaultdict(int)
        hourly_incoming = defaultdict(int)
        hourly_outgoing = defaultdict(int)
        unique_ips = set()

        first_ts = None
        last_ts = None
        total_packets = 0
        total_bytes = 0

        for index, packet in enumerate(reader):
            # Only process packets that contain an IPv4 layer.
            # Packets without IPv4 (e.g. ARP) are skipped safely.
            if not packet.haslayer(IP):
                continue

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            unique_ips.add(src_ip)
            unique_ips.add(dst_ip)

            # Identify the transport protocol and extract ports when available.
            protocol = "Other"
            src_port = 0
            dst_port = 0

            if packet.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            # Get the packet timestamp from Scapy.
            # Scapy stores the capture time as packet.time (Unix timestamp).
            ts = getattr(packet, "time", None)
            if ts is not None:
                ts_float = float(ts)
                if first_ts is None or ts_float < first_ts:
                    first_ts = ts_float
                if last_ts is None or ts_float > last_ts:
                    last_ts = ts_float

                # Group by hour for traffic time series
                dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
                hour_key = dt.strftime("%H:%M")

                packet_size = len(packet)
                total_bytes += packet_size
                total_packets += 1

                protocol_counts[protocol] += 1
                protocol_bytes[protocol] += packet_size

                # Heuristic: traffic to external IPs is outgoing, from external is incoming
                # Simple heuristic: if destination is private RFC1918, it's incoming
                # This is a simplification; real classification would need network topology
                def is_private(ip):
                    parts = ip.split(".")
                    if len(parts) != 4:
                        return False
                    a, b = int(parts[0]), int(parts[1])
                    return (
                        a == 10
                        or (a == 172 and 16 <= b <= 31)
                        or (a == 192 and b == 168)
                    )

                if is_private(dst_ip):
                    hourly_incoming[hour_key] += packet_size
                else:
                    hourly_outgoing[hour_key] += packet_size

    except Exception:
        return None
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    # Build hourly traffic data points (24 hours)
    hourly_data = []
    if first_ts is not None and last_ts is not None:
        start_hour = datetime.fromtimestamp(first_ts, tz=timezone.utc).replace(
            minute=0, second=0, microsecond=0
        )
        end_hour = datetime.fromtimestamp(last_ts, tz=timezone.utc).replace(
            minute=0, second=0, microsecond=0
        )
        current = start_hour
        while current <= end_hour:
            hour_key = current.strftime("%H:%M")
            incoming_mbps = (hourly_incoming.get(hour_key, 0) * 8) / 1_000_000
            outgoing_mbps = (hourly_outgoing.get(hour_key, 0) * 8) / 1_000_000
            hourly_data.append(
                {
                    "time": hour_key,
                    "incoming": round(incoming_mbps, 2),
                    "outgoing": round(outgoing_mbps, 2),
                }
            )
            current = datetime.fromtimestamp(current.timestamp() + 3600, tz=timezone.utc)

    # Build protocol distribution
    total_pkts = sum(protocol_counts.values()) or 1
    protocol_data = []
    for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        protocol_data.append(
            {
                "protocol": PROTOCOL_DISPLAY.get(proto, proto),
                "value": count,
                "percentage": round((count / total_pkts) * 100, 1),
                "color": PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["Other"]),
            }
        )

    # Compute dashboard metrics
    duration_hours = (last_ts - first_ts) / 3600 if (first_ts and last_ts and last_ts > first_ts) else 1
    avg_mbps = (total_bytes * 8) / 1_000_000 / duration_hours if duration_hours > 0 else 0

    # Peak bandwidth: max hourly throughput in Mbps
    peak_mbps = 0
    for hour_key in hourly_incoming:
        inc = hourly_incoming.get(hour_key, 0)
        out = hourly_outgoing.get(hour_key, 0)
        total_mbps = ((inc + out) * 8) / 1_000_000
        if total_mbps > peak_mbps:
            peak_mbps = total_mbps

    # Unique IPs as devices
    unique_ip_count = len(unique_ips)

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": (last_ts - first_ts) if (first_ts and last_ts) else 0,
        "start_time": datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat() if first_ts else None,
        "end_time": datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts else None,
        "protocol_counts": dict(protocol_counts),
        "protocol_bytes": dict(protocol_bytes),
        "hourly_traffic": hourly_data,
        "unique_ips": list(unique_ips),
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "dashboard_metrics": {
            "totalPackets": total_packets,
            "totalPacketsDelta": 0.0,  # Cannot compute without historical data
            "bandwidthUsage": round(avg_mbps, 1),
            "bandwidthPeak": round(peak_mbps, 1),
            "activeDevices": unique_ip_count,
            "totalDevices": unique_ip_count,
            "securityAlerts": 0,
            "criticalAlerts": 0,
        },
        "traffic_data": hourly_data,
        "protocol_data": protocol_data,
    }


def get_dashboard_metrics(pcap_path=None):
    """Get dashboard metrics from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return result["dashboard_metrics"]


def get_traffic_data(pcap_path=None):
    """Get traffic time series data from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return result["traffic_data"]


def get_protocol_distribution(pcap_path=None):
    """Get protocol distribution from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return result["protocol_data"]