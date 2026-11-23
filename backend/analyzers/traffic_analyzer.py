"""Traffic analysis utilities for the NetWatch backend.

Provides packet analysis functions for computing dashboard metrics,
traffic time series, protocol distribution, device inventory, and
connection flows from PCAP captures.

This module now consumes the shared parsed-capture cache instead of
parsing PCAP files directly.
"""

import copy
import ipaddress
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .shared_capture import (
    get_parsed_capture,
    clear_caches,
    PacketRecord,
    ParsedCapture,
)
from .security_analyzer import SecurityEventDetector

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

# Derived analysis cache: key = (pcap_path, mtime_ns, size, file_identity)
# Value = complete analysis result dict
_ANALYSIS_CACHE = {}


def _is_private_unicast_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is a private unicast address.

    Excludes loopback, multicast, unspecified, and broadcast addresses.
    """
    return (
        ip_obj.is_private
        and not ip_obj.is_multicast
        and not ip_obj.is_loopback
        and not ip_obj.is_unspecified
        and not ip_obj.is_reserved
        and ip_obj != ipaddress.IPv4Address("255.255.255.255")
    )


def _build_analysis_from_parsed_capture(capture: ParsedCapture) -> Dict[str, Any]:
    """
    Build the complete analysis result from a ParsedCapture.

    This function performs all aggregations and derivations that were
    previously done during the PCAP parse loop.
    """
    packets = capture.packets
    first_ts = capture.first_timestamp
    last_ts = capture.last_timestamp
    total_packets = capture.total_packets
    total_bytes = capture.total_bytes

    # Aggregation containers
    protocol_counts = defaultdict(int)
    protocol_bytes = defaultdict(int)

    # Store packet timestamps and sizes for discrete 1-second bin peak calculation
    packet_samples = []

    # Unique IP addresses
    all_observed_ips = set()
    observed_private_unicast_ips = set()

    # Device inventory tracking
    device_first_seen = {}
    device_last_seen = {}
    device_traffic_in = defaultdict(int)
    device_traffic_out = defaultdict(int)
    device_pkts_in = defaultdict(int)
    device_pkts_out = defaultdict(int)
    device_macs = {}
    device_open_ports = defaultdict(set)
    device_protocols = defaultdict(set)

    # Connection flow tracking (bidirectional conversation sessions)
    # Key: (min(endpoint_a, endpoint_b), max(endpoint_a, endpoint_b), transport_type)
    flow_records = {}

    # Directional bytes per hourly bucket (hour 0..23)
    hourly_incoming_bytes = defaultdict(int)
    hourly_outgoing_bytes = defaultdict(int)
    ambiguous_traffic_bytes = 0

    # Security event detector (heuristic reconnaissance detection)
    security_detector = SecurityEventDetector()

    # Iterate over pre-parsed packets
    for pkt in packets:
        packet_size = pkt.packet_size
        ts_float = pkt.timestamp if pkt.timestamp > 0 else None

        protocol_counts[pkt.protocol] += 1
        protocol_bytes[pkt.protocol] += packet_size

        if ts_float is not None:
            packet_samples.append((ts_float, packet_size))

        # Protocol classification already done in shared capture
        protocol = pkt.protocol
        transport_type = pkt.transport_type
        src_ip_str = pkt.source_ip
        dst_ip_str = pkt.destination_ip
        src_port = pkt.source_port
        dst_port = pkt.destination_port
        tcp_flags = pkt.tcp_flags

        # MAC addresses from shared capture
        eth_src = pkt.eth_src
        eth_dst = pkt.eth_dst

        # Device metric analysis
        src_addr = None
        dst_addr = None

        if src_ip_str:
            try:
                src_addr = ipaddress.ip_address(src_ip_str)
                all_observed_ips.add(src_ip_str)
                if _is_private_unicast_ip(src_addr):
                    observed_private_unicast_ips.add(src_ip_str)
                    device_traffic_out[src_ip_str] += packet_size
                    device_pkts_out[src_ip_str] += 1
                    device_protocols[src_ip_str].add(protocol)
                    if eth_src and src_ip_str not in device_macs:
                        device_macs[src_ip_str] = eth_src.upper()
                    if ts_float is not None:
                        if src_ip_str not in device_first_seen or ts_float < device_first_seen[src_ip_str]:
                            device_first_seen[src_ip_str] = ts_float
                        if src_ip_str not in device_last_seen or ts_float > device_last_seen[src_ip_str]:
                            device_last_seen[src_ip_str] = ts_float
            except ValueError:
                pass

        if dst_ip_str:
            try:
                dst_addr = ipaddress.ip_address(dst_ip_str)
                all_observed_ips.add(dst_ip_str)
                if _is_private_unicast_ip(dst_addr):
                    observed_private_unicast_ips.add(dst_ip_str)
                    device_traffic_in[dst_ip_str] += packet_size
                    device_pkts_in[dst_ip_str] += 1
                    device_protocols[dst_ip_str].add(protocol)
                    if eth_dst and dst_ip_str not in device_macs and eth_dst != "FF:FF:FF:FF:FF:FF":
                        device_macs[dst_ip_str] = eth_dst.upper()
                    # Record listening/service port if destination received service traffic
                    if dst_port == 53 or (0 < dst_port < 1024):
                        device_open_ports[dst_ip_str].add(dst_port)
                    if ts_float is not None:
                        if dst_ip_str not in device_first_seen or ts_float < device_first_seen[dst_ip_str]:
                            device_first_seen[dst_ip_str] = ts_float
                        if dst_ip_str not in device_last_seen or ts_float > device_last_seen[dst_ip_str]:
                            device_last_seen[dst_ip_str] = ts_float
            except ValueError:
                pass

        # Directional classification
        if ts_float is not None:
            hour = datetime.fromtimestamp(ts_float, tz=timezone.utc).hour
            if src_addr is not None and dst_addr is not None:
                if src_addr.is_private and not dst_addr.is_private:
                    hourly_outgoing_bytes[hour] += packet_size
                elif not src_addr.is_private and dst_addr.is_private:
                    hourly_incoming_bytes[hour] += packet_size
                else:
                    ambiguous_traffic_bytes += packet_size
            else:
                ambiguous_traffic_bytes += packet_size

        # Connection / Flow analysis (TCP and UDP flows)
        if transport_type in ("TCP", "UDP") and src_ip_str and dst_ip_str:
            ep_src = (src_ip_str, src_port)
            ep_dst = (dst_ip_str, dst_port)
            canon_key = (min(ep_src, ep_dst), max(ep_src, ep_dst), transport_type)

            if canon_key not in flow_records:
                flow_records[canon_key] = {
                    "initiator": ep_src,
                    "responder": ep_dst,
                    "protocol": protocol,
                    "transport_type": transport_type,
                    "first_ts": ts_float,
                    "last_ts": ts_float,
                    "bytes": packet_size,
                    "packets": 1,
                    "flags": set([tcp_flags]) if tcp_flags else set(),
                    "fwd_packets": 1,
                    "rev_packets": 0,
                }
            else:
                flow = flow_records[canon_key]
                flow["bytes"] += packet_size
                flow["packets"] += 1
                if ts_float is not None:
                    if flow["first_ts"] is None or ts_float < flow["first_ts"]:
                        flow["first_ts"] = ts_float
                    if flow["last_ts"] is None or ts_float > flow["last_ts"]:
                        flow["last_ts"] = ts_float
                if tcp_flags:
                    flow["flags"].add(tcp_flags)
                    # Explicit SYN packet without ACK reliably identifies the true client initiator
                    if "S" in tcp_flags and "A" not in tcp_flags:
                        flow["initiator"] = ep_src
                        flow["responder"] = ep_dst

                if ep_src == flow["initiator"]:
                    flow["fwd_packets"] += 1
                else:
                    flow["rev_packets"] += 1

                # Refine generic TCP/UDP protocol name if application protocol becomes known
                if flow["protocol"] in ("TCP", "UDP") and protocol not in ("TCP", "UDP"):
                    flow["protocol"] = protocol

        # Security detection tracking
        if transport_type == "TCP" and src_ip_str and dst_ip_str:
            security_detector.observe_tcp(ts_float, src_ip_str, dst_ip_str, src_port, dst_port, tcp_flags)
        elif transport_type == "UDP" and src_ip_str and dst_ip_str:
            security_detector.observe_udp(ts_float, src_ip_str, dst_ip_str, src_port, dst_port)

    # 1. Average Bandwidth:
    if first_ts is not None and last_ts is not None and last_ts > first_ts:
        duration_seconds = last_ts - first_ts
        avg_mbps = (total_bytes * 8) / (duration_seconds * 1_000_000)
    else:
        duration_seconds = 0.0
        avg_mbps = 0.0

    # 2. Peak Bandwidth (1-second discrete measurement bins):
    peak_mbps = 0.0
    if duration_seconds >= 1.0 and first_ts is not None and last_ts is not None:
        bin_bytes = defaultdict(int)
        for ts_val, psize in packet_samples:
            bin_idx = int(ts_val - first_ts)
            bin_bytes[bin_idx] += psize

        for bin_idx, b_count in bin_bytes.items():
            bin_start = first_ts + bin_idx * 1.0
            bin_end = min(bin_start + 1.0, last_ts)
            bin_dur = bin_end - bin_start
            window = bin_dur if bin_dur >= 0.5 else 1.0
            bin_rate = (b_count * 8) / (window * 1_000_000)
            if bin_rate > peak_mbps:
                peak_mbps = bin_rate
    elif duration_seconds > 0.0:
        peak_mbps = avg_mbps

    # 3. Traffic Time Series (24 hourly buckets):
    hourly_data = []
    if first_ts is not None and last_ts is not None:
        day_start = datetime.fromtimestamp(first_ts, tz=timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).timestamp()

        for h in range(24):
            bucket_start = day_start + h * 3600
            bucket_end = bucket_start + 3600

            overlap_start = max(first_ts, bucket_start)
            overlap_end = min(last_ts, bucket_end)
            overlap_dur = max(0.0, overlap_end - overlap_start)

            inc_bytes = hourly_incoming_bytes.get(h, 0)
            out_bytes = hourly_outgoing_bytes.get(h, 0)

            if overlap_dur > 0:
                inc_mbps = (inc_bytes * 8) / (overlap_dur * 1_000_000)
                out_mbps = (out_bytes * 8) / (overlap_dur * 1_000_000)
            else:
                inc_mbps = 0.0
                out_mbps = 0.0

            hourly_data.append(
                {
                    "time": f"{h:02d}:00",
                    "incoming": round(inc_mbps, 4),
                    "outgoing": round(out_mbps, 4),
                }
            )
    else:
        for h in range(24):
            hourly_data.append(
                {
                    "time": f"{h:02d}:00",
                    "incoming": 0.0,
                    "outgoing": 0.0,
                }
            )

    # 4. Protocol Distribution:
    protocol_data = []
    if total_packets > 0:
        for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
            protocol_data.append(
                {
                    "protocol": PROTOCOL_DISPLAY.get(proto, proto),
                    "value": count,
                    "percentage": round((count / total_packets) * 100, 1),
                    "color": PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["Other"]),
                }
            )

    # 5. Device Inventory:
    devices = []
    for idx, ip_str in enumerate(sorted(observed_private_unicast_ips)):
        last_s = device_last_seen.get(ip_str, first_ts)
        last_seen_iso = (
            datetime.fromtimestamp(last_s, tz=timezone.utc).isoformat()
            if last_s is not None
            else None
        )
        mac = device_macs.get(ip_str)
        devices.append(
            {
                "id": f"dev-{idx + 1:03d}",
                "hostname": ip_str,
                "ipAddress": ip_str,
                "macAddress": mac if mac else None,
                "deviceType": "unknown",
                "lastSeen": last_seen_iso,
                "isActive": False,
                "openPorts": sorted(device_open_ports[ip_str]),
                "trafficIn": device_traffic_in[ip_str],
                "trafficOut": device_traffic_out[ip_str],
            }
        )

    # 6. Connection Flows:
    connections = []
    sorted_flows = sorted(
        flow_records.values(),
        key=lambda f: f["first_ts"] if f["first_ts"] is not None else 0.0,
        reverse=True,
    )

    for idx, flow in enumerate(sorted_flows):
        init_ip, init_port = flow["initiator"]
        resp_ip, resp_port = flow["responder"]

        # If initiator was mid-stream and connected to a well-known service port (< 1024),
        # ensure client with ephemeral port is sourceIp and server is destinationIp.
        if (init_port == 443 or init_port == 80 or init_port == 53) and resp_port > 1024:
            src_ip, s_port = resp_ip, resp_port
            dst_ip, d_port = init_ip, init_port
        else:
            src_ip, s_port = init_ip, init_port
            dst_ip, d_port = resp_ip, resp_port

        # Connection status determination based on evidence:
        if flow["transport_type"] == "TCP":
            flags = flow["flags"]
            has_rst = any("R" in fl for fl in flags)
            has_fin = any("F" in fl for fl in flags)
            has_syn = any("S" in fl for fl in flags)
            if has_rst:
                # Connection refused requires evidence of an initial handshake attempt (SYN)
                # being rejected by RST. An isolated RST packet without a preceding SYN
                # represents session reset/teardown (closed in capture), not connection refusal.
                if has_syn and flow["packets"] <= 2:
                    status = "refused"
                else:
                    status = "closed"
            elif has_fin:
                status = "closed"
            else:
                # Flow observed with no termination evidence in capture interval
                status = "active"
        else:
            # UDP is connectionless; completed request-response transactions are marked closed.
            # Flows with only one direction observed are marked timeout (no response observed).
            if flow["fwd_packets"] > 0 and flow["rev_packets"] > 0:
                status = "closed"
            else:
                status = "timeout"

        dur = (
            round(flow["last_ts"] - flow["first_ts"], 2)
            if (flow["first_ts"] is not None and flow["last_ts"] is not None)
            else 0.0
        )
        est_iso = (
            datetime.fromtimestamp(flow["first_ts"], tz=timezone.utc).isoformat()
            if flow["first_ts"] is not None
            else None
        )

        connections.append(
            {
                "id": f"con-{idx + 1:03d}",
                "sourceIp": src_ip,
                "destinationIp": dst_ip,
                "sourcePort": s_port,
                "destinationPort": d_port,
                "protocol": flow["protocol"],
                "status": status,
                "established": est_iso,
                "duration": dur,
                "bytesTransferred": flow["bytes"],
            }
        )

    # 7. Security Events Detection:
    security_events = security_detector.evaluate()

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": duration_seconds,
        "start_time": datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat() if first_ts else None,
        "end_time": datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts else None,
        "protocol_counts": dict(protocol_counts),
        "protocol_bytes": dict(protocol_bytes),
        "hourly_traffic": hourly_data,
        "unique_ips": sorted(all_observed_ips),
        "observed_private_unicast_ips": sorted(observed_private_unicast_ips),
        "ambiguous_traffic_bytes": ambiguous_traffic_bytes,
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "dashboard_metrics": {
            "totalPackets": total_packets,
            "totalPacketsDelta": None,
            "bandwidthUsage": round(avg_mbps, 4),
            "bandwidthPeak": round(peak_mbps, 4),
            "activeDevices": None,
            "totalDevices": len(observed_private_unicast_ips),
            "securityAlerts": len(security_events),
            "criticalAlerts": sum(1 for e in security_events if e["severity"] == "critical"),
        },
        "traffic_data": hourly_data,
        "protocol_data": protocol_data,
        "devices": devices,
        "connections": connections,
        "security_events": security_events,
    }


def analyze_capture(pcap_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Perform analysis of a PCAP/PCAPNG capture using shared parsed capture.

    Processes IPv4 and ARP packets. Non-IP/non-ARP packets are safely skipped.
    Derives dashboard metrics, hourly traffic series, protocol distribution,
    device inventory, and connection flows.
    Caches derived results by file fingerprint to avoid recomputation.

    Args:
        pcap_path: Path to the PCAP/PCAPNG capture file.

    Returns:
        Dictionary with analyzed capture metrics, or None if the file cannot be read.
    """
    from .shared_capture import _get_cache_key

    if pcap_path is None:
        from .packet_analyzer import PCAP_PATH
        pcap_path = PCAP_PATH

    if not os.path.exists(pcap_path):
        return None

    # Get cache key for derived result cache (same fingerprint as shared cache)
    try:
        cache_key = _get_cache_key(pcap_path)
        if cache_key is not None and cache_key in _ANALYSIS_CACHE:
            return _ANALYSIS_CACHE[cache_key]
    except OSError:
        cache_key = None

    # Get parsed capture from shared cache (handles parsing, caching, synchronization)
    capture = get_parsed_capture(pcap_path)
    if capture is None:
        return None

    # Build analysis from parsed capture
    result = _build_analysis_from_parsed_capture(capture)

    # Cache derived result
    if cache_key is not None:
        _ANALYSIS_CACHE.clear()
        _ANALYSIS_CACHE[cache_key] = result

    return result


def get_dashboard_metrics(pcap_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get dashboard metrics from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return copy.deepcopy(result["dashboard_metrics"])


def get_traffic_data(pcap_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    """Get traffic time series data from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return copy.deepcopy(result["traffic_data"])


def get_protocol_distribution(pcap_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    """Get protocol distribution from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return copy.deepcopy(result["protocol_data"])


def get_devices(pcap_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    """Get device inventory from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return copy.deepcopy(result["devices"])


def get_connections(pcap_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    """Get connection flows from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return copy.deepcopy(result["connections"])


def get_security_events(pcap_path: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    """Get security events from capture analysis."""
    result = analyze_capture(pcap_path)
    if result is None:
        return None
    return copy.deepcopy(result.get("security_events", []))


# For backward compatibility with packet_analyzer import
from .packet_analyzer import PCAP_PATH, MAX_PACKET_LIMIT, DEFAULT_PACKET_LIMIT