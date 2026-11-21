"""
security_analyzer.py

Deterministic heuristic security event detection engine for offline PCAPNG captures.
Analyzes captured transport flows to detect reconnaissance patterns (TCP SYN port scans
and UDP port probes) with explainable thresholds and deduplication.

Detection rules:
- Rule A: Suspected TCP Port Scan (distinct TCP SYN destination ports to a target host)
- Rule B: Suspected UDP Port Probing (distinct UDP destination ports to a target host,
  excluding DNS responses, DHCP, NTP, and multicast/broadcast)
- Rule C: Repeated connection attempts (Deferred: distinguishing benign application retries
  from brute force requires application-layer auth decoding not present in raw PCAP).
"""

from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
from typing import Dict, List, Optional, Tuple, Any

# Configurable detection thresholds
TCP_SYN_SCAN_THRESHOLD = 5       # Minimum distinct destination ports to flag TCP scan
UDP_PROBE_THRESHOLD = 5          # Minimum distinct destination ports to flag UDP probe
SCAN_WINDOW_SECONDS = 60.0       # Sliding observation window in seconds

# Standard well-known service ports to exclude from UDP probing rules (server replies to clients)
UDP_EXCLUDED_SERVER_PORTS = {53, 67, 68, 123}


class SecurityEventDetector:
    """
    Stateful detector accumulating candidate packets during capture analysis
    and deterministically evaluating security events across sliding windows.
    """

    def __init__(
        self,
        tcp_syn_threshold: int = TCP_SYN_SCAN_THRESHOLD,
        udp_probe_threshold: int = UDP_PROBE_THRESHOLD,
        window_seconds: float = SCAN_WINDOW_SECONDS,
    ):
        self.tcp_syn_threshold = tcp_syn_threshold
        self.udp_probe_threshold = udp_probe_threshold
        self.window_seconds = window_seconds

        # Candidate records: list of (timestamp, sport, dport)
        self.tcp_syn_candidates: Dict[Tuple[str, str], List[Tuple[float, int, int]]] = defaultdict(list)
        self.udp_candidates: Dict[Tuple[str, str], List[Tuple[float, int, int]]] = defaultdict(list)

    def observe_tcp(
        self,
        ts_float: Optional[float],
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        tcp_flags: str,
    ) -> None:
        """
        Record candidate TCP SYN packets (SYN=1, ACK=0).
        Deduplicates immediate retransmissions of the same (sport, dport) within 1.0s.
        """
        if ts_float is None or not src_ip or not dst_ip:
            return

        # Initial handshake attempt: SYN flag is set, ACK flag is NOT set
        if "S" in tcp_flags and "A" not in tcp_flags:
            key = (src_ip, dst_ip)
            existing = self.tcp_syn_candidates[key]
            # Deduplicate immediate retransmission of identical tuple within 1.0 second
            if existing and existing[-1][1] == sport and existing[-1][2] == dport:
                if abs(ts_float - existing[-1][0]) < 1.0:
                    return
            self.tcp_syn_candidates[key].append((ts_float, sport, dport))

    def observe_udp(
        self,
        ts_float: Optional[float],
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
    ) -> None:
        """
        Record candidate outbound UDP probing packets.
        Excludes well-known server responses (DNS, NTP, DHCP) and multicast/broadcast addresses.
        """
        if ts_float is None or not src_ip or not dst_ip:
            return

        # Exclude server reply traffic to client ephemeral ports
        if sport in UDP_EXCLUDED_SERVER_PORTS:
            return

        # Exclude multicast and broadcast destinations
        try:
            dst_addr = ipaddress.ip_address(dst_ip)
            if dst_addr.is_multicast or dst_ip == "255.255.255.255":
                return
        except ValueError:
            return

        key = (src_ip, dst_ip)
        existing = self.udp_candidates[key]
        # Deduplicate immediate retransmission of identical tuple within 1.0 second
        if existing and existing[-1][1] == sport and existing[-1][2] == dport:
            if abs(ts_float - existing[-1][0]) < 1.0:
                return
        self.udp_candidates[key].append((ts_float, sport, dport))

    def evaluate(self) -> List[Dict[str, Any]]:
        """
        Evaluate candidate packets against detection rules.
        Returns a list of structured SecurityEvent dicts matching frontend contracts.
        """
        events: List[Dict[str, Any]] = []

        # ─── Rule A: TCP Port Scan Detection ──────────────────────────────────
        for (src_ip, dst_ip), packets in sorted(self.tcp_syn_candidates.items()):
            if not packets:
                continue

            packets_sorted = sorted(packets, key=lambda x: x[0])
            n = len(packets_sorted)

            # Sliding window over packets
            best_window = None
            max_distinct_ports = 0

            for i in range(n):
                start_ts = packets_sorted[i][0]
                window_dports = set()
                end_idx = i
                for j in range(i, n):
                    if packets_sorted[j][0] - start_ts <= self.window_seconds:
                        window_dports.add(packets_sorted[j][2])
                        end_idx = j
                    else:
                        break

                if len(window_dports) >= self.tcp_syn_threshold:
                    if len(window_dports) > max_distinct_ports:
                        max_distinct_ports = len(window_dports)
                        dur = max(0.01, packets_sorted[end_idx][0] - start_ts)
                        best_window = (start_ts, dur, sorted(window_dports))

            if best_window and max_distinct_ports >= self.tcp_syn_threshold:
                first_ts, duration, observed_ports = best_window
                sample_ports = observed_ports[:5]
                sample_str = ", ".join(str(p) for p in sample_ports)
                if len(observed_ports) > 5:
                    sample_str += f", … (+{len(observed_ports) - 5} more)"

                severity = "high" if max_distinct_ports >= 20 else "medium"
                ts_iso = datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat()

                events.append(
                    {
                        "id": f"sec-{len(events) + 1:03d}",
                        "title": "Suspected TCP Port Scan",
                        "description": (
                            f"Heuristic: Source {src_ip} sent initial TCP SYN packets to "
                            f"{max_distinct_ports} distinct destination ports on {dst_ip} "
                            f"within {duration:.1f}s (ports: {sample_str})."
                        ),
                        "severity": severity,
                        "sourceIp": src_ip,
                        "destinationIp": dst_ip,
                        "timestamp": ts_iso,
                        "protocol": "TCP",
                        "eventType": "port_scan",
                        "resolved": False,
                    }
                )

        # ─── Rule B: UDP Port Probing Detection ───────────────────────────────
        for (src_ip, dst_ip), packets in sorted(self.udp_candidates.items()):
            if not packets:
                continue

            packets_sorted = sorted(packets, key=lambda x: x[0])
            n = len(packets_sorted)

            best_window = None
            max_distinct_ports = 0

            for i in range(n):
                start_ts = packets_sorted[i][0]
                window_dports = set()
                end_idx = i
                for j in range(i, n):
                    if packets_sorted[j][0] - start_ts <= self.window_seconds:
                        window_dports.add(packets_sorted[j][2])
                        end_idx = j
                    else:
                        break

                if len(window_dports) >= self.udp_probe_threshold:
                    if len(window_dports) > max_distinct_ports:
                        max_distinct_ports = len(window_dports)
                        dur = max(0.01, packets_sorted[end_idx][0] - start_ts)
                        best_window = (start_ts, dur, sorted(window_dports))

            if best_window and max_distinct_ports >= self.udp_probe_threshold:
                first_ts, duration, observed_ports = best_window
                sample_ports = observed_ports[:5]
                sample_str = ", ".join(str(p) for p in sample_ports)
                if len(observed_ports) > 5:
                    sample_str += f", … (+{len(observed_ports) - 5} more)"

                severity = "high" if max_distinct_ports >= 20 else "medium"
                ts_iso = datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat()

                events.append(
                    {
                        "id": f"sec-{len(events) + 1:03d}",
                        "title": "Suspected UDP Port Probing",
                        "description": (
                            f"Heuristic: Source {src_ip} sent UDP packets to "
                            f"{max_distinct_ports} distinct destination ports on {dst_ip} "
                            f"within {duration:.1f}s (ports: {sample_str}). "
                            f"Heuristic observation — does not establish confirmed malicious intent."
                        ),
                        "severity": severity,
                        "sourceIp": src_ip,
                        "destinationIp": dst_ip,
                        "timestamp": ts_iso,
                        "protocol": "UDP",
                        # "port_scan" is used here rather than "anomaly" because it is the
                        # most semantically accurate type in the frontend SecurityEvent contract
                        # for multi-port reconnaissance patterns. "anomaly" would be less specific.
                        "eventType": "port_scan",
                        "resolved": False,
                    }
                )

        return events
