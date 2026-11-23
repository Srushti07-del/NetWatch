"""Shared PCAP parsing and caching layer for NetWatch analyzers.

This module provides a common parsing layer that reads a PCAPNG capture once
and produces a reusable parsed-capture representation consumed by both the
packet analyzer and traffic analyzer.

Cache features:
- File identity and fingerprint handling (mtime_ns, size, inode on POSIX)
- Single-flight parsing per capture fingerprint
- LRU eviction with configurable entry and packet-count limits
- Pre-scan and post-scan fingerprint validation
- Correct cleanup after parsing failures
- Protection against callers mutating cached data
- In-flight result handoff for oversized/failed captures
"""

import os
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any

from scapy.all import PcapNgReader, IP, TCP, UDP, ICMP, ARP, DNS, Ether


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Maximum number of cached captures (LRU eviction when exceeded).
MAX_CACHE_ENTRIES = int(os.environ.get("NETWATCH_MAX_CACHE_ENTRIES", "32"))

# Maximum total number of packets across all cached captures.
# Practical bound, not an exact byte-level memory measurement.
MAX_CACHE_PACKETS = int(os.environ.get("NETWATCH_MAX_CACHE_PACKETS", "50000"))


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class PacketRecord:
    """
    Internal packet representation containing all information needed by
    downstream analyzers. Uses primitive types only — no Scapy objects.
    """
    # Original capture position (0-based index in the capture file)
    index: int

    # Timestamp as Unix epoch float (for precise calculations)
    timestamp: float

    # ISO-formatted timestamp (for packet analyzer output)
    timestamp_iso: str

    # IP addresses
    source_ip: str
    destination_ip: str

    # Ports (0 if not applicable)
    source_port: int
    destination_port: int

    # Protocol classification
    protocol: str  # TCP, UDP, DNS, HTTP, HTTPS, ICMP, ARP, Other
    transport_type: Optional[str]  # "TCP" | "UDP" | "ICMP" | None

    # Packet wire size in bytes
    packet_size: int

    # TTL (IP packets only)
    ttl: Optional[int]

    # MAC addresses (when available from Ethernet/ARP layer)
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None

    # TCP flags string (e.g., "S", "SA", "FA", "R") — empty if not TCP
    tcp_flags: str = ""

    # ARP-specific fields
    is_arp: bool = False
    arp_op: Optional[int] = None  # 1=request, 2=reply


@dataclass
class ParsedCapture:
    """
    Complete parsed capture result. All packets are stored in capture order
    (oldest to newest). Contains metadata for efficient derived computations.
    """
    packets: List[PacketRecord]
    first_timestamp: float
    last_timestamp: float
    total_packets: int
    total_bytes: int

    # Pre-computed indices for common queries (optional optimization)
    packet_indices_by_hour: Dict[int, List[int]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal cache state
# ---------------------------------------------------------------------------

# Cache for parsed captures.
# Key: (pcap_path, mtime_ns, file_size, file_identity)
#   where file_identity is inode on POSIX, None on Windows or if unavailable.
# Value: ParsedCapture
_PARSED_CAPTURE_CACHE = OrderedDict()
_PARSED_CAPTURE_LOCK = threading.RLock()

# Running total of packets currently cached. Updated under _PARSED_CAPTURE_LOCK.
_CACHED_PACKET_COUNT = 0

# Per-capture synchronization: maps cache_key -> threading.Event.
# An Event is set when the parse for that key completes (success or failure).
# Waiting threads block on the event and then re-check the cache.
_PARSE_EVENTS = {}
_PARSE_EVENTS_LOCK = threading.Lock()

# In-flight results for single-flight handoff.
# Key: cache_key -> ParsedCapture or None (for failed parse)
# This allows waiting threads to get the result even if it's not cached
# (e.g., oversized captures or failed parses).
_IN_FLIGHT_RESULTS = {}
_IN_FLIGHT_RESULTS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# File identity and fingerprint
# ---------------------------------------------------------------------------

def _get_file_identity(pcap_path: str) -> Optional[int]:
    """
    Get a file identity value suitable for cache key inclusion.

    On POSIX (Linux/macOS): returns st_ino (inode number) which changes
    when a file is replaced, even if path/mtime/size are preserved.

    On Windows: st_ino is not reliably stable across replacements.
    Returns None to indicate identity tracking is unavailable.
    In this case, same-path/same-mtime/same-size replacements are NOT
    detected by the cache key. This is a documented platform limitation.
    """
    try:
        stat = os.stat(pcap_path)
        if sys.platform == "win32":
            # Windows st_ino is not reliable for detecting file replacement.
            return None
        # POSIX: use inode
        return getattr(stat, "st_ino", None)
    except OSError:
        return None


def _get_cache_key(pcap_path: str) -> Optional[Tuple[str, int, int, Optional[int]]]:
    """Generate a cache key from file path, mtime_ns, file size, and identity."""
    try:
        stat = os.stat(pcap_path)
        file_identity = _get_file_identity(pcap_path)
        return (pcap_path, stat.st_mtime_ns, stat.st_size, file_identity)
    except OSError:
        return None


def _get_file_fingerprint(pcap_path: str) -> Optional[Tuple[int, int, Optional[int]]]:
    """
    Capture file identity information for pre/post-scan change detection.

    Returns (mtime_ns, size, file_identity) matching the cache key fields
    except for the path component.
    """
    try:
        stat = os.stat(pcap_path)
        file_identity = _get_file_identity(pcap_path)
        return (stat.st_mtime_ns, stat.st_size, file_identity)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Cache access and eviction
# ---------------------------------------------------------------------------

def _get_cached_capture(pcap_path: str) -> Optional[ParsedCapture]:
    """Retrieve cached parsed capture if valid, otherwise return None."""
    cache_key = _get_cache_key(pcap_path)
    if cache_key is None:
        return None
    with _PARSED_CAPTURE_LOCK:
        capture = _PARSED_CAPTURE_CACHE.get(cache_key)
        if capture is not None:
            # Move to end (most recently used) for LRU
            _PARSED_CAPTURE_CACHE.move_to_end(cache_key)
        return capture


def _evict_lru_entries() -> None:
    """
    Evict least-recently-used entries until both entry and packet limits
    are satisfied. Must be called under _PARSED_CAPTURE_LOCK.
    """
    global _CACHED_PACKET_COUNT
    while (_PARSED_CAPTURE_CACHE and
           (len(_PARSED_CAPTURE_CACHE) >= MAX_CACHE_ENTRIES or
            _CACHED_PACKET_COUNT >= MAX_CACHE_PACKETS)):
        _, evicted_capture = _PARSED_CAPTURE_CACHE.popitem(last=False)
        _CACHED_PACKET_COUNT -= evicted_capture.total_packets


def _cache_parsed_capture(pcap_path: str, capture: ParsedCapture) -> None:
    """
    Cache the parsed capture with dual-limit LRU eviction.

    If the capture itself exceeds the packet budget, it is not cached
    (but the analyzed packets are still returned to the caller).
    """
    global _CACHED_PACKET_COUNT
    cache_key = _get_cache_key(pcap_path)
    if cache_key is None:
        return

    packet_count = capture.total_packets
    # If this single capture exceeds the packet budget, don't cache it.
    if packet_count > MAX_CACHE_PACKETS:
        return

    with _PARSED_CAPTURE_LOCK:
        # If key already exists, update and move to end (adjust packet count)
        if cache_key in _PARSED_CAPTURE_CACHE:
            old_capture = _PARSED_CAPTURE_CACHE[cache_key]
            _CACHED_PACKET_COUNT -= old_capture.total_packets
            _PARSED_CAPTURE_CACHE[cache_key] = capture
            _PARSED_CAPTURE_CACHE.move_to_end(cache_key)
            _CACHED_PACKET_COUNT += packet_count
            return

        # Evict oldest entries until both limits satisfied
        _evict_lru_entries()

        # After eviction, check if we still have room
        if (len(_PARSED_CAPTURE_CACHE) < MAX_CACHE_ENTRIES and
                _CACHED_PACKET_COUNT + packet_count <= MAX_CACHE_PACKETS):
            _PARSED_CAPTURE_CACHE[cache_key] = capture
            _CACHED_PACKET_COUNT += packet_count
        # If still no room, don't cache this entry


def _get_or_create_parse_event(cache_key: Tuple) -> Tuple[threading.Event, bool]:
    """Get or create a parse event for the given cache key.

    Returns the event that callers should wait on. The caller that creates
    the event (i.e., the one that will perform the parse) is responsible for
    setting it when done.

    Also cleans up any stale in-flight result from a previous parse.
    """
    with _PARSE_EVENTS_LOCK:
        # Clean up any stale in-flight result from a previous parse for this key
        with _IN_FLIGHT_RESULTS_LOCK:
            _IN_FLIGHT_RESULTS.pop(cache_key, None)

        event = _PARSE_EVENTS.get(cache_key)
        if event is None:
            event = threading.Event()
            _PARSE_EVENTS[cache_key] = event
            return event, True  # This thread should perform the parse
        return event, False  # Another thread is parsing; wait on event


def _clear_parse_event(cache_key: Tuple) -> None:
    """Remove the parse event for the given cache key after parse completes.

    Note: We do NOT clean up the in-flight result here, as waiting threads
    may still need to consume it. It will be cleaned up when the next parse
    for the same key starts.
    """
    with _PARSE_EVENTS_LOCK:
        _PARSE_EVENTS.pop(cache_key, None)


def _store_in_flight_result(cache_key: Tuple, capture: Optional[ParsedCapture]) -> None:
    """Store the in-flight result for waiting threads to consume."""
    with _IN_FLIGHT_RESULTS_LOCK:
        _IN_FLIGHT_RESULTS[cache_key] = capture


def _consume_in_flight_result(cache_key: Tuple) -> Optional[ParsedCapture]:
    """
    Retrieve the in-flight result without removing it.
    The result will be cleaned up on the next parse for the same key,
    or when caches are cleared.
    """
    with _IN_FLIGHT_RESULTS_LOCK:
        return _IN_FLIGHT_RESULTS.get(cache_key)


# ---------------------------------------------------------------------------
# PCAP parsing
# ---------------------------------------------------------------------------

def _parse_capture(pcap_path: str, cache_key: Tuple, fingerprint_before: Tuple) -> Optional[ParsedCapture]:
    """
    Internal function to parse a PCAP file into a ParsedCapture.

    Returns the ParsedCapture, or None on failure.
    The caller is responsible for setting the parse event.
    """
    reader = None
    packets = []
    first_ts = None
    last_ts = None
    total_bytes = 0

    try:
        reader = PcapNgReader(pcap_path)

        for index, packet in enumerate(reader):
            # Process IPv4 and ARP packets. Other link-layer frames are skipped safely.
            if not packet.haslayer(IP) and not packet.haslayer(ARP):
                continue

            packet_size = len(packet)
            total_bytes += packet_size

            # Extract timestamp
            ts = getattr(packet, "time", None)
            ts_float = float(ts) if ts is not None else None
            if ts_float is not None:
                if first_ts is None or ts_float < first_ts:
                    first_ts = ts_float
                if last_ts is None or ts_float > last_ts:
                    last_ts = ts_float

            # ISO timestamp for packet analyzer output
            if ts_float is not None:
                timestamp_iso = datetime.fromtimestamp(
                    ts_float, tz=timezone.utc
                ).isoformat()
            else:
                timestamp_iso = datetime.now(tz=timezone.utc).isoformat()

            # MAC addresses
            eth_src = None
            eth_dst = None
            if packet.haslayer(Ether):
                eth_src = str(packet[Ether].src)
                eth_dst = str(packet[Ether].dst)

            # Protocol classification & IP/port extraction
            protocol = "Other"
            transport_type = None
            src_ip = ""
            dst_ip = ""
            src_port = 0
            dst_port = 0
            ttl = None
            tcp_flags = ""
            is_arp = False
            arp_op = None

            if packet.haslayer(ARP):
                protocol = "ARP"
                is_arp = True
                arp_layer = packet[ARP]
                src_ip = str(arp_layer.psrc)
                dst_ip = str(arp_layer.pdst)
                arp_op = int(arp_layer.op) if hasattr(arp_layer, 'op') else None
                if arp_layer.hwsrc:
                    eth_src = str(arp_layer.hwsrc)
                if arp_layer.hwdst and str(arp_layer.hwdst) != "00:00:00:00:00:00":
                    eth_dst = str(arp_layer.hwdst)

            elif packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)

                ip_ttl = getattr(ip_layer, "ttl", None)
                if ip_ttl is not None:
                    ttl = int(ip_ttl)

                if packet.haslayer(DNS):
                    protocol = "DNS"
                    if packet.haslayer(TCP):
                        transport_type = "TCP"
                        src_port = int(packet[TCP].sport)
                        dst_port = int(packet[TCP].dport)
                        tcp_flags = str(packet[TCP].flags)
                    elif packet.haslayer(UDP):
                        transport_type = "UDP"
                        src_port = int(packet[UDP].sport)
                        dst_port = int(packet[UDP].dport)
                elif packet.haslayer(TCP):
                    transport_type = "TCP"
                    tcp_layer = packet[TCP]
                    src_port = int(tcp_layer.sport)
                    dst_port = int(tcp_layer.dport)
                    tcp_flags = str(tcp_layer.flags)
                    if src_port == 53 or dst_port == 53:
                        protocol = "DNS"
                    elif src_port == 443 or dst_port == 443:
                        protocol = "HTTPS"
                    elif src_port == 80 or dst_port == 80:
                        protocol = "HTTP"
                    else:
                        protocol = "TCP"
                elif packet.haslayer(UDP):
                    transport_type = "UDP"
                    udp_layer = packet[UDP]
                    src_port = int(udp_layer.sport)
                    dst_port = int(udp_layer.dport)
                    if src_port == 53 or dst_port == 53:
                        protocol = "DNS"
                    else:
                        protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                    transport_type = "ICMP"

            # Build packet record
            record = PacketRecord(
                index=index,
                timestamp=ts_float if ts_float is not None else 0.0,
                timestamp_iso=timestamp_iso,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                transport_type=transport_type,
                packet_size=packet_size,
                ttl=ttl,
                eth_src=eth_src,
                eth_dst=eth_dst,
                tcp_flags=tcp_flags,
                is_arp=is_arp,
                arp_op=arp_op,
            )
            packets.append(record)

    except Exception:
        return None
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    # Verify file hasn't changed during scan
    fingerprint_after = _get_file_fingerprint(pcap_path)
    if fingerprint_after != fingerprint_before:
        # File changed during scan; do not cache inconsistent results
        return None

    # Build pre-computed hour indices for traffic time series optimization
    packet_indices_by_hour: Dict[int, List[int]] = {}
    if first_ts is not None and last_ts is not None:
        day_start = datetime.fromtimestamp(first_ts, tz=timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).timestamp()
        for i, pkt in enumerate(packets):
            if pkt.timestamp > 0:
                hour = int((pkt.timestamp - day_start) // 3600)
                if 0 <= hour < 24:
                    packet_indices_by_hour.setdefault(hour, []).append(i)

    return ParsedCapture(
        packets=packets,
        first_timestamp=first_ts if first_ts is not None else 0.0,
        last_timestamp=last_ts if last_ts is not None else 0.0,
        total_packets=len(packets),
        total_bytes=total_bytes,
        packet_indices_by_hour=packet_indices_by_hour,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_parsed_capture(pcap_path: str) -> Optional[ParsedCapture]:
    """
    Get a parsed capture, either from cache or by parsing the file.

    This is the main entry point for all analyzers. It handles:
    - Cache lookup with LRU promotion
    - Single-flight parsing for cache misses
    - Fingerprint validation before and after parsing
    - Cache population with dual-limit eviction
    - In-flight result handoff for oversized/failed captures

    Returns None if the file cannot be read or parsed.
    """
    # Validate file exists
    if not os.path.exists(pcap_path):
        return None

    # Try cache first
    cached = _get_cached_capture(pcap_path)
    if cached is not None:
        return cached

    # Cache miss - need to parse. Use per-capture synchronization.
    cache_key = _get_cache_key(pcap_path)
    if cache_key is None:
        return None

    # Capture file fingerprint before analysis
    fingerprint_before = _get_file_fingerprint(pcap_path)
    if fingerprint_before is None:
        return None

    # Get or create the parse event for this cache key
    parse_event, should_parse = _get_or_create_parse_event(cache_key)

    if should_parse:
        # This thread performs the parse
        try:
            capture = _parse_capture(pcap_path, cache_key, fingerprint_before)
            # Store in-flight result for waiting threads (even if oversized or failed)
            _store_in_flight_result(cache_key, capture)
            if capture is not None and capture.total_packets > 0:
                _cache_parsed_capture(pcap_path, capture)
            # If parse failed or file changed, don't cache anything
        finally:
            # Always signal completion and clean up event
            parse_event.set()
            _clear_parse_event(cache_key)
    else:
        # Another thread is parsing; wait for it to complete
        parse_event.wait()
        # After wait, first check the persistent cache
        cached = _get_cached_capture(pcap_path)
        if cached is not None:
            return cached
        # If not in persistent cache, consume the in-flight result
        # (for oversized captures or failed parses)
        in_flight = _consume_in_flight_result(cache_key)
        if in_flight is not None:
            return in_flight
        # If still no result, the parse failed or file changed; fall through to return None

    # If we performed the parse, return our result (or None if failed)
    if should_parse:
        return capture

    # Should not reach here, but safety fallback
    return None


def clear_caches() -> None:
    """Clear all internal caches. For testing only."""
    global _CACHED_PACKET_COUNT
    with _PARSED_CAPTURE_LOCK:
        _PARSED_CAPTURE_CACHE.clear()
        _CACHED_PACKET_COUNT = 0
    with _PARSE_EVENTS_LOCK:
        _PARSE_EVENTS.clear()
    with _IN_FLIGHT_RESULTS_LOCK:
        _IN_FLIGHT_RESULTS.clear()


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics for monitoring/debugging."""
    with _PARSED_CAPTURE_LOCK:
        return {
            "entries": len(_PARSED_CAPTURE_CACHE),
            "total_packets": _CACHED_PACKET_COUNT,
            "max_entries": MAX_CACHE_ENTRIES,
            "max_packets": MAX_CACHE_PACKETS,
        }