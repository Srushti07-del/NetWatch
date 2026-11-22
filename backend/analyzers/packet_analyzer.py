"""Basic offline packet analyser for the NetWatch project.

Reads a PCAP capture file and returns structured packet data
that can be consumed by the FastAPI backend.

Processes IPv4 and ARP packets. Non-IP/non-ARP packets are handled safely.
"""

import os
import sys
import threading
from collections import OrderedDict
from datetime import datetime, timezone

from scapy.all import PcapNgReader, IP, TCP, UDP, ICMP, ARP, DNS

# Resolve the capture path relative to this file's location so the script
# works regardless of the current working directory.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_PATH = os.path.join(BASE_DIR, "captures", "sample.pcapng")

MAX_PACKET_LIMIT = 500
DEFAULT_PACKET_LIMIT = 100

# Maximum number of cached captures (LRU eviction when exceeded).
# Documented and configurable via environment variable if needed.
MAX_CACHE_ENTRIES = int(os.environ.get("NETWATCH_MAX_CACHE_ENTRIES", "32"))

# Maximum total number of packets across all cached captures.
# Practical bound, not an exact byte-level memory measurement.
# Configurable via environment variable.
MAX_CACHE_PACKETS = int(os.environ.get("NETWATCH_MAX_CACHE_PACKETS", "50000"))

# Cache for parsed packet collections.
# Key: (pcap_path, mtime_ns, file_size, file_identity)
#   where file_identity is inode on POSIX, None on Windows or if unavailable.
# Value: list of all parsed packet dicts in capture order (oldest to newest).
_PACKET_CACHE = OrderedDict()
_PACKET_CACHE_LOCK = threading.RLock()

# Running total of packets currently cached. Updated under _PACKET_CACHE_LOCK.
_CACHED_PACKET_COUNT = 0

# Per-capture synchronization: maps cache_key -> threading.Event.
# An Event is set when the scan for that key completes (success or failure).
# Waiting threads block on the event and then re-check the cache.
_SCAN_EVENTS = {}
_SCAN_EVENTS_LOCK = threading.Lock()


def _get_file_identity(pcap_path):
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
            # Return None to indicate no identity tracking.
            return None
        # POSIX: use inode
        return getattr(stat, "st_ino", None)
    except OSError:
        return None


def _get_cache_key(pcap_path):
    """Generate a cache key from file path, mtime_ns, file size, and identity."""
    try:
        stat = os.stat(pcap_path)
        file_identity = _get_file_identity(pcap_path)
        return (pcap_path, stat.st_mtime_ns, stat.st_size, file_identity)
    except OSError:
        return None


def _get_file_fingerprint(pcap_path):
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


def _get_cached_packets(pcap_path):
    """Retrieve cached packets if cache is valid, otherwise return None."""
    cache_key = _get_cache_key(pcap_path)
    if cache_key is None:
        return None
    with _PACKET_CACHE_LOCK:
        packets = _PACKET_CACHE.get(cache_key)
        if packets is not None:
            # Move to end (most recently used) for LRU
            _PACKET_CACHE.move_to_end(cache_key)
        return packets


def _evict_lru_entries():
    """
    Evict least-recently-used entries until both entry and packet limits
    are satisfied. Must be called under _PACKET_CACHE_LOCK.
    """
    global _CACHED_PACKET_COUNT
    while (_PACKET_CACHE and
           (len(_PACKET_CACHE) >= MAX_CACHE_ENTRIES or
            _CACHED_PACKET_COUNT >= MAX_CACHE_PACKETS)):
        _, evicted_packets = _PACKET_CACHE.popitem(last=False)
        _CACHED_PACKET_COUNT -= len(evicted_packets)


def _cache_packets(pcap_path, packets):
    """
    Cache the full packet list for the given pcap_path with dual-limit LRU eviction.

    If the capture itself exceeds the packet budget, it is not cached
    (but the analyzed packets are still returned to the caller).
    """
    global _CACHED_PACKET_COUNT
    cache_key = _get_cache_key(pcap_path)
    if cache_key is None:
        return

    packet_count = len(packets)
    # If this single capture exceeds the packet budget, don't cache it.
    if packet_count > MAX_CACHE_PACKETS:
        return

    with _PACKET_CACHE_LOCK:
        # If key already exists, update and move to end (adjust packet count)
        if cache_key in _PACKET_CACHE:
            old_packets = _PACKET_CACHE[cache_key]
            _CACHED_PACKET_COUNT -= len(old_packets)
            _PACKET_CACHE[cache_key] = packets
            _PACKET_CACHE.move_to_end(cache_key)
            _CACHED_PACKET_COUNT += packet_count
            return

        # Evict oldest entries until both limits satisfied
        _evict_lru_entries()

        # After eviction, check if we still have room (in case packet budget is 0 or negative)
        if len(_PACKET_CACHE) < MAX_CACHE_ENTRIES and _CACHED_PACKET_COUNT + packet_count <= MAX_CACHE_PACKETS:
            _PACKET_CACHE[cache_key] = packets
            _CACHED_PACKET_COUNT += packet_count
        # If still no room, don't cache this entry


def _get_or_create_scan_event(cache_key):
    """Get or create a scan event for the given cache key.

    Returns the event that callers should wait on. The caller that creates
    the event (i.e., the one that will perform the scan) is responsible for
    setting it when done.
    """
    with _SCAN_EVENTS_LOCK:
        event = _SCAN_EVENTS.get(cache_key)
        if event is None:
            event = threading.Event()
            _SCAN_EVENTS[cache_key] = event
            return event, True  # This thread should perform the scan
        return event, False  # Another thread is scanning; wait on event


def _clear_scan_event(cache_key):
    """Remove the scan event for the given cache key after scan completes."""
    with _SCAN_EVENTS_LOCK:
        _SCAN_EVENTS.pop(cache_key, None)


def _parse_packet(packet, index):
    """Parse a single packet and return a packet dict, or None if not IP/ARP."""
    protocol = "Other"
    src_ip = ""
    dst_ip = ""
    src_port = 0
    dst_port = 0
    ttl = None

    if packet.haslayer(ARP):
        protocol = "ARP"
        arp_layer = packet[ARP]
        src_ip = str(arp_layer.psrc)
        dst_ip = str(arp_layer.pdst)

    elif packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        if packet.haslayer(DNS):
            protocol = "DNS"
            if packet.haslayer(TCP):
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
            elif packet.haslayer(UDP):
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
        elif packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            if src_port == 53 or dst_port == 53:
                protocol = "DNS"
            elif src_port == 443 or dst_port == 443:
                protocol = "HTTPS"
            elif src_port == 80 or dst_port == 80:
                protocol = "HTTP"
            else:
                protocol = "TCP"
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            if src_port == 53 or dst_port == 53:
                protocol = "DNS"
            else:
                protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        ip_ttl = getattr(ip_layer, "ttl", None)
        if ip_ttl is not None:
            ttl = int(ip_ttl)

    else:
        return None

    # Get the packet timestamp from Scapy.
    ts = getattr(packet, "time", None)
    if ts is not None:
        timestamp = datetime.fromtimestamp(
            float(ts), tz=timezone.utc
        ).isoformat()
    else:
        timestamp = datetime.now(tz=timezone.utc).isoformat()

    # Get the actual packet length in bytes.
    packet_size = int(len(packet))

    return {
        "id": str(index),
        "timestamp": timestamp,
        "sourceIp": src_ip,
        "destinationIp": dst_ip,
        "sourcePort": src_port,
        "destinationPort": dst_port,
        "protocol": protocol,
        "packetSize": packet_size,
        "status": "monitored",
        "ttl": ttl,
    }


def _scan_packets(pcap_path, cache_key, fingerprint_before):
    """Internal function to scan packets from a PCAP file.

    Returns the list of parsed packets, or None on failure.
    The caller is responsible for setting the scan event.
    """
    reader = None
    all_packets = []

    try:
        reader = PcapNgReader(pcap_path)

        for index, packet in enumerate(reader):
            # Process IPv4 and ARP packets. Other link-layer frames are skipped safely.
            if not packet.haslayer(IP) and not packet.haslayer(ARP):
                continue

            parsed = _parse_packet(packet, index)
            if parsed is not None:
                all_packets.append(parsed)

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

    return all_packets


def analyze_packets(pcap_path, limit=DEFAULT_PACKET_LIMIT):
    """Analyse packets in a PCAP file and return structured data.

    Args:
        pcap_path: Path to the PCAP/PCAPNG capture file.
        limit: Maximum number of packets to return (1-500).

    Returns:
        A list of packet dictionaries matching the frontend NetworkPacket
        contract, or None if the file cannot be read.
    """
    # Validate the limit.
    if limit < 1:
        limit = 1
    if limit > MAX_PACKET_LIMIT:
        limit = MAX_PACKET_LIMIT

    # Check whether the capture file exists before attempting to read it.
    if not os.path.exists(pcap_path):
        return None

    # Try to get cached packets first.
    cached_packets = _get_cached_packets(pcap_path)
    if cached_packets is not None:
        # Return the newest N packets (last N in capture order)
        return [pkt.copy() for pkt in cached_packets[-limit:]]

    # Cache miss - need to scan. Use per-capture synchronization.
    cache_key = _get_cache_key(pcap_path)
    if cache_key is None:
        return None

    # Capture file fingerprint before analysis
    fingerprint_before = _get_file_fingerprint(pcap_path)
    if fingerprint_before is None:
        return None

    # Get or create the scan event for this cache key
    scan_event, should_scan = _get_or_create_scan_event(cache_key)

    if should_scan:
        # This thread performs the scan
        try:
            all_packets = _scan_packets(pcap_path, cache_key, fingerprint_before)
            if all_packets is not None and all_packets:
                _cache_packets(pcap_path, all_packets)
            # If scan failed or file changed, don't cache anything
        finally:
            # Always signal completion and clean up event
            scan_event.set()
            _clear_scan_event(cache_key)
    else:
        # Another thread is scanning; wait for it to complete
        scan_event.wait()
        # After wait, re-check cache (the scanning thread may have populated it)
        cached_packets = _get_cached_packets(pcap_path)
        if cached_packets is not None:
            return [pkt.copy() for pkt in cached_packets[-limit:]]
        # If still not in cache, the scan failed or file changed; fall through to return None

    # If we performed the scan, return our result (or None if failed)
    if should_scan:
        if all_packets:
            return [pkt.copy() for pkt in all_packets[-limit:]]
        return None

    # Should not reach here, but safety fallback
    return None


def main():
    """Entry point: run the analyser against the default capture file."""
    packets = analyze_packets(PCAP_PATH, limit=10)

    if packets is None:
        print("Error: failed to read PCAP file at '{}'".format(PCAP_PATH))
        return

    if len(packets) == 0:
        print(
            "The capture file '{}' is empty or contains no analyzed packets.".format(
                PCAP_PATH
            )
        )
        return

    print("\n=== Packet Analyser Report ===")
    print("File: {}".format(PCAP_PATH))
    print("Total packets returned: {}".format(len(packets)))

    print("\nProtocol distribution:")
    protocol_counter = {}
    for pkt in packets:
        protocol_counter[pkt["protocol"]] = (
            protocol_counter.get(pkt["protocol"], 0) + 1
        )
    for protocol, count in sorted(protocol_counter.items()):
        print("  {}: {}".format(protocol, count))

    print("\nFirst few packets:")
    for pkt in packets[:5]:
        print(
            "  {} | {} | {}:{} -> {}:{} | {} bytes | TTL={}".format(
                pkt["timestamp"],
                pkt["protocol"],
                pkt["sourceIp"],
                pkt["sourcePort"],
                pkt["destinationIp"],
                pkt["destinationPort"],
                pkt["packetSize"],
                pkt["ttl"],
            )
        )


if __name__ == "__main__":
    main()