"""
NetWatch — Milestone 4D.4: Deep Cache & In-Flight Analysis (Fixed)
====================================================================

Fixed version with better cleanup handling.
"""

import os
import sys
import time
import threading
import tempfile
import statistics
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BACKEND_DIR))

from analyzers.shared_capture import (
    get_parsed_capture,
    clear_caches,
    _PARSED_CAPTURE_CACHE,
    _PARSED_CAPTURE_LOCK,
    _PARSE_EVENTS,
    _PARSE_EVENTS_LOCK,
    _IN_FLIGHT_RESULTS,
    _IN_FLIGHT_RESULTS_LOCK,
    _CACHED_PACKET_COUNT,
    _get_cache_key,
    MAX_CACHE_ENTRIES,
    MAX_CACHE_PACKETS,
    _evict_lru_entries,
)
from analyzers.packet_analyzer import analyze_packets
from analyzers.traffic_analyzer import (
    get_dashboard_metrics,
    get_traffic_data,
    get_protocol_distribution,
    get_devices,
    get_connections,
    get_security_events,
    analyze_capture,
)
import analyzers.traffic_analyzer as ta_module


def _build_pcapng_with_tcp_packets(n_packets: int) -> bytes:
    import struct
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_len = 12 + len(shb_body)
    shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)

    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_len = 12 + len(idb_body)
    idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)

    epbs = b""
    for i in range(n_packets):
        dport = 1000 + i
        sport = 50000

        eth = bytes([0x00]*6 + [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] + [0x08, 0x00])

        iph_ver_ihl = 0x45
        iph_tos = 0
        total_len = 40
        ip_id = i
        ip_frag = 0
        ip_ttl = 64
        ip_proto = 6
        ip_chk = 0
        src_ip = bytes([10, 0, 0, 1])
        dst_ip = bytes([10, 0, 0, 2])
        iph = struct.pack("!BBHHHBBH", iph_ver_ihl, iph_tos, total_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_chk) + src_ip + dst_ip

        tcp_seq = 1000 + i
        tcp_ack = 0
        tcp_data_off = 0x50
        tcp_flags = 0x10
        tcp_win = 65535
        tcp_chk = 0
        tcp_urg = 0
        tcph = struct.pack("!HHIIBBHHH", sport, dport, tcp_seq, tcp_ack, tcp_data_off, tcp_flags, tcp_win, tcp_chk, tcp_urg)

        raw_packet = eth + iph + tcph

        ts_us = i * 1_000_000
        ts_hi = ts_us >> 32
        ts_lo = ts_us & 0xFFFFFFFF
        cap_len = len(raw_packet)
        orig_len = cap_len

        epb_body = struct.pack("<IIIII", 0, ts_hi, ts_lo, cap_len, orig_len) + raw_packet
        pad = (4 - (len(epb_body) % 4)) % 4
        epb_body += b"\x00" * pad
        epb_len = 12 + len(epb_body)
        epb = struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)
        epbs += epb

    return shb + idb + epbs


def _write_temp_pcapng(data: bytes, suffix: str = "") -> str:
    with tempfile.NamedTemporaryFile(suffix=f"{suffix}.pcapng", delete=False) as f:
        f.write(data)
        return f.name


def _safe_unlink(path: str):
    """Safely unlink a file, retrying if needed."""
    for _ in range(5):
        try:
            os.unlink(path)
            return
        except PermissionError:
            time.sleep(0.05)
            gc.collect()
    try:
        os.unlink(path)
    except:
        pass


def test_packet_count_accounting():
    """Test packet count accounting in detail."""
    print("\n" + "=" * 70)
    print("TEST: Packet Count Accounting")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    # Create a capture and analyze
    data = _build_pcapng_with_tcp_packets(100)
    path = _write_temp_pcapng(data, "_pktcount")
    
    try:
        print(f"  Created capture with 100 packets")
        
        with _PARSED_CAPTURE_LOCK:
            print(f"  Before analyze: entries={len(_PARSED_CAPTURE_CACHE)}, count={_CACHED_PACKET_COUNT}")
        
        result = analyze_capture(path)
        print(f"  analyze_capture returned: {result['total_packets'] if result else 'None'} packets")
        
        with _PARSED_CAPTURE_LOCK:
            print(f"  After analyze: entries={len(_PARSED_CAPTURE_CACHE)}, count={_CACHED_PACKET_COUNT}")
            for key, cap in _PARSED_CAPTURE_CACHE.items():
                print(f"    Cached capture: {cap.total_packets} packets")
        
        # Check the shared capture directly
        from analyzers.shared_capture import get_parsed_capture
        capture = get_parsed_capture(path)
        if capture:
            print(f"  get_parsed_capture: {capture.total_packets} packets")
        
    finally:
        _safe_unlink(path)
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


def test_in_flight_accumulation_detailed():
    """Detailed test of in-flight results accumulation."""
    print("\n" + "=" * 70)
    print("TEST: In-Flight Results Accumulation (Detailed)")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    # Create 10 distinct captures
    paths = []
    for i in range(10):
        data = _build_pcapng_with_tcp_packets(50)
        paths.append(_write_temp_pcapng(data, f"_inflight_acc_{i}"))
    
    try:
        print("  Analyzing 10 distinct captures sequentially...")
        for i, path in enumerate(paths):
            result = analyze_capture(path)
            with _IN_FLIGHT_RESULTS_LOCK:
                count = len(_IN_FLIGHT_RESULTS)
            print(f"    Capture {i}: {result['total_packets'] if result else 'FAILED'} packets | in-flight: {count}")
        
        print(f"\n  Final _IN_FLIGHT_RESULTS: {len(_IN_FLIGHT_RESULTS)} entries")
        print("  Keys:")
        with _IN_FLIGHT_RESULTS_LOCK:
            for key, val in list(_IN_FLIGHT_RESULTS.items())[:5]:
                print(f"    {key[:3]}... -> {'capture' if val else 'None (failed)'}")
        
        # Now analyze a capture that exceeds packet budget (not cached)
        print("\n  Analyzing oversized capture (1000 packets, budget=50000)...")
        oversized_data = _build_pcapng_with_tcp_packets(1000)
        oversized_path = _write_temp_pcapng(oversized_data, "_oversized")
        
        result = analyze_capture(oversized_path)
        print(f"  Oversized result: {result['total_packets'] if result else 'FAILED'} packets")
        
        with _IN_FLIGHT_RESULTS_LOCK:
            print(f"  _IN_FLIGHT_RESULTS after oversized: {len(_IN_FLIGHT_RESULTS)}")
        
        with _PARSED_CAPTURE_LOCK:
            print(f"  _PARSED_CAPTURE_CACHE after oversized: {len(_PARSED_CAPTURE_CACHE)} entries")
        
        _safe_unlink(oversized_path)
        
        # Now trigger a re-parse of one of the original captures
        print("\n  Re-analyzing capture 0 (should clean up its in-flight entry)...")
        result = analyze_capture(paths[0])
        
        with _IN_FLIGHT_RESULTS_LOCK:
            print(f"  _IN_FLIGHT_RESULTS after re-parse: {len(_IN_FLIGHT_RESULTS)}")
        
    finally:
        for path in paths:
            _safe_unlink(path)
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


def test_lru_eviction_with_packet_count():
    """Test LRU eviction with packet count limits."""
    print("\n" + "=" * 70)
    print("TEST: LRU Eviction with Packet Count Limits")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    # Temporarily reduce limits for testing
    import analyzers.shared_capture as sc_module
    orig_entries = sc_module.MAX_CACHE_ENTRIES
    orig_packets = sc_module.MAX_CACHE_PACKETS
    sc_module.MAX_CACHE_ENTRIES = 5
    sc_module.MAX_CACHE_PACKETS = 500
    
    try:
        paths = []
        for i in range(10):
            data = _build_pcapng_with_tcp_packets(100)
            paths.append(_write_temp_pcapng(data, f"_lru_{i}"))
        
        print(f"  Limits: MAX_CACHE_ENTRIES=5, MAX_CACHE_PACKETS=500")
        print(f"  Creating 10 captures with 100 packets each...")
        
        for i, path in enumerate(paths):
            result = analyze_capture(path)
            with _PARSED_CAPTURE_LOCK:
                entries = len(_PARSED_CAPTURE_CACHE)
                count = sc_module._CACHED_PACKET_COUNT
            print(f"    Capture {i}: entries={entries}, total_packets={count}")
        
        # Check which captures remain
        with _PARSED_CAPTURE_LOCK:
            print(f"\n  Final cache state:")
            print(f"    Entries: {len(_PARSED_CAPTURE_CACHE)} / {sc_module.MAX_CACHE_ENTRIES}")
            print(f"    Total packets: {sc_module._CACHED_PACKET_COUNT} / {sc_module.MAX_CACHE_PACKETS}")
            print(f"    Cached keys (MRU order):")
            for key, cap in list(_PARSED_CAPTURE_CACHE.items())[-5:]:
                print(f"      {cap.total_packets} packets")
        
    finally:
        sc_module.MAX_CACHE_ENTRIES = orig_entries
        sc_module.MAX_CACHE_PACKETS = orig_packets
        for path in paths:
            _safe_unlink(path)
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


def test_concurrent_different_captures():
    """Test concurrent requests for different captures."""
    print("\n" + "=" * 70)
    print("TEST: Concurrent Different Captures")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    paths = []
    for i in range(5):
        data = _build_pcapng_with_tcp_packets(50)
        paths.append(_write_temp_pcapng(data, f"_concurrent_{i}"))
    
    try:
        def analyze_one(path):
            return analyze_capture(path)
        
        print("  Starting 5 concurrent analyzes for different captures...")
        start = time.perf_counter()
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(analyze_one, path): i for i, path in enumerate(paths)}
            results = {}
            for future in as_completed(futures):
                i = futures[future]
                results[i] = future.result()
        
        elapsed = (time.perf_counter() - start) * 1000
        print(f"  Total time: {elapsed:.2f} ms")
        
        import analyzers.shared_capture as sc_module
        with _PARSED_CAPTURE_LOCK:
            print(f"  Shared cache entries: {len(_PARSED_CAPTURE_CACHE)}")
            print(f"  Total packets cached: {sc_module._CACHED_PACKET_COUNT}")
        
        with _IN_FLIGHT_RESULTS_LOCK:
            print(f"  In-flight results: {len(_IN_FLIGHT_RESULTS)}")
        
        # Verify all succeeded
        for i, result in results.items():
            print(f"    Capture {i}: {result['total_packets'] if result else 'FAILED'} packets")
        
    finally:
        for path in paths:
            _safe_unlink(path)
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


def test_stale_data_protection():
    """Test that modifications to returned data don't affect cache."""
    print("\n" + "=" * 70)
    print("TEST: Stale Data Protection (Mutation Isolation)")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    path = BACKEND_DIR + "/captures/sample.pcapng"
    
    # Get data multiple times and mutate
    metrics1 = get_dashboard_metrics(path)
    metrics2 = get_dashboard_metrics(path)
    
    # Mutate first result
    metrics1["totalPackets"] = 99999
    metrics1["bandwidthUsage"] = -1.0
    
    # Get again
    metrics3 = get_dashboard_metrics(path)
    
    if metrics3["totalPackets"] == metrics2["totalPackets"]:
        print("  PASS: Dashboard metrics isolated from mutations")
    else:
        print(f"  FAIL: Cache polluted! Expected {metrics2['totalPackets']}, got {metrics3['totalPackets']}")
    
    # Test connections (larger structure)
    conn1 = get_connections(path)
    conn2 = get_connections(path)
    
    if conn1:
        conn1[0]["bytesTransferred"] = -999
    
    conn3 = get_connections(path)
    
    if conn3 and conn3[0]["bytesTransferred"] == conn2[0]["bytesTransferred"]:
        print("  PASS: Connections isolated from mutations")
    else:
        print("  FAIL: Connections cache polluted!")
    
    # Test packets (from packet_analyzer)
    from analyzers.packet_analyzer import analyze_packets
    pkts1 = analyze_packets(path, limit=10)
    pkts2 = analyze_packets(path, limit=10)
    
    if pkts1:
        pkts1[0]["protocol"] = "MUTATED"
    
    pkts3 = analyze_packets(path, limit=10)
    
    if pkts3 and pkts3[0]["protocol"] == pkts2[0]["protocol"]:
        print("  PASS: Packets isolated from mutations")
    else:
        print("  FAIL: Packets cache polluted!")


if __name__ == "__main__":
    print("=" * 70)
    print("NetWatch — Milestone 4D.4: Deep Cache & In-Flight Analysis (Fixed)")
    print("=" * 70)
    
    test_packet_count_accounting()
    test_in_flight_accumulation_detailed()
    test_lru_eviction_with_packet_count()
    test_concurrent_different_captures()
    test_stale_data_protection()
    
    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)