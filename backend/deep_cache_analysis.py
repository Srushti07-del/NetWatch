"""
NetWatch — Milestone 4D.4: Deep Cache & In-Flight Analysis
===========================================================

Detailed investigation of:
1. In-flight results lifecycle and cleanup
2. Deep copy overhead in traffic analyzer
3. Concurrent request behavior
4. Cache eviction with multiple captures
"""

import os
import sys
import time
import threading
import tempfile
import statistics
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
    """Build a valid PCAPNG with n_packets TCP packets."""
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
        tcp_flags = 0x10  # ACK
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


def test_in_flight_lifecycle():
    """Test the in-flight results lifecycle - do they accumulate?"""
    print("\n" + "=" * 70)
    print("TEST: In-Flight Results Lifecycle")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    # Create multiple distinct captures
    paths = []
    for i in range(5):
        data = _build_pcapng_with_tcp_packets(100)
        paths.append(_write_temp_pcapng(data, f"_inflight_{i}"))
    
    try:
        # Analyze each capture once
        for i, path in enumerate(paths):
            result = analyze_capture(path)
            if result is None:
                print(f"  Capture {i}: FAILED")
            else:
                print(f"  Capture {i}: OK ({result['total_packets']} packets)")
        
        # Check in-flight results
        with _IN_FLIGHT_RESULTS_LOCK:
            in_flight_count = len(_IN_FLIGHT_RESULTS)
            print(f"\n  After 5 distinct captures analyzed:")
            print(f"    _IN_FLIGHT_RESULTS entries: {in_flight_count}")
            for key in list(_IN_FLIGHT_RESULTS.keys())[:3]:
                print(f"      Key: {key[:3]}...")
        
        # Analyze them again (warm)
        for i, path in enumerate(paths):
            result = analyze_capture(path)
        
        with _IN_FLIGHT_RESULTS_LOCK:
            in_flight_count2 = len(_IN_FLIGHT_RESULTS)
            print(f"\n  After re-analyzing same 5 captures:")
            print(f"    _IN_FLIGHT_RESULTS entries: {in_flight_count2}")
        
        # Cleanup
        for path in paths:
            os.unlink(path)
        
    finally:
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


def test_deep_copy_overhead():
    """Measure the overhead of deepcopy in traffic analyzer endpoints."""
    print("\n" + "=" * 70)
    print("TEST: Deep Copy Overhead")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    # Warm up
    result = analyze_capture(BACKEND_DIR + "/captures/sample.pcapng")
    
    import copy
    import json
    
    # Get the full analysis result
    full_result = analyze_capture(BACKEND_DIR + "/captures/sample.pcapng")
    
    # Extract each endpoint's data
    endpoints_data = {
        "dashboard_metrics": full_result.get("dashboard_metrics"),
        "traffic_data": full_result.get("traffic_data"),
        "protocol_data": full_result.get("protocol_data"),
        "devices": full_result.get("devices"),
        "connections": full_result.get("connections"),
        "security_events": full_result.get("security_events"),
    }
    
    from analyzers.packet_analyzer import analyze_packets
    endpoints_data["packets"] = analyze_packets(BACKEND_DIR + "/captures/sample.pcapng", limit=100)
    
    for name, data in endpoints_data.items():
        if data is None:
            continue
        
        # Time deepcopy
        times = []
        for _ in range(100):
            start = time.perf_counter()
            copied = copy.deepcopy(data)
            times.append((time.perf_counter() - start) * 1000)
        
        avg_copy = statistics.mean(times)
        median_copy = statistics.median(times)
        
        # Time JSON serialization of original vs copied
        start = time.perf_counter()
        json_str = json.dumps(data)
        ser_orig = (time.perf_counter() - start) * 1000
        
        start = time.perf_counter()
        json_str2 = json.dumps(copied)
        ser_copy = (time.perf_counter() - start) * 1000
        
        print(f"  {name:25s} | deepcopy avg={avg_copy:.3f}ms median={median_copy:.3f}ms | "
              f"JSON orig={ser_orig:.3f}ms copy={ser_copy:.3f}ms | "
              f"size={len(json.dumps(data))} bytes")


def test_concurrent_endpoint_requests():
    """Test concurrent requests to different endpoints for the same capture."""
    print("\n" + "=" * 70)
    print("TEST: Concurrent Endpoint Requests")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    endpoints = [
        ("dashboard_metrics", lambda p: get_dashboard_metrics(p)),
        ("traffic", lambda p: get_traffic_data(p)),
        ("protocols", lambda p: get_protocol_distribution(p)),
        ("devices", lambda p: get_devices(p)),
        ("connections", lambda p: get_connections(p)),
        ("security_events", lambda p: get_security_events(p)),
        ("packets", lambda p: analyze_packets(p, limit=100)),
    ]
    
    path = BACKEND_DIR + "/captures/sample.pcapng"
    
    # Cold concurrent
    print("  Cold concurrent (all endpoints simultaneously)...")
    start = time.perf_counter()
    
    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(func, path): name for name, func in endpoints}
        results = {}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = f"ERROR: {e}"
    
    cold_time = (time.perf_counter() - start) * 1000
    print(f"    Total time: {cold_time:.2f} ms")
    print(f"    Shared cache entries: {len(_PARSED_CAPTURE_CACHE)}")
    print(f"    Derived cache entries: {len(ta_module._ANALYSIS_CACHE)}")
    
    # Warm concurrent
    print("\n  Warm concurrent (all endpoints simultaneously)...")
    start = time.perf_counter()
    
    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(func, path): name for name, func in endpoints}
        results = {}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = f"ERROR: {e}"
    
    warm_time = (time.perf_counter() - start) * 1000
    print(f"    Total time: {warm_time:.2f} ms")
    print(f"    Shared cache entries: {len(_PARSED_CAPTURE_CACHE)}")
    print(f"    Derived cache entries: {len(ta_module._ANALYSIS_CACHE)}")
    
    print(f"\n  Speedup: {cold_time/warm_time:.1f}x")


def test_multiple_captures_cache_behavior():
    """Test cache behavior with multiple distinct captures."""
    print("\n" + "=" * 70)
    print("TEST: Multiple Captures Cache Behavior")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    # Create 10 captures with 200 packets each = 2000 total
    paths = []
    for i in range(10):
        data = _build_pcapng_with_tcp_packets(200)
        paths.append(_write_temp_pcapng(data, f"_multi_{i}"))
    
    try:
        print("  Analyzing 10 captures (200 packets each)...")
        for i, path in enumerate(paths):
            result = analyze_capture(path)
            if result:
                print(f"    Capture {i}: {result['total_packets']} packets")
        
        with _PARSED_CAPTURE_LOCK:
            print(f"\n  Shared cache state:")
            print(f"    Entries: {len(_PARSED_CAPTURE_CACHE)} / {MAX_CACHE_ENTRIES}")
            print(f"    Total packets: {_CACHED_PACKET_COUNT} / {MAX_CACHE_PACKETS}")
        
        # Now add more captures to trigger eviction
        print("\n  Adding 25 more captures to trigger LRU eviction...")
        extra_paths = []
        for i in range(25):
            data = _build_pcapng_with_tcp_packets(50)
            extra_paths.append(_write_temp_pcapng(data, f"_extra_{i}"))
        
        for i, path in enumerate(extra_paths):
            analyze_capture(path)
        
        with _PARSED_CAPTURE_LOCK:
            print(f"\n  After adding 25 more captures:")
            print(f"    Entries: {len(_PARSED_CAPTURE_CACHE)} / {MAX_CACHE_ENTRIES}")
            print(f"    Total packets: {_CACHED_PACKET_COUNT} / {MAX_CACHE_PACKETS}")
        
        # Check in-flight results
        with _IN_FLIGHT_RESULTS_LOCK:
            print(f"\n  _IN_FLIGHT_RESULTS entries: {len(_IN_FLIGHT_RESULTS)}")
            if len(_IN_FLIGHT_RESULTS) > 10:
                print(f"    WARNING: In-flight results accumulating! ({len(_IN_FLIGHT_RESULTS)} entries)")
        
        for path in extra_paths:
            os.unlink(path)
        
    finally:
        for path in paths:
            os.unlink(path)
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


def test_failed_parse_cleanup():
    """Test that failed parses clean up properly."""
    print("\n" + "=" * 70)
    print("TEST: Failed Parse Cleanup")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    # Create corrupt file
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        f.write(b"NOT A PCAPNG FILE\x00\x01\x02\x03")
        corrupt_path = f.name
    
    try:
        # Multiple concurrent requests for corrupt file
        def worker():
            return analyze_capture(corrupt_path)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker) for _ in range(5)]
            results = [f.result() for f in futures]
        
        print(f"  Results: {[r is None for r in results]}")
        
        with _PARSE_EVENTS_LOCK:
            print(f"  _PARSE_EVENTS after failed parses: {len(_PARSE_EVENTS)}")
        
        with _IN_FLIGHT_RESULTS_LOCK:
            print(f"  _IN_FLIGHT_RESULTS after failed parses: {len(_IN_FLIGHT_RESULTS)}")
        
        with _PARSED_CAPTURE_LOCK:
            print(f"  _PARSED_CAPTURE_CACHE after failed parses: {len(_PARSED_CAPTURE_CACHE)}")
        
    finally:
        os.unlink(corrupt_path)
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


def test_file_replacement_invalidation():
    """Test that file replacement properly invalidates cache."""
    print("\n" + "=" * 70)
    print("TEST: File Replacement Invalidation")
    print("=" * 70)
    
    clear_caches()
    ta_module._ANALYSIS_CACHE.clear()
    
    data1 = _build_pcapng_with_tcp_packets(50)
    data2 = _build_pcapng_with_tcp_packets(100)  # Different packet count
    path = _write_temp_pcapng(data1, "_replace")
    
    try:
        # First analysis
        result1 = analyze_capture(path)
        print(f"  First analysis: {result1['total_packets'] if result1 else 'FAILED'} packets")
        
        with _PARSED_CAPTURE_LOCK:
            keys_before = list(_PARSED_CAPTURE_CACHE.keys())
            print(f"  Cache keys before: {len(keys_before)}")
        
        # Replace file
        os.unlink(path)
        time.sleep(0.01)
        with open(path, "wb") as f:
            f.write(data2)
        
        # Second analysis
        result2 = analyze_capture(path)
        print(f"  Second analysis: {result2['total_packets'] if result2 else 'FAILED'} packets")
        
        with _PARSED_CAPTURE_LOCK:
            keys_after = list(_PARSED_CAPTURE_CACHE.keys())
            print(f"  Cache keys after: {len(keys_after)}")
            if keys_after != keys_before:
                print(f"  Cache key changed (invalidation worked)")
            else:
                print(f"  WARNING: Cache key unchanged!")
        
        with _IN_FLIGHT_RESULTS_LOCK:
            print(f"  _IN_FLIGHT_RESULTS entries: {len(_IN_FLIGHT_RESULTS)}")
        
    finally:
        os.unlink(path)
        clear_caches()
        ta_module._ANALYSIS_CACHE.clear()


if __name__ == "__main__":
    print("=" * 70)
    print("NetWatch — Milestone 4D.4: Deep Cache & In-Flight Analysis")
    print("=" * 70)
    
    test_in_flight_lifecycle()
    test_deep_copy_overhead()
    test_concurrent_endpoint_requests()
    test_multiple_captures_cache_behavior()
    test_failed_parse_cleanup()
    test_file_replacement_invalidation()
    
    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)