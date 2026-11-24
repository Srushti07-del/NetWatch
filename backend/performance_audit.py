"""
NetWatch — Milestone 4D.4: Backend Performance & Reliability Audit
==================================================================

Comprehensive performance measurement for all backend endpoints.
Measures cold-cache and warm-cache latencies, response sizes, and serialization overhead.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import statistics
from typing import Dict, List, Tuple, Any

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
REAL_PCAP = os.path.join(BACKEND_DIR, "captures", "sample.pcapng")
PORT = 18766  # Different from test_integration.py to avoid conflicts
BASE_URL = f"http://127.0.0.1:{PORT}"

ENDPOINTS = [
    ("/api/dashboard/metrics", "GET"),
    ("/api/traffic", "GET"),
    ("/api/protocols", "GET"),
    ("/api/packets?limit=100", "GET"),
    ("/api/security-events", "GET"),
    ("/api/devices", "GET"),
    ("/api/connections", "GET"),
]

WARM_REQUESTS = 10  # Number of warm requests for averaging


def _wait_for_server(timeout: int = 20) -> bool:
    """Poll /api/health until the server is up or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def _make_request(path: str, timeout: int = 30) -> Tuple[int, bytes, float]:
    """Make a GET request; return (status_code, response_body_bytes, elapsed_ms)."""
    url = BASE_URL + path
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read()
            elapsed_ms = (time.perf_counter() - start) * 1000
            return resp.status, body, elapsed_ms
    except urllib.error.HTTPError as e:
        body = e.read()
        elapsed_ms = (time.perf_counter() - start) * 1000
        return e.code, body, elapsed_ms
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return 0, str(e).encode(), elapsed_ms


def _clear_all_caches():
    """Clear all internal caches by calling the module functions directly."""
    sys.path.insert(0, os.path.dirname(BACKEND_DIR))
    from analyzers.shared_capture import clear_caches as clear_shared_cache
    import analyzers.traffic_analyzer as ta_module
    clear_shared_cache()
    ta_module._ANALYSIS_CACHE.clear()


def measure_cold_requests(server_proc) -> List[Dict[str, Any]]:
    """Measure first request to each endpoint after clearing caches."""
    print("\n" + "=" * 70)
    print("COLD CACHE MEASUREMENTS (first request after cache clear)")
    print("=" * 70)
    
    results = []
    
    for path, method in ENDPOINTS:
        # Clear caches before each cold measurement
        _clear_all_caches()
        
        # Small delay to ensure caches are cleared
        time.sleep(0.1)
        
        code, body, elapsed_ms = _make_request(path)
        size_bytes = len(body)
        
        result = {
            "endpoint": path,
            "method": method,
            "status": code,
            "response_size_bytes": size_bytes,
            "response_size_kb": round(size_bytes / 1024, 2),
            "elapsed_ms": round(elapsed_ms, 2),
            "cache_state": "cold",
        }
        results.append(result)
        
        status_str = "OK" if code == 200 else f"ERROR({code})"
        print(f"  {path:35s} | {status_str:10s} | {size_bytes:>10,} bytes ({result['response_size_kb']:>6.2f} KB) | {elapsed_ms:>8.2f} ms")
    
    return results


def measure_warm_requests(server_proc) -> List[Dict[str, Any]]:
    """Measure multiple warm requests to each endpoint for statistics."""
    print("\n" + "=" * 70)
    print(f"WARM CACHE MEASUREMENTS ({WARM_REQUESTS} requests each, caches already populated)")
    print("=" * 70)
    
    all_results = []
    
    for path, method in ENDPOINTS:
        times = []
        sizes = []
        statuses = []
        
        for i in range(WARM_REQUESTS):
            code, body, elapsed_ms = _make_request(path)
            times.append(elapsed_ms)
            sizes.append(len(body))
            statuses.append(code)
            
            # Small delay between requests
            if i < WARM_REQUESTS - 1:
                time.sleep(0.01)
        
        # All requests should have same status and size (deterministic)
        status = statuses[0]
        size_bytes = sizes[0]
        size_kb = round(size_bytes / 1024, 2)
        
        avg_ms = statistics.mean(times)
        median_ms = statistics.median(times)
        stdev_ms = statistics.stdev(times) if len(times) > 1 else 0
        min_ms = min(times)
        max_ms = max(times)
        
        result = {
            "endpoint": path,
            "method": method,
            "status": status,
            "response_size_bytes": size_bytes,
            "response_size_kb": size_kb,
            "avg_ms": round(avg_ms, 2),
            "median_ms": round(median_ms, 2),
            "stdev_ms": round(stdev_ms, 2),
            "min_ms": round(min_ms, 2),
            "max_ms": round(max_ms, 2),
            "times_ms": [round(t, 2) for t in times],
            "cache_state": "warm",
        }
        all_results.append(result)
        
        status_str = "OK" if status == 200 else f"ERROR({status})"
        print(f"  {path:35s} | {status_str:10s} | {size_bytes:>10,} bytes ({size_kb:>6.2f} KB) | "
              f"avg={avg_ms:>7.2f}ms | median={median_ms:>7.2f}ms | "
              f"min={min_ms:>7.2f}ms | max={max_ms:>7.2f}ms | stdev={stdev_ms:>6.2f}ms")
    
    return all_results


def measure_serialization_overhead() -> Dict[str, Any]:
    """Measure JSON serialization overhead by comparing raw Python dict vs JSON string."""
    print("\n" + "=" * 70)
    print("SERIALIZATION OVERHEAD ANALYSIS")
    print("=" * 70)
    
    sys.path.insert(0, os.path.dirname(BACKEND_DIR))
    from analyzers.traffic_analyzer import analyze_capture
    import copy
    
    # Get full analysis result
    result = analyze_capture(REAL_PCAP)
    if result is None:
        return {"error": "Failed to analyze capture"}
    
    # Extract each endpoint's data
    endpoint_data = {
        "dashboard_metrics": result.get("dashboard_metrics"),
        "traffic_data": result.get("traffic_data"),
        "protocol_data": result.get("protocol_data"),
        "devices": result.get("devices"),
        "connections": result.get("connections"),
        "security_events": result.get("security_events"),
    }
    
    # Also get packets separately
    from analyzers.packet_analyzer import analyze_packets
    packets = analyze_packets(REAL_PCAP, limit=100)
    endpoint_data["packets"] = packets
    
    serialization_results = {}
    
    for name, data in endpoint_data.items():
        if data is None:
            continue
        
        # Deep copy to simulate what the API does
        data_copy = copy.deepcopy(data)
        
        # Measure JSON serialization
        start = time.perf_counter()
        json_str = json.dumps(data_copy)
        serialize_ms = (time.perf_counter() - start) * 1000
        
        # Measure JSON parsing (deserialization)
        start = time.perf_counter()
        json.loads(json_str)
        deserialize_ms = (time.perf_counter() - start) * 1000
        
        size_bytes = len(json_str.encode('utf-8'))
        
        serialization_results[name] = {
            "json_size_bytes": size_bytes,
            "json_size_kb": round(size_bytes / 1024, 2),
            "serialize_ms": round(serialize_ms, 2),
            "deserialize_ms": round(deserialize_ms, 2),
            "total_serde_ms": round(serialize_ms + deserialize_ms, 2),
        }
        
        print(f"  {name:25s} | {size_bytes:>10,} bytes ({serialization_results[name]['json_size_kb']:>6.2f} KB) | "
              f"serialize={serialize_ms:>6.2f}ms | deserialize={deserialize_ms:>6.2f}ms | "
              f"total={serialization_results[name]['total_serde_ms']:>6.2f}ms")
    
    return serialization_results


def measure_cache_stats() -> Dict[str, Any]:
    """Get cache statistics after warm measurements."""
    print("\n" + "=" * 70)
    print("CACHE STATISTICS")
    print("=" * 70)
    
    sys.path.insert(0, os.path.dirname(BACKEND_DIR))
    from analyzers.shared_capture import get_cache_stats
    import analyzers.traffic_analyzer as ta_module
    
    shared_stats = get_cache_stats()
    derived_entries = len(ta_module._ANALYSIS_CACHE)
    
    print(f"  Shared capture cache:")
    print(f"    Entries:          {shared_stats['entries']} / {shared_stats['max_entries']}")
    print(f"    Total packets:    {shared_stats['total_packets']:,} / {shared_stats['max_packets']:,}")
    print(f"  Derived analysis cache:")
    print(f"    Entries:          {derived_entries}")
    
    return {
        "shared_cache": shared_stats,
        "derived_cache_entries": derived_entries,
    }


def measure_in_flight_state() -> Dict[str, Any]:
    """Inspect in-flight results state."""
    print("\n" + "=" * 70)
    print("IN-FLIGHT RESULTS STATE")
    print("=" * 70)
    
    sys.path.insert(0, os.path.dirname(BACKEND_DIR))
    from analyzers.shared_capture import (
        _IN_FLIGHT_RESULTS,
        _IN_FLIGHT_RESULTS_LOCK,
        _PARSE_EVENTS,
        _PARSE_EVENTS_LOCK,
    )
    
    with _IN_FLIGHT_RESULTS_LOCK:
        in_flight_count = len(_IN_FLIGHT_RESULTS)
        in_flight_keys = list(_IN_FLIGHT_RESULTS.keys())
    
    with _PARSE_EVENTS_LOCK:
        parse_events_count = len(_PARSE_EVENTS)
        parse_events_keys = list(_PARSE_EVENTS.keys())
    
    print(f"  _IN_FLIGHT_RESULTS entries: {in_flight_count}")
    print(f"  _PARSE_EVENTS entries:      {parse_events_count}")
    
    if in_flight_keys:
        print(f"  In-flight keys (first 5):   {in_flight_keys[:5]}")
    if parse_events_keys:
        print(f"  Parse event keys (first 5): {parse_events_keys[:5]}")
    
    return {
        "in_flight_results_count": in_flight_count,
        "parse_events_count": parse_events_count,
        "in_flight_keys_sample": in_flight_keys[:5],
        "parse_event_keys_sample": parse_events_keys[:5],
    }


def run_full_audit():
    """Run the complete performance audit."""
    print("=" * 70)
    print("NetWatch — Milestone 4D.4: Backend Performance & Reliability Audit")
    print("=" * 70)
    print(f"PCAP file: {REAL_PCAP}")
    print(f"PCAP size: {os.path.getsize(REAL_PCAP):,} bytes ({os.path.getsize(REAL_PCAP)/1024/1024:.2f} MB)")
    print(f"Server port: {PORT}")
    
    # Start server
    print(f"\nStarting Uvicorn server on port {PORT}...")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "main:app",
            "--host", "127.0.0.1",
            "--port", str(PORT),
            "--log-level", "error",
        ],
        cwd=BACKEND_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    try:
        print(f"  Server PID: {proc.pid}")
        if not _wait_for_server(timeout=20):
            print("  ERROR: Server did not start within 20s")
            proc.terminate()
            return
        print("  Server ready.")
        
        # Run all measurements
        cold_results = measure_cold_requests(proc)
        warm_results = measure_warm_requests(proc)
        serialization_results = measure_serialization_overhead()
        cache_stats = measure_cache_stats()
        in_flight_state = measure_in_flight_state()
        
        # Summary
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        
        print("\nCold vs Warm Comparison:")
        for cold, warm in zip(cold_results, warm_results):
            if cold["status"] == 200 and warm["status"] == 200:
                speedup = cold["elapsed_ms"] / warm["avg_ms"] if warm["avg_ms"] > 0 else 0
                print(f"  {cold['endpoint']:35s} | cold={cold['elapsed_ms']:>7.2f}ms | "
                      f"warm_avg={warm['avg_ms']:>7.2f}ms | speedup={speedup:>5.1f}x")
        
        # Total cold sequence time
        total_cold = sum(r["elapsed_ms"] for r in cold_results if r["status"] == 200)
        print(f"\n  Total cold sequence (7 endpoints): {total_cold:.2f} ms ({total_cold/1000:.2f} s)")
        
        # Average warm time
        avg_warm = statistics.mean(r["avg_ms"] for r in warm_results if r["status"] == 200)
        print(f"  Average warm endpoint time:        {avg_warm:.2f} ms")
        
        # Total response sizes
        total_cold_size = sum(r["response_size_bytes"] for r in cold_results if r["status"] == 200)
        total_warm_size = sum(r["response_size_bytes"] for r in warm_results if r["status"] == 200)
        print(f"\n  Total cold response size:  {total_cold_size:,} bytes ({total_cold_size/1024:.2f} KB)")
        print(f"  Total warm response size:  {total_warm_size:,} bytes ({total_warm_size/1024:.2f} KB)")
        
        # Serialization summary
        if serialization_results:
            total_ser_size = sum(r["json_size_bytes"] for r in serialization_results.values())
            total_ser_time = sum(r["total_serde_ms"] for r in serialization_results.values())
            print(f"\n  Total JSON size (all endpoints):     {total_ser_size:,} bytes ({total_ser_size/1024:.2f} KB)")
            print(f"  Total serde time (all endpoints):    {total_ser_time:.2f} ms")
        
        # Cache efficiency
        print(f"\n  Cache entries used:     {cache_stats['shared_cache']['entries']} / {cache_stats['shared_cache']['max_entries']}")
        print(f"  Packets cached:         {cache_stats['shared_cache']['total_packets']:,} / {cache_stats['shared_cache']['max_packets']:,}")
        print(f"  Derived cache entries:  {cache_stats['derived_cache_entries']}")
        
        # In-flight state
        print(f"\n  In-flight results:      {in_flight_state['in_flight_results_count']}")
        print(f"  Parse events:           {in_flight_state['parse_events_count']}")
        
        return {
            "cold_results": cold_results,
            "warm_results": warm_results,
            "serialization_results": serialization_results,
            "cache_stats": cache_stats,
            "in_flight_state": in_flight_state,
            "summary": {
                "total_cold_ms": total_cold,
                "avg_warm_ms": avg_warm,
                "total_cold_size_bytes": total_cold_size,
                "total_warm_size_bytes": total_warm_size,
            }
        }
        
    finally:
        print("\nStopping server...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("  Server stopped.")


if __name__ == "__main__":
    os.chdir(BACKEND_DIR)
    results = run_full_audit()
    
    # Save results to JSON for reference
    output_path = os.path.join(BACKEND_DIR, "performance_audit_results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to: {output_path}")