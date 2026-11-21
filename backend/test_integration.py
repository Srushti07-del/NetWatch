"""
NetWatch — Milestone 4C.1 Integration Tests
============================================

Real HTTP integration tests for all backend endpoints.

Test strategy
-------------
- Starts a Uvicorn subprocess on port 18765 (unlikely to be in use).
- Uses stdlib urllib.request to make real HTTP calls through the ASGI stack,
  covering routing, middleware, and status-code handling.
- Tests the real sample.pcapng (normal path) AND synthetic PCAP scenarios
  (missing file → 404, empty capture → 200, corrupt file → 500).

NOTE: Synthetic-capture tests require temporarily overriding PCAP_PATH in
      main.py via an env-var mechanism.  Because main.py hardcodes PCAP_PATH
      at module-import time, the cleanest approach is to invoke the tests that
      exercise HTTP 404/500 semantics by calling the analyzer functions directly
      (logic-level tests), while still verifying HTTP status codes against the
      real server for the nominal path.

Synthetic path tests are therefore split:
  - Nominal HTTP (server running against real PCAP): urllib calls → real HTTP codes.
  - Synthetic path (missing/empty/corrupt PCAP): logic-level, using analyzer
    functions directly with synthetic paths — documents exactly what happens at
    the function level and what the endpoint would return.

Run from the backend/ directory:
    python test_integration.py
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BACKEND_DIR))

REAL_PCAP = os.path.join(BACKEND_DIR, "captures", "sample.pcapng")
PORT = 18765
BASE_URL = f"http://127.0.0.1:{PORT}"

# ---------------------------------------------------------------------------
# Minimal valid PCAPNG builder (section header + interface description block)
# ---------------------------------------------------------------------------

def _build_empty_pcapng() -> bytes:
    """Return bytes for a valid PCAPNG file containing 0 packets."""
    # Section Header Block (SHB)
    byte_order_magic = 0x1A2B3C4D
    major = 1
    minor = 0
    section_len = -1  # 0xFFFFFFFFFFFFFFFF as signed int64 — means "unknown length"
    shb_body = struct.pack("<IHHq", byte_order_magic, major, minor, section_len)
    shb_len = 12 + len(shb_body)  # type(4) + total_len(4) + body + total_len(4)
    shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)

    # Interface Description Block (IDB) — link type 1 (Ethernet)
    link_type = 1
    snap_len = 65535
    idb_body = struct.pack("<HHI", link_type, 0, snap_len)
    idb_len = 12 + len(idb_body)
    idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)

    return shb + idb


# ---------------------------------------------------------------------------
# Test infrastructure helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0
_results = []


def _ok(name: str, detail: str = ""):
    global PASS
    PASS += 1
    _results.append(("PASS", name, detail))
    print(f"  PASS  {name}" + (f" — {detail}" if detail else ""))


def _fail(name: str, detail: str = ""):
    global FAIL
    FAIL += 1
    _results.append(("FAIL", name, detail))
    print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


def _get(path: str, timeout: int = 10):
    """Make a GET request; return (status_code, response_body_dict_or_str)."""
    url = BASE_URL + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read().decode()
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body


def _wait_for_server(timeout: int = 15) -> bool:
    """Poll /api/health until the server is up or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------------------
# 1. Logic-level tests (no HTTP server needed)
# ---------------------------------------------------------------------------

def run_logic_tests():
    """Test analyzer functions directly for synthetic PCAP scenarios."""
    print("\n── Logic-level tests (synthetic PCAP scenarios) ──")

    from analyzers.traffic_analyzer import analyze_capture
    from analyzers.security_analyzer import SecurityEventDetector

    # 1a. Missing file → analyze_capture returns None
    missing = os.path.join(BACKEND_DIR, "captures", "__nonexistent__.pcapng")
    result = analyze_capture(missing)
    if result is None:
        _ok("Missing PCAP → analyze_capture returns None (endpoint would return HTTP 404)")
    else:
        _fail("Missing PCAP → analyze_capture returned non-None", str(result)[:80])

    # 1b. Zero-byte file → Scapy exception → returns None
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        zero_path = f.name  # file exists, 0 bytes
    try:
        result = analyze_capture(zero_path)
        if result is None:
            _ok("Zero-byte file → analyze_capture returns None (endpoint would return HTTP 500)")
        else:
            _fail("Zero-byte file → analyze_capture returned non-None")
    finally:
        os.unlink(zero_path)

    # 1c. Valid empty PCAPNG → HTTP 200 with empty arrays
    empty_bytes = _build_empty_pcapng()
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        f.write(empty_bytes)
        empty_path = f.name
    try:
        result = analyze_capture(empty_path)
        if result is not None:
            checks = (
                result["total_packets"] == 0,
                result["devices"] == [],
                result["connections"] == [],
                result["security_events"] == [],
                result["dashboard_metrics"]["securityAlerts"] == 0,
                result["dashboard_metrics"]["criticalAlerts"] == 0,
            )
            if all(checks):
                _ok("Valid empty PCAPNG → analyze_capture returns HTTP-200-compatible empty result")
            else:
                _fail("Valid empty PCAPNG → unexpected field values", str(result["dashboard_metrics"]))
        else:
            _fail("Valid empty PCAPNG → analyze_capture returned None")
    finally:
        os.unlink(empty_path)

    # 1d. Corrupt file → Scapy exception → returns None
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        f.write(b"THISISNOTAPCAPNGFILE\xff\x00\x01\x02\x03")
        corrupt_path = f.name
    try:
        result = analyze_capture(corrupt_path)
        if result is None:
            _ok("Corrupt file → analyze_capture returns None (endpoint would return HTTP 500)")
        else:
            _fail("Corrupt file → analyze_capture returned non-None")
    finally:
        try:
            os.unlink(corrupt_path)
        except PermissionError:
            pass  # Scapy may hold the handle briefly on exception

    # 1e. Synthetic TCP port scan — 8 SYN packets to different ports from same source
    print("\n  [Synthetic TCP scan detection]")
    _test_synthetic_tcp_scan()

    # 1f. Sliding window boundary — packets just outside window should not merge
    _test_window_boundary()

    # 1g. Single SYN packet — below threshold, no event
    _test_single_syn_no_event()


def _make_synthetic_pcapng_with_syns(n_ports: int) -> bytes:
    """
    Build a PCAPNG with n_ports SYN packets from 10.0.0.1 to 10.0.0.2
    on ports 1000..1000+n_ports, spaced 1 second apart within window.
    Uses raw byte construction (no Scapy dependency at test time).
    """
    import struct

    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_len = 12 + len(shb_body)
    shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)

    idb_body = struct.pack("<HHI", 1, 0, 65535)  # Ethernet
    idb_len = 12 + len(idb_body)
    idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)

    epbs = b""
    for i in range(n_ports):
        dport = 1000 + i
        sport = 50000

        # Ethernet header (14 bytes)
        eth = bytes([0x00]*6 + [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] + [0x08, 0x00])

        # IPv4 header (20 bytes)
        iph_ver_ihl = 0x45
        iph_tos = 0
        total_len = 40  # 20 IP + 20 TCP
        ip_id = i
        ip_frag = 0
        ip_ttl = 64
        ip_proto = 6  # TCP
        ip_chk = 0
        src_ip = bytes([10, 0, 0, 1])
        dst_ip = bytes([10, 0, 0, 2])
        iph = struct.pack("!BBHHHBBH", iph_ver_ihl, iph_tos, total_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_chk) + src_ip + dst_ip

        # TCP header (20 bytes), SYN flag = 0x02
        tcp_seq = 1000 + i
        tcp_ack = 0
        tcp_data_off = 0x50  # 5*4=20 bytes
        tcp_flags = 0x02  # SYN
        tcp_win = 65535
        tcp_chk = 0
        tcp_urg = 0
        tcph = struct.pack("!HHIIBBHHH", sport, dport, tcp_seq, tcp_ack, tcp_data_off, tcp_flags, tcp_win, tcp_chk, tcp_urg)

        raw_packet = eth + iph + tcph

        # EPB: timestamp in microseconds (1 second apart)
        ts_us = i * 1_000_000
        ts_hi = ts_us >> 32
        ts_lo = ts_us & 0xFFFFFFFF
        cap_len = len(raw_packet)
        orig_len = cap_len

        epb_body = struct.pack("<IIIII", 0, ts_hi, ts_lo, cap_len, orig_len) + raw_packet
        # Pad to 32-bit alignment
        pad = (4 - (len(epb_body) % 4)) % 4
        epb_body += b"\x00" * pad
        epb_len = 12 + len(epb_body)
        epb = struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)
        epbs += epb

    return shb + idb + epbs


def _test_synthetic_tcp_scan():
    """8 SYN packets to 8 distinct ports → should produce 1 TCP port-scan event."""
    from analyzers.traffic_analyzer import analyze_capture

    pcapng_bytes = _make_synthetic_pcapng_with_syns(8)
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        f.write(pcapng_bytes)
        path = f.name
    try:
        result = analyze_capture(path)
        if result is None:
            _fail("Synthetic TCP scan: analyze_capture returned None")
            return
        events = result["security_events"]
        if len(events) == 1 and events[0]["eventType"] == "port_scan" and events[0]["protocol"] == "TCP":
            _ok("Synthetic TCP scan (8 SYN → 8 ports) → 1 TCP port_scan event detected",
                f"severity={events[0]['severity']}, src={events[0]['sourceIp']}")
        else:
            _fail("Synthetic TCP scan: unexpected events", str(events))
    finally:
        os.unlink(path)


def _test_window_boundary():
    """Packets outside the 60s window should not combine with packets inside it."""
    from analyzers.security_analyzer import SecurityEventDetector

    detector = SecurityEventDetector(tcp_syn_threshold=5, window_seconds=60.0)
    # 3 SYN packets at t=0, then 3 more at t=120 (outside window)
    for port in range(3):
        detector.observe_tcp(float(port), "192.168.1.1", "10.0.0.1", 50000, 1000 + port, "S")
    for port in range(3, 6):
        detector.observe_tcp(120.0 + port, "192.168.1.1", "10.0.0.1", 50000, 1000 + port, "S")

    events = detector.evaluate()
    if len(events) == 0:
        _ok("Window boundary: 3+3 SYNs split across >60s gap → 0 events (correct)")
    else:
        _fail("Window boundary: unexpected events detected", str(events))


def _test_single_syn_no_event():
    """A single SYN packet must not trigger a port-scan event."""
    from analyzers.security_analyzer import SecurityEventDetector

    detector = SecurityEventDetector()
    detector.observe_tcp(0.0, "192.168.1.1", "10.0.0.1", 50000, 80, "S")
    events = detector.evaluate()
    if len(events) == 0:
        _ok("Single SYN → 0 events (below threshold)")
    else:
        _fail("Single SYN → unexpected event triggered", str(events))


# ---------------------------------------------------------------------------
# 2. HTTP integration tests (real Uvicorn against real PCAP)
# ---------------------------------------------------------------------------

def run_http_tests():
    """Start a live Uvicorn server and run real HTTP calls against it."""
    if not os.path.exists(REAL_PCAP):
        print(f"\n  SKIP  HTTP tests — real PCAP not found at: {REAL_PCAP}")
        return

    print(f"\n── HTTP integration tests (Uvicorn on port {PORT}) ──")

    # Launch Uvicorn in a subprocess, pointing at the real PCAP.
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
        print(f"  Starting Uvicorn (pid={proc.pid})…", end=" ", flush=True)
        if not _wait_for_server(timeout=20):
            _fail("Server did not start within 20s")
            proc.terminate()
            return
        print("ready.")

        # ── Nominal endpoint tests ──────────────────────────────────────────

        # /api/health
        code, body = _get("/api/health")
        if code == 200 and isinstance(body, dict) and body.get("status") == "ok":
            _ok("GET /api/health → 200 {status: ok}")
        else:
            _fail("GET /api/health", f"status={code}, body={body}")

        # /api/packets
        code, body = _get("/api/packets")
        if code == 200 and isinstance(body, list) and len(body) > 0:
            _ok("GET /api/packets → 200, non-empty list", f"count={len(body)}")
        else:
            _fail("GET /api/packets", f"status={code}")

        # /api/dashboard/metrics
        code, body = _get("/api/dashboard/metrics")
        if code == 200 and isinstance(body, dict):
            tp = body.get("totalPackets")
            sa = body.get("securityAlerts")
            ca = body.get("criticalAlerts")
            bw = body.get("bandwidthUsage")
            if tp == 934 and sa == 0 and ca == 0 and isinstance(bw, float):
                _ok("GET /api/dashboard/metrics → 200, totalPackets=934, securityAlerts=0",
                    f"bandwidthUsage={bw}")
            else:
                _fail("GET /api/dashboard/metrics: unexpected values",
                      f"totalPackets={tp}, securityAlerts={sa}, bw={bw}")
        else:
            _fail("GET /api/dashboard/metrics", f"status={code}")

        # /api/traffic
        code, body = _get("/api/traffic")
        if code == 200 and isinstance(body, list) and len(body) == 24:
            first = body[0]
            if "time" in first and "incoming" in first and "outgoing" in first:
                _ok("GET /api/traffic → 200, 24 hourly buckets with time/incoming/outgoing")
            else:
                _fail("GET /api/traffic: missing required fields", str(first))
        else:
            _fail("GET /api/traffic", f"status={code}, len={len(body) if isinstance(body, list) else 'n/a'}")

        # /api/protocols
        code, body = _get("/api/protocols")
        if code == 200 and isinstance(body, list) and len(body) > 0:
            first = body[0]
            # API shape: {protocol, value, percentage, color}
            if "protocol" in first and "value" in first and "percentage" in first:
                _ok("GET /api/protocols → 200, non-empty list with protocol/value/percentage",
                    f"protocols={[p['protocol'] for p in body]}")
            else:
                _fail("GET /api/protocols: missing required fields", str(first))
        else:
            _fail("GET /api/protocols", f"status={code}")

        # /api/devices
        code, body = _get("/api/devices")
        if code == 200 and isinstance(body, list):
            if len(body) == 2:
                _ok("GET /api/devices → 200, 2 devices", f"ips={[d.get('ipAddress') for d in body]}")
            else:
                _fail("GET /api/devices: expected 2 devices", f"got {len(body)}: {[d.get('ipAddress') for d in body]}")
            # Verify required fields (actual API shape)
            if body:
                d = body[0]
                required = {"id", "ipAddress", "macAddress", "lastSeen",
                            "trafficIn", "trafficOut", "isActive", "openPorts"}
                missing = required - set(d.keys())
                if not missing:
                    _ok("GET /api/devices: required fields all present")
                else:
                    _fail("GET /api/devices: missing fields", str(missing))
        else:
            _fail("GET /api/devices", f"status={code}")

        # /api/connections
        code, body = _get("/api/connections")
        if code == 200 and isinstance(body, list):
            _ok("GET /api/connections → 200", f"count={len(body)}")
            if body:
                c = body[0]
                # Actual API shape: {id, sourceIp, destinationIp, sourcePort, destinationPort,
                #                    protocol, status, established, duration, bytesTransferred}
                required = {"id", "sourceIp", "destinationIp", "protocol",
                            "bytesTransferred", "established", "status"}
                missing = required - set(c.keys())
                if not missing:
                    _ok("GET /api/connections: required fields all present")
                else:
                    _fail("GET /api/connections: missing fields", str(missing))
        else:
            _fail("GET /api/connections", f"status={code}")

        # /api/security-events
        code, body = _get("/api/security-events")
        if code == 200 and isinstance(body, list) and len(body) == 0:
            _ok("GET /api/security-events → 200, empty list (sample PCAP has no scan events)")
        elif code == 200 and isinstance(body, list):
            _ok("GET /api/security-events → 200", f"count={len(body)}")
        else:
            _fail("GET /api/security-events", f"status={code}")

        # security metrics consistency check
        code_m, body_m = _get("/api/dashboard/metrics")
        code_s, body_s = _get("/api/security-events")
        if code_m == 200 and code_s == 200:
            metric_sa = body_m.get("securityAlerts", -1)
            metric_ca = body_m.get("criticalAlerts", -1)
            actual_sa = len(body_s)
            actual_ca = sum(1 for e in body_s if e.get("severity") == "critical")
            if metric_sa == actual_sa and metric_ca == actual_ca:
                _ok("Dashboard security metrics consistent with /api/security-events",
                    f"securityAlerts={metric_sa}, criticalAlerts={metric_ca}")
            else:
                _fail("Dashboard security metrics mismatch",
                      f"metrics: sa={metric_sa} ca={metric_ca}, events: sa={actual_sa} ca={actual_ca}")

        # 404 on unknown route
        code, body = _get("/api/nonexistent")
        if code == 404:
            _ok("GET /api/nonexistent → 404 (FastAPI default)")
        else:
            _fail("GET /api/nonexistent", f"status={code}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.chdir(BACKEND_DIR)

    print("=" * 60)
    print("NetWatch — Milestone 4C.1 Integration Tests")
    print("=" * 60)

    run_logic_tests()
    run_http_tests()

    print("\n" + "=" * 60)
    total = PASS + FAIL
    print(f"Results: {PASS}/{total} passed, {FAIL} failed")
    print("=" * 60)
    sys.exit(0 if FAIL == 0 else 1)
