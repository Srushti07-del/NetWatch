import os
import sys
import tempfile
import struct
sys.path.insert(0, os.path.dirname(os.path.abspath('.')))

import analyzers.shared_capture as sc
from analyzers.traffic_analyzer import analyze_capture
import analyzers.traffic_analyzer as ta_module


def _build_pcapng_with_tcp_packets(n_packets: int) -> bytes:
    shb_body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    shb_len = 12 + len(shb_body)
    shb = struct.pack('<II', 0x0A0D0D0A, shb_len) + shb_body + struct.pack('<I', shb_len)
    idb_body = struct.pack('<HHI', 1, 0, 65535)
    idb_len = 12 + len(idb_body)
    idb = struct.pack('<II', 0x00000001, idb_len) + idb_body + struct.pack('<I', idb_len)
    epbs = b''
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
        iph = struct.pack('!BBHHHBBH', iph_ver_ihl, iph_tos, total_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_chk) + src_ip + dst_ip
        tcp_seq = 1000 + i
        tcp_ack = 0
        tcp_data_off = 0x50
        tcp_flags = 0x10
        tcp_win = 65535
        tcp_chk = 0
        tcp_urg = 0
        tcph = struct.pack('!HHIIBBHHH', sport, dport, tcp_seq, tcp_ack, tcp_data_off, tcp_flags, tcp_win, tcp_chk, tcp_urg)
        raw_packet = eth + iph + tcph
        ts_us = i * 1_000_000
        ts_hi = ts_us >> 32
        ts_lo = ts_us & 0xFFFFFFFF
        cap_len = len(raw_packet)
        orig_len = cap_len
        epb_body = struct.pack('<IIIII', 0, ts_hi, ts_lo, cap_len, orig_len) + raw_packet
        pad = (4 - (len(epb_body) % 4)) % 4
        epb_body += b'\x00' * pad
        epb_len = 12 + len(epb_body)
        epb = struct.pack('<II', 0x00000006, epb_len) + epb_body + struct.pack('<I', epb_len)
        epbs += epb
    return shb + idb + epbs


sc.clear_caches()
ta_module._ANALYSIS_CACHE.clear()

# Create 5 distinct captures
paths = []
for i in range(5):
    data = _build_pcapng_with_tcp_packets(100)
    with tempfile.NamedTemporaryFile(suffix=f'_inflight_{i}.pcapng', delete=False) as f:
        f.write(data)
        paths.append(f.name)

print('Analyzing 5 distinct captures...')
for i, path in enumerate(paths):
    result = analyze_capture(path)
    with sc._IN_FLIGHT_RESULTS_LOCK:
        count = len(sc._IN_FLIGHT_RESULTS)
    pkts = result['total_packets'] if result else 'FAILED'
    print('  Capture {}: {} packets | in-flight: {}'.format(i, pkts, count))

print('\nFinal _IN_FLIGHT_RESULTS: {} entries'.format(len(sc._IN_FLIGHT_RESULTS)))

# Cleanup
for path in paths:
    try:
        os.unlink(path)
    except:
        pass

sc.clear_caches()
ta_module._ANALYSIS_CACHE.clear()