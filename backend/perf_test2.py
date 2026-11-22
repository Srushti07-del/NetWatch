import time
import os
import sys
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath('.')))
from analyzers.packet_analyzer import analyze_packets, _PACKET_CACHE, _PACKET_CACHE_LOCK, _SCAN_EVENTS, _SCAN_EVENTS_LOCK

PCAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captures', 'sample.pcapng')

def _clear_caches():
    with _PACKET_CACHE_LOCK:
        _PACKET_CACHE.clear()
    with _SCAN_EVENTS_LOCK:
        _SCAN_EVENTS.clear()

# Test concurrent scans for DIFFERENT files (should run in parallel)
# Create a copy of the sample file
import shutil
PCAP_PATH2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captures', 'sample_copy.pcapng')
shutil.copy2(PCAP_PATH, PCAP_PATH2)

_clear_caches()

barrier = threading.Barrier(2)
results = [None, None]
start_times = [None, None]
end_times = [None, None]

def worker1():
    barrier.wait()
    start_times[0] = time.perf_counter()
    results[0] = analyze_packets(PCAP_PATH, limit=100)
    end_times[0] = time.perf_counter()

def worker2():
    barrier.wait()
    start_times[1] = time.perf_counter()
    results[1] = analyze_packets(PCAP_PATH2, limit=100)
    end_times[1] = time.perf_counter()

t1 = threading.Thread(target=worker1)
t2 = threading.Thread(target=worker2)
concurrent_start = time.perf_counter()
t1.start()
t2.start()
t1.join()
t2.join()
concurrent_total = time.perf_counter() - concurrent_start

print(f'Concurrent different files: total={concurrent_total*1000:.2f}ms')
print(f'Thread 1: {(end_times[0]-start_times[0])*1000:.2f}ms')
print(f'Thread 2: {(end_times[1]-start_times[1])*1000:.2f}ms')
print(f'Overlap: {min(end_times[0], end_times[1]) - max(start_times[0], start_times[1]):.4f}s')
print(f'Cache entries: {len(_PACKET_CACHE)}')
print(f'Both succeeded: {results[0] is not None and results[1] is not None}')

# Cleanup
os.unlink(PCAP_PATH2)