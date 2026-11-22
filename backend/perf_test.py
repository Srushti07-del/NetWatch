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

# Clear cache
_clear_caches()

# Cold cache measurement
start = time.perf_counter()
result = analyze_packets(PCAP_PATH, limit=100)
cold_time = time.perf_counter() - start
print(f'Cold cache: {cold_time*1000:.2f}ms, {len(result)} packets')

# Warm cache measurement (run multiple times)
times = []
for i in range(5):
    start = time.perf_counter()
    result = analyze_packets(PCAP_PATH, limit=100)
    times.append(time.perf_counter() - start)

avg_warm = sum(times) / len(times) * 1000
print(f'Warm cache (avg of 5): {avg_warm:.2f}ms, {len(result)} packets')
print(f'Warm times: {[f"{t*1000:.2f}ms" for t in times]}')

# Concurrent cold cache test - multiple threads requesting same uncached file
import threading
_clear_caches()

barrier = threading.Barrier(5)
results = [None] * 5
start_times = [None] * 5
end_times = [None] * 5

def worker(idx):
    barrier.wait()
    start_times[idx] = time.perf_counter()
    results[idx] = analyze_packets(PCAP_PATH, limit=100)
    end_times[idx] = time.perf_counter()

threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
concurrent_start = time.perf_counter()
for t in threads:
    t.start()
for t in threads:
    t.join()
concurrent_total = time.perf_counter() - concurrent_start

print(f'Concurrent cold (5 threads): total={concurrent_total*1000:.2f}ms')
individual_times = [(end_times[i]-start_times[i])*1000 for i in range(5)]
print(f'Individual times: {[f"{t:.2f}ms" for t in individual_times]}')
print(f'All results identical: {all(len(r) == 100 for r in results)}')
print(f'Cache entries after concurrent: {len(_PACKET_CACHE)}')