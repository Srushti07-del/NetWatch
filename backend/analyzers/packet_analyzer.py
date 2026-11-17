"""Basic offline packet analyser for the NetWatch project.

Reads a PCAP capture file and reports:
  - total number of packets processed
  - protocol distribution (TCP, UDP, ICMP, other)
  - top five source IP addresses

Packets without an IPv4 layer are handled safely.
"""

import os
from collections import Counter

from scapy.all import rdpcap, IP, TCP, UDP, ICMP

# Resolve the capture path relative to this file's location so the script
# works regardless of the current working directory.
# File: backend/analyzers/packet_analyzer.py
# Capture: backend/captures/sample.pcapng
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_PATH = os.path.join(BASE_DIR, "captures", "sample.pcapng")


def analyze_packets(pcap_path):
    """Analyse packets in a PCAP file and print a summary report."""
    # Check whether the capture file exists before attempting to read it.
    if not os.path.exists(pcap_path):
        print("Error: PCAP file not found at '{}'".format(pcap_path))
        return

    # Read all packets from the capture file.
    try:
        packets = rdpcap(pcap_path)
    except Exception as exc:  # pragma: no cover - defensive file handling
        print("Error: failed to read PCAP file '{}': {}".format(pcap_path, exc))
        return

    # Handle an empty capture gracefully.
    if len(packets) == 0:
        print("The capture file '{}' is empty.".format(pcap_path))
        return

    # Counters for protocol distribution and source IP occurrences.
    protocol_counter = Counter()
    src_ip_counter = Counter()

    total_processed = 0

    for packet in packets:
        # Only process packets that contain an IPv4 layer.
        # Packets without IPv4 (e.g. ARP) are skipped safely.
        if not packet.haslayer(IP):
            continue

        total_processed += 1

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Count the source IP address occurrence.
        src_ip_counter[src_ip] += 1

        # Identify the transport protocol and extract ports when available.
        if packet.haslayer(TCP):
            protocol_counter["TCP"] += 1
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            print(
                "TCP  {}:{} -> {}:{}".format(src_ip, src_port, dst_ip, dst_port)
            )
        elif packet.haslayer(UDP):
            protocol_counter["UDP"] += 1
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            print(
                "UDP  {}:{} -> {}:{}".format(src_ip, src_port, dst_ip, dst_port)
            )
        elif packet.haslayer(ICMP):
            protocol_counter["ICMP"] += 1
            print("ICMP {} -> {}".format(src_ip, dst_ip))
        else:
            # IPv4 packet using another protocol (e.g. IGMP, OSPF).
            protocol_counter["Other"] += 1
            print("Other {} -> {}".format(src_ip, dst_ip))

    # Display the summary report.
    print("\n=== Packet Analyser Report ===")
    print("File: {}".format(pcap_path))
    print("Total packets processed: {}".format(total_processed))

    print("\nProtocol distribution:")
    if protocol_counter:
        for protocol, count in protocol_counter.most_common():
            print("  {}: {}".format(protocol, count))
    else:
        print("  None")

    print("\nTop five source IP addresses:")
    if src_ip_counter:
        for src_ip, count in src_ip_counter.most_common(5):
            print("  {}: {} packets".format(src_ip, count))
    else:
        print("  None")


def main():
    """Entry point: run the analyser against the default capture file."""
    analyze_packets(PCAP_PATH)


if __name__ == "__main__":
    main()
