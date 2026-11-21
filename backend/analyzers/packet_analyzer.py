"""Basic offline packet analyser for the NetWatch project.

Reads a PCAP capture file and returns structured packet data
that can be consumed by the FastAPI backend.

Processes IPv4 and ARP packets. Non-IP/non-ARP packets are handled safely.
"""

import os
from collections import deque
from datetime import datetime, timezone

from scapy.all import PcapNgReader, IP, TCP, UDP, ICMP, ARP, DNS

# Resolve the capture path relative to this file's location so the script
# works regardless of the current working directory.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_PATH = os.path.join(BASE_DIR, "captures", "sample.pcapng")

MAX_PACKET_LIMIT = 500
DEFAULT_PACKET_LIMIT = 100


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

    # Use deque with maxlen to keep only the most recent packets in capture order.
    # This ensures memory usage is bounded by the limit.
    recent_packets = deque(maxlen=limit)
    reader = None

    try:
        reader = PcapNgReader(pcap_path)

        for index, packet in enumerate(reader):
            # Process IPv4 and ARP packets. Other link-layer frames are skipped safely.
            if not packet.haslayer(IP) and not packet.haslayer(ARP):
                continue

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

            recent_packets.append({
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
            })

    except Exception:
        return None
    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    return list(recent_packets)


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
