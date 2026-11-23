"""Basic offline packet analyser for the NetWatch project.

Reads a PCAP capture file and returns structured packet data
that can be consumed by the FastAPI backend.

Processes IPv4 and ARP packets. Non-IP/non-ARP packets are handled safely.
"""

import os
from datetime import datetime, timezone

from .shared_capture import (
    get_parsed_capture,
    clear_caches,
    PacketRecord,
    ParsedCapture,
)

# Resolve the capture path relative to this file's location so the script
# works regardless of the current working directory.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_PATH = os.path.join(BASE_DIR, "captures", "sample.pcapng")

MAX_PACKET_LIMIT = 500
DEFAULT_PACKET_LIMIT = 100


def _packet_record_to_dict(pkt: PacketRecord) -> dict:
    """Convert internal PacketRecord to the public packet dictionary format."""
    return {
        "id": str(pkt.index),
        "timestamp": pkt.timestamp_iso,
        "sourceIp": pkt.source_ip,
        "destinationIp": pkt.destination_ip,
        "sourcePort": pkt.source_port,
        "destinationPort": pkt.destination_port,
        "protocol": pkt.protocol,
        "packetSize": pkt.packet_size,
        "status": "monitored",
        "ttl": pkt.ttl,
    }


def analyze_packets(pcap_path: str, limit: int = DEFAULT_PACKET_LIMIT):
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

    # Get parsed capture from shared cache (handles parsing, caching, synchronization)
    capture = get_parsed_capture(pcap_path)
    if capture is None:
        return None

    # Return the newest N packets (last N in capture order) as deep copies
    return [_packet_record_to_dict(pkt) for pkt in capture.packets[-limit:]]


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