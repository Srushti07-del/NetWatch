"""NetWatch FastAPI backend.

Exposes packet capture data through a REST API for the frontend dashboard.
"""

import os
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from analyzers.packet_analyzer import analyze_packets, MAX_PACKET_LIMIT, DEFAULT_PACKET_LIMIT
from analyzers.traffic_analyzer import get_dashboard_metrics, get_traffic_data, get_protocol_distribution

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH = os.path.join(BACKEND_DIR, "captures", "sample.pcapng")

app = FastAPI(title="NetWatch API", version="1.0.0")

# Configure CORS for local Vite development origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/api/packets")
async def get_packets(
    limit: int = Query(default=DEFAULT_PACKET_LIMIT, ge=1, le=MAX_PACKET_LIMIT)
):
    """Return packets from the sample capture file."""
    # Check if the capture file exists before attempting to read it.
    if not os.path.exists(PCAP_PATH):
        raise HTTPException(status_code=404, detail="Capture file not found")

    packets = analyze_packets(PCAP_PATH, limit=limit)
    if packets is None:
        raise HTTPException(status_code=500, detail="Failed to read capture file")
    return packets


@app.get("/api/dashboard/metrics")
async def get_dashboard_metrics_endpoint():
    """Return dashboard metrics from the capture analysis."""
    if not os.path.exists(PCAP_PATH):
        raise HTTPException(status_code=404, detail="Capture file not found")

    metrics = get_dashboard_metrics(PCAP_PATH)
    if metrics is None:
        raise HTTPException(status_code=500, detail="Failed to analyze capture file")
    return metrics


@app.get("/api/traffic")
async def get_traffic_endpoint():
    """Return traffic time series data from the capture."""
    if not os.path.exists(PCAP_PATH):
        raise HTTPException(status_code=404, detail="Capture file not found")

    traffic = get_traffic_data(PCAP_PATH)
    if traffic is None:
        raise HTTPException(status_code=500, detail="Failed to analyze capture file")
    return traffic


@app.get("/api/protocols")
async def get_protocols_endpoint():
    """Return protocol distribution from the capture."""
    if not os.path.exists(PCAP_PATH):
        raise HTTPException(status_code=404, detail="Capture file not found")

    protocols = get_protocol_distribution(PCAP_PATH)
    if protocols is None:
        raise HTTPException(status_code=500, detail="Failed to analyze capture file")
    return protocols