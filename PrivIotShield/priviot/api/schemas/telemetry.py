"""
Telemetry Ingestion Pydantic v2 Schemas
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class TelemetryObservationItem(BaseModel):
    timestamp: Optional[str] = None
    observation_type: str = Field(..., description="network, dns, service, identity, behavior")
    src_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = "TCP"
    dns_query: Optional[str] = None
    dns_resolved_ip: Optional[str] = None
    dhcp_fingerprint: Optional[Dict[str, Any]] = None
    ssdp_payload: Optional[Dict[str, Any]] = None
    mdns_payload: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None

class TelemetryIngestBatch(BaseModel):
    collector_id: Optional[str] = None
    observations: List[TelemetryObservationItem] = Field(..., min_length=1, max_length=1000)

class TelemetryIngestResponse(BaseModel):
    success: bool
    processed_count: int
    anomalies_detected: int
    new_assets_discovered: int
    request_id: Optional[str] = None
