"""
FastAPI Continuous Telemetry Ingestion Router
"""
from fastapi import APIRouter, Depends, HTTPException, status, Header
from extensions import db
from priviot.api.dependencies import get_authenticated_collector, get_current_tenant
from priviot.data.models import Collector
from priviot.engines.telemetry import telemetry_engine
from priviot.api.schemas.telemetry import TelemetryIngestBatch, TelemetryIngestResponse

router = APIRouter(prefix="/api/v2/telemetry", tags=["Telemetry Ingestion"])

@router.post("/ingest", response_model=TelemetryIngestResponse, summary="Ingest Raw Edge Telemetry Batch")
def ingest_telemetry(
    batch: TelemetryIngestBatch,
    collector: Collector = Depends(get_authenticated_collector),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Continuous passive and active observation ingestion endpoint for authenticated edge collectors.
    """
    raw_obs_list = [obs.model_dump() for obs in batch.observations]

    # Delegate to domain telemetry engine (No duplicated business logic!)
    try:
        res = telemetry_engine.ingest_telemetry_batch(
            collector=collector,
            raw_events=raw_obs_list
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )

    if res.get("status") != "success":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=res.get("error", "Telemetry ingestion failed.")
        )

    return TelemetryIngestResponse(
        success=True,
        processed_count=res.get("total_ingested", len(raw_obs_list)),
        anomalies_detected=res.get("anomalies_detected", 0),
        new_assets_discovered=res.get("correlated_assets", 0)
    )
