import io
import csv
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from app import app as flask_app
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User, Asset, Observation, BehavioralBaseline
from priviot.api.schemas.assets import AssetResponse, AssetListResponse, TrustProfileResponse

router = APIRouter(prefix="/api/v2/assets", tags=["Asset Inventory & Trust Profiles"])

@router.get("/export/csv", summary="Export Real Discovered Assets to Highly-Formatted Excel CSV")
def export_assets_csv(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Generate an RFC-4180 compliant, UTF-8 BOM formatted Excel CSV spreadsheet
    containing all canonical hardware and sensor assets for the tenant.
    """
    with flask_app.app_context():
        assets = Asset.query.filter_by(tenant_id=tenant_id).order_by(Asset.last_seen.desc().nullslast()).all()
        
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        
        writer.writerow(["PRIVIOT SHIELD — CANONICAL HARDWARE & SENSOR ASSET INVENTORY"])
        writer.writerow(["Generated At", datetime.utcnow().isoformat() + "Z"])
        writer.writerow(["Tenant Scope", tenant_id])
        writer.writerow(["Total Monitored Endpoints", len(assets)])
        writer.writerow(["Authoritative Sensor", "Physical ESP32 Wi-Fi/BLE Airspace Scanner"])
        writer.writerow([])
        
        writer.writerow([
            "Asset ID",
            "MAC / BSSID Address",
            "SSID / Hostname",
            "IP Address",
            "Network Scope",
            "Hardware Vendor (OUI)",
            "Model",
            "Device Category",
            "Discovery Source",
            "Sensor Provenance",
            "Reconciliation Method",
            "Identity Confidence (%)",
            "PRI-v2 Risk Score",
            "PRI Risk Level",
            "Behavioral State",
            "Maturity Stage",
            "First Seen",
            "Last Seen"
        ])
        
        for a in assets:
            is_esp32 = (
                a.discovery_source in ("esp32_wifi_scan", "esp32_ble_scan") or
                getattr(a, "reconciliation_method", "") in ("esp32_hardware_scanner", "esp32_ble_scanner")
            )
            risk = a.get_latest_risk()
            baseline = a.get_active_baseline()
            summary = json.loads(baseline.summary_json or '{}') if baseline else {}
            
            writer.writerow([
                a.id,
                a.mac_address,
                a.hostname or ("Discovered Wireless Beacon" if is_esp32 else "Unlabeled"),
                a.ip_address,
                "L2 Airspace AP" if a.ip_address == "0.0.0.0" else a.network_scope,
                a.vendor or "Unknown Vendor",
                a.model or "Unknown Model",
                a.device_type or "Wireless Access Point",
                a.discovery_source or "esp32_wifi_scan",
                "REAL PHYSICAL SENSOR" if is_esp32 else "SYSTEM",
                getattr(a, "reconciliation_method", "mac_address") or "mac_address",
                round((a.identity_confidence or 0.35) * 100),
                f"{risk.pri_score:.1f}" if risk else "2.0",
                (risk.pri_level if risk else "low").upper(),
                baseline.status if baseline else "STABLE",
                summary.get("maturity_stage", "PRELIMINARY"),
                a.first_seen.isoformat() if a.first_seen else "N/A",
                a.last_seen.isoformat() if a.last_seen else "N/A"
            ])
            
        csv_bytes = output.getvalue().encode("utf-8")
        filename = f"priviot_inventory_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "text/csv; charset=utf-8"
            }
        )

@router.get("", response_model=AssetListResponse, summary="List Multi-Tenant Assets")
def list_assets(
    severity: Optional[str] = None,
    drift: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        query = Asset.query.filter_by(tenant_id=tenant_id)

        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (Asset.ip_address.ilike(search_pattern)) |
                (Asset.mac_address.ilike(search_pattern)) |
                (Asset.vendor.ilike(search_pattern)) |
                (Asset.model.ilike(search_pattern)) |
                (Asset.hostname.ilike(search_pattern))
            )

        total_count = query.count()
        items = query.order_by(Asset.last_seen.desc().nullslast()).offset(offset).limit(limit).all()

        result_items = []
        for a in items:
            baseline = a.get_active_baseline()
            summary = json.loads(baseline.summary_json or '{}') if baseline else {}
            latest_risk = a.get_latest_risk()

            obs_count = Observation.query.filter_by(tenant_id=tenant_id, asset_id=a.id).count()
            latest_obs = Observation.query.filter_by(tenant_id=tenant_id, asset_id=a.id).order_by(Observation.timestamp.desc()).first()
            payload = json.loads(latest_obs.payload_json or '{}') if latest_obs else {}

            resp = AssetResponse(
                id=a.id,
                tenant_id=a.tenant_id,
                ip_address=a.ip_address,
                mac_address=a.mac_address,
                hostname=a.hostname,
                vendor=a.vendor or "Unknown",
                model=a.model or "Unknown",
                device_type=a.device_type or "Unknown IoT",
                firmware_version=a.firmware_version,
                identity_confidence=a.identity_confidence or 0.5,
                discovery_source=getattr(a, "discovery_source", "esp32_wifi_scan") or "esp32_wifi_scan",
                reconciliation_method=getattr(a, "reconciliation_method", "esp32_hardware_scanner") or "esp32_hardware_scanner",
                network_scope=a.network_scope or "Physical 2.4GHz Airspace",
                is_managed=getattr(a, "is_managed", a.lifecycle_status == "active"),
                current_pri_score=latest_risk.pri_score if latest_risk else 2.0,
                pri_risk_level=latest_risk.pri_level if latest_risk else "low",
                behavioral_state=baseline.status if baseline else "LEARNING",
                active_containment_state=a.get_active_containment().status if a.get_active_containment() else "UNCONTAINED",
                first_seen=a.first_seen,
                last_seen=a.last_seen,
                rssi=payload.get("rssi", summary.get("rssi_current")),
                channel=payload.get("channel", summary.get("primary_channel")),
                observation_count=obs_count,
                proximity_zone=summary.get("proximity_zone", "NEAR_RANGE"),
                maturity_stage=summary.get("maturity_stage", "PRELIMINARY"),
                maturity_confidence=summary.get("maturity_confidence", 0.55),
                evidence_window=summary.get("evidence_window", "0.0 minutes")
            )
            result_items.append(resp)

        return AssetListResponse(items=result_items, total_count=total_count)

@router.get("/{asset_id}", response_model=AssetResponse, summary="Get Asset Details")
def get_asset(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset with ID {asset_id} not found in tenant scope."
            )

        baseline = asset.get_active_baseline()
        summary = json.loads(baseline.summary_json or '{}') if baseline else {}
        latest_risk = asset.get_latest_risk()

        obs_count = Observation.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).count()
        latest_obs = Observation.query.filter_by(tenant_id=tenant_id, asset_id=asset.id).order_by(Observation.timestamp.desc()).first()
        payload = json.loads(latest_obs.payload_json or '{}') if latest_obs else {}

        return AssetResponse(
            id=asset.id,
            tenant_id=asset.tenant_id,
            ip_address=asset.ip_address,
            mac_address=asset.mac_address,
            hostname=asset.hostname,
            vendor=asset.vendor or "Unknown",
            model=asset.model or "Unknown",
            device_type=asset.device_type or "Unknown IoT",
            firmware_version=asset.firmware_version,
            identity_confidence=asset.identity_confidence or 0.5,
            discovery_source=getattr(asset, "discovery_source", "esp32_wifi_scan") or "esp32_wifi_scan",
            reconciliation_method=getattr(asset, "reconciliation_method", "esp32_hardware_scanner") or "esp32_hardware_scanner",
            network_scope=asset.network_scope or "Physical 2.4GHz Airspace",
            is_managed=getattr(asset, "is_managed", asset.lifecycle_status == "active"),
            current_pri_score=latest_risk.pri_score if latest_risk else 2.0,
            pri_risk_level=latest_risk.pri_level if latest_risk else "low",
            behavioral_state=baseline.status if baseline else "LEARNING",
            active_containment_state=asset.get_active_containment().status if asset.get_active_containment() else "UNCONTAINED",
            first_seen=asset.first_seen,
            last_seen=asset.last_seen,
            rssi=payload.get("rssi", summary.get("rssi_current")),
            channel=payload.get("channel", summary.get("primary_channel")),
            observation_count=obs_count,
            proximity_zone=summary.get("proximity_zone", "NEAR_RANGE"),
            maturity_stage=summary.get("maturity_stage", "PRELIMINARY"),
            maturity_confidence=summary.get("maturity_confidence", 0.55),
            evidence_window=summary.get("evidence_window", "0.0 minutes")
        )

@router.get("/{asset_id}/signal-history", summary="Get Historical Signal & Presence Observations")
def get_signal_history(
    asset_id: int,
    limit: int = Query(50, ge=5, le=200),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Returns time-series signal strength (RSSI), channel, and presence observations for the asset.
    """
    with flask_app.app_context():
        asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset with ID {asset_id} not found."
            )

        observations = Observation.query.filter_by(
            tenant_id=tenant_id,
            asset_id=asset.id
        ).order_by(Observation.timestamp.desc()).limit(limit).all()

        history = []
        for o in reversed(observations):
            payload = json.loads(o.payload_json or '{}')
            history.append({
                "timestamp": o.timestamp.isoformat() if o.timestamp else None,
                "rssi": payload.get("rssi"),
                "channel": payload.get("channel"),
                "ssid": payload.get("ssid") or asset.hostname,
                "encryption_type": payload.get("encryption_type")
            })

        return {
            "asset_id": asset.id,
            "mac_address": asset.mac_address,
            "total_points": len(history),
            "history": history
        }

@router.get("/{asset_id}/radio-fingerprint", summary="Get Complete 20-Dimensional Radio Fingerprint & Baseline Similarity")
def get_radio_fingerprint(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset {asset_id} not found in tenant scope."
            )

        baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id, tenant_id=tenant_id).first()
        summary = json.loads(baseline.summary_json or '{}') if baseline else {}
        fingerprint = summary.get("radio_fingerprint") or {}
        similarity = summary.get("similarity") or {}
        trajectory = summary.get("trajectory") or {}

        return {
            "asset_id": asset.id,
            "bssid": asset.mac_address,
            "ssid": asset.hostname or fingerprint.get("ssid", "Unknown"),
            "fingerprint": fingerprint,
            "similarity": similarity,
            "trajectory": trajectory,
            "maturity_stage": summary.get("maturity_stage", "PRELIMINARY"),
            "maturity_confidence": summary.get("maturity_confidence", 0.35),
            "evidence_window": summary.get("evidence_window", "0.0 minutes")
        }

@router.get("/{asset_id}/proximity", summary="Get Calibrated Relative Proximity Score & Zone")
def get_proximity(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset {asset_id} not found in tenant scope."
            )

        baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id, tenant_id=tenant_id).first()
        summary = json.loads(baseline.summary_json or '{}') if baseline else {}
        fp = summary.get("radio_fingerprint", {})

        return {
            "asset_id": asset.id,
            "bssid": asset.mac_address,
            "proximity_score": fp.get("proximity_score", summary.get("proximity_score", 50)),
            "proximity_state": fp.get("proximity_state", summary.get("proximity_zone", "NEAR_RANGE")),
            "rssi_ema": fp.get("rssi_ema", summary.get("rssi_ema", -60.0)),
            "rssi_current": summary.get("rssi_current"),
            "rssi_mean": summary.get("rssi_mean"),
            "confidence": summary.get("maturity_confidence", 0.50),
            "scale": "0 (Very Far / -100 dBm) to 100 (Immediate / -20 dBm)",
            "interpretation": "Relative radio proximity estimate from single ESP32 sensor. No geographic coordinates inferred."
        }

@router.get("/{asset_id}/movement", summary="Get Trajectory Slope & Movement State")
def get_movement(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset {asset_id} not found in tenant scope."
            )

        baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id, tenant_id=tenant_id).first()
        summary = json.loads(baseline.summary_json or '{}') if baseline else {}
        trajectory = summary.get("trajectory", {})

        return {
            "asset_id": asset.id,
            "bssid": asset.mac_address,
            "movement_state": trajectory.get("movement_state", summary.get("movement_state", "UNKNOWN")),
            "trend": trajectory.get("trend", summary.get("proximity_trend", "STABLE")),
            "slope_db_per_sec": trajectory.get("slope_db_per_sec", 0.0),
            "directional_consistency": trajectory.get("directional_consistency", 0.0),
            "window_points": trajectory.get("window_points", 0),
            "confidence": trajectory.get("confidence", 0.50),
            "description": trajectory.get("description", "Stationary / stable proximity.")
        }

@router.get("/{asset_id}/trust-profile", response_model=TrustProfileResponse, summary="Get Flagship Device Trust Profile")
def get_asset_trust_profile(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(get_current_tenant)
):
    with flask_app.app_context():
        asset = Asset.query.filter_by(id=asset_id, tenant_id=tenant_id).first()
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Asset with ID {asset_id} not found in tenant scope."
            )

        profile = asset.get_trust_profile()
        return TrustProfileResponse(
            asset_id=asset.id,
            tenant_id=asset.tenant_id,
            profile=profile
        )
