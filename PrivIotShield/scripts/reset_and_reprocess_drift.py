"""
PrivIoT Shield - Clean Reset & Reprocessing of Derived Behavioral Drift State
Preserves ALL raw physical ESP32 observations and assets.
Reconstructs deduplicated baselines, drift events, alerts, and PRI scores from real telemetry history.
"""
import os
import sys
import json
sys.path.insert(0, os.path.abspath("."))
from app import app
from extensions import db
from models import Observation, Asset, BehavioralBaseline, BehavioralDriftEvent, Alert, RiskAssessment
from behavioral_engine import behavioral_engine
from exposure_engine import exposure_engine

sys.stdout.reconfigure(encoding='utf-8')

with app.app_context():
    print("=== PRIVIOT SHIELD: RESETTING DERIVED DRIFT & BASELINE STATE ===")
    
    # 1. Clear derived tables (PRESERVES observations and assets)
    num_alerts_cleared = Alert.query.delete()
    num_drifts_cleared = BehavioralDriftEvent.query.delete()
    num_risks_cleared = RiskAssessment.query.delete()
    num_baselines_cleared = BehavioralBaseline.query.delete()
    db.session.commit()
    
    print(f"Cleared {num_drifts_cleared} legacy drift events, {num_alerts_cleared} legacy alerts, {num_risks_cleared} risk records.")
    
    # 2. Query all real physical ESP32 observations in chronological order
    obs_all = Observation.query.order_by(Observation.timestamp.asc()).all()
    total_obs = len(obs_all)
    print(f"Replaying {total_obs} real physical observations through updated deduplicated drift pipeline...")
    
    anomalies_count = 0
    for idx, o in enumerate(obs_all):
        if not o.asset_id:
            continue
        asset = db.session.get(Asset, o.asset_id)
        if not asset:
            continue
            
        payload = json.loads(o.payload_json or '{}')
        now = o.timestamp
        
        # Process radio observation with strict deduplication
        drift = behavioral_engine.process_radio_observation(o.tenant_id, asset, payload, now=now)
        if drift:
            anomalies_count += 1
            
        # Calculate PRI strictly from unique active drift conditions
        exposure_engine.calculate_and_persist_radio_pri(o.tenant_id, asset, payload, now=now)
        
        # Check open unencrypted AP on initial discovery
        enc = payload.get("encryption_type")
        if enc == 0:
            existing_open_alert = Alert.query.filter_by(
                tenant_id=o.tenant_id, asset_id=asset.id, alert_type="open_unencrypted_wifi", status="OPEN"
            ).first()
            if not existing_open_alert:
                alert = Alert(
                    tenant_id=o.tenant_id,
                    asset_id=asset.id,
                    alert_type="open_unencrypted_wifi",
                    severity="high",
                    title=f"Open Unencrypted Wi-Fi AP: {asset.hostname or asset.mac_address}",
                    description=f"Wireless Access Point '{asset.hostname or 'Hidden'}' ({asset.mac_address}) is broadcasting cleartext unencrypted 802.11 beacons.",
                    evidence_json=json.dumps({
                        "bssid": asset.mac_address,
                        "ssid": asset.hostname,
                        "rssi": payload.get("rssi"),
                        "channel": payload.get("channel"),
                        "encryption_type": 0
                    }),
                    status="OPEN",
                    created_at=now
                )
                db.session.add(alert)
                
    db.session.commit()
    
    # 3. Report Post-Clean State
    print("\n=== POST-RESET CLEAN STATE SUMMARY ===")
    total_drifts = BehavioralDriftEvent.query.count()
    total_alerts = Alert.query.count()
    total_baselines = BehavioralBaseline.query.count()
    total_risks = RiskAssessment.query.count()
    
    print(f"Total Unique Drift Events: {total_drifts} (NO DUPLICATES)")
    print(f"Total Unique Threat Alerts: {total_alerts}")
    print(f"Total Active Baselines: {total_baselines}")
    
    print("\n=== ASSET #1 (Veeru_Hotspot_Live) VERIFICATION ===")
    a1 = db.session.get(Asset, 1)
    if a1:
        a1_drifts = BehavioralDriftEvent.query.filter_by(asset_id=1).all()
        print(f"Asset #1 Open Drift Events Count: {len(a1_drifts)}")
        for d in a1_drifts:
            ev = json.loads(d.evidence_json or '{}')
            print(f"  - [{d.drift_type}] Status: {d.status} | Occurrences Tracked: {ev.get('occurrence_count', 1)} | First: {ev.get('first_observed')} | Last: {ev.get('last_observed')}")
            
        a1_risk = a1.get_latest_risk()
        if a1_risk:
            print(f"Asset #1 PRI Score: {a1_risk.pri_score} / 10.0 ({a1_risk.pri_level})")
            print(f"Asset #1 Risk Breakdown: {a1_risk.to_dict().get('breakdown')}")
