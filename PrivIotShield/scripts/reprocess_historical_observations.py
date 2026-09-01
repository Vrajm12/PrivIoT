import sys
import os
sys.path.insert(0, os.path.abspath("."))
import json
from app import app
from extensions import db
from models import Asset, Observation, BehavioralBaseline, RiskAssessment, Alert
from behavioral_engine import behavioral_engine
from exposure_engine import exposure_engine
from alert_engine import alert_engine

with app.app_context():
    obs_all = Observation.query.order_by(Observation.timestamp.asc()).all()
    print(f"Replaying {len(obs_all)} real historical observations through behavioral and exposure engines...")
    
    for o in obs_all:
        if not o.asset_id:
            continue
        asset = Asset.query.get(o.asset_id)
        if not asset:
            continue
        payload = json.loads(o.payload_json or '{}')
        
        # Process baseline & radio profile
        behavioral_engine.process_radio_observation(o.tenant_id, asset, payload, now=o.timestamp)
        
        # Calculate & persist PRI
        exposure_engine.calculate_and_persist_radio_pri(o.tenant_id, asset, payload, now=o.timestamp)
        
        # Check open Wi-Fi
        if payload.get('encryption_type') == 0:
            alert_engine.create_alert(
                tenant_id=o.tenant_id,
                alert_type='open_unencrypted_wifi',
                severity='high',
                title=f"Open Unencrypted Wi-Fi AP: {asset.hostname or asset.mac_address}",
                description=f"Wireless Access Point '{asset.hostname or 'Hidden'}' ({asset.mac_address}) is broadcasting cleartext unencrypted 802.11 beacons in physical airspace.",
                evidence={'bssid': asset.mac_address, 'ssid': asset.hostname, 'rssi': payload.get('rssi'), 'channel': payload.get('channel')},
                asset_id=asset.id
            )
            
    db.session.commit()
    print("Backfill complete successfully!")

    # Summary report
    baselines = BehavioralBaseline.query.all()
    risks = RiskAssessment.query.all()
    alerts = Alert.query.all()
    print(f"Total Baselines: {len(baselines)}")
    print(f"Total Risk Assessments: {len(risks)}")
    print(f"Total Alerts: {len(alerts)}")

    for a in Asset.query.limit(5).all():
        latest_risk = a.get_latest_risk()
        baseline = a.get_active_baseline()
        summary = json.loads(baseline.summary_json or '{}') if baseline else {}
        print(f"Asset #{a.id} ({a.hostname or a.mac_address}): PRI={latest_risk.pri_score if latest_risk else 'N/A'} ({latest_risk.pri_level if latest_risk else 'N/A'}) | Stage={summary.get('maturity_stage')} | RSSI Mean={summary.get('rssi_mean')} | Obs={summary.get('observation_count')}")
