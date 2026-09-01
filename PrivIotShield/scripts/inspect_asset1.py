import os
import sys
import json
sys.path.insert(0, os.path.abspath("."))
from app import app
from models import Observation, Asset, BehavioralBaseline, BehavioralDriftEvent, Alert

sys.stdout.reconfigure(encoding='utf-8')
with app.app_context():
    obs1 = Observation.query.filter_by(asset_id=1).order_by(Observation.timestamp.desc()).limit(20).all()
    print("=== RECENT 20 OBSERVATIONS FOR ASSET #1 ===")
    for o in reversed(obs1):
        p = json.loads(o.payload_json or '{}')
        print(f"{o.timestamp} | SSID: {p.get('ssid')} | Ch: {p.get('channel')} | RSSI: {p.get('rssi')} dBm | Enc: {p.get('encryption_type')}")
        
    b1 = BehavioralBaseline.query.filter_by(asset_id=1).first()
    if b1:
        s = json.loads(b1.summary_json or '{}')
        print("\n=== BASELINE SUMMARY FOR ASSET #1 ===")
        print(f"Status: {b1.status}")
        print(f"Primary SSID: {s.get('primary_ssid')}")
        print(f"Primary Channel: {s.get('primary_channel')}")
        print(f"Obs Count: {s.get('observation_count')}")
        print(f"Maturity: {s.get('maturity_stage')}")
        print(f"RSSI Current/Mean/Std: {s.get('rssi_current')}/{s.get('rssi_mean')}/{s.get('rssi_std_dev')}")
        
    drifts = BehavioralDriftEvent.query.filter_by(asset_id=1).all()
    print(f"\n=== DRIFT EVENTS FOR ASSET #1 ({len(drifts)}) ===")
    for d in drifts:
        ev = json.loads(d.evidence_json or '{}')
        print(f"Drift #{d.id} | Type: {d.drift_type} | Status: {d.status} | Occurrences: {ev.get('occurrence_count')} | Diff: {d.difference_description} | First: {ev.get('first_observed')} | Last: {ev.get('last_observed')}")
