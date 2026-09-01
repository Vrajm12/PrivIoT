"""
Safe Database Migration & Cleanup: Remove ONLY the 5 mock/pilot asset records.
Preserve all real ESP32-discovered hardware assets and collector infrastructure.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from extensions import db
from models import (
    Asset, Observation, Alert, BehavioralBaseline,
    ContainmentIntent, RiskAssessment, AssetService
)

PILOT_MOCK_MACS = [
    "00:12:17:88:41:A2",  # Hikvision DS-2CD2042WD-I
    "50:C7:BF:12:34:56",  # TP-Link Kasa HS100
    "CC:6E:A4:91:02:11",  # Samsung QN65Q80B
    "00:1E:0B:44:99:AA",  # HP LaserJet Enterprise M608
    "94:E6:86:99:88:77"   # Generic Espressif ESP32 Board
]

with app.app_context():
    deleted_count = 0
    for mac in PILOT_MOCK_MACS:
        assets = Asset.query.filter_by(mac_address=mac).all()
        for a in assets:
            print(f"[*] Removing Mock Asset: ID={a.id}, MAC={a.mac_address}, Vendor={a.vendor}, Model={a.model}")
            
            # Clean dependent records safely
            try:
                Observation.query.filter_by(asset_id=a.id).delete()
                Alert.query.filter_by(asset_id=a.id).delete()
                BehavioralBaseline.query.filter_by(asset_id=a.id).delete()
                ContainmentIntent.query.filter_by(asset_id=a.id).delete()
                RiskAssessment.query.filter_by(asset_id=a.id).delete()
                AssetService.query.filter_by(asset_id=a.id).delete()
            except Exception as ex:
                print(f"    Note during dependent cleanup: {ex}")
            
            db.session.delete(a)
            deleted_count += 1
            
    db.session.commit()
    print(f"\n[PASS] Successfully deleted {deleted_count} mock/pilot asset records.")
    
    # Audit remaining canonical Asset records
    remaining = Asset.query.all()
    print(f"\n--- CANONICAL REAL ASSET INVENTORY (Count: {len(remaining)}) ---")
    for r in remaining:
        print(f"ID={r.id} | MAC={r.mac_address} | Hostname={r.hostname} | Vendor={r.vendor} | Source={r.discovery_source} | Tenant={r.tenant_id}")
