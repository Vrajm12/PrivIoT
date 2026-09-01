"""
Comprehensive Live FastAPI Verification for the exact ESP32 Wi-Fi Scanner payloads.
"""
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from priviot.api.fastapi_app import app as fastapi_app
from starlette.testclient import TestClient
from models import Collector, Asset, Observation
from collector_manager import collector_manager
from priviot.engines.telemetry import telemetry_engine

client = TestClient(fastapi_app, raise_server_exceptions=True)

with app.app_context():
    # 1. Provision / Retrieve Active Token
    collector = Collector.query.filter_by(name="ESP32_Hardware_Scanner", tenant_id="default_tenant").first()
    if not collector:
        collector, raw_token = collector_manager.enroll_collector(
            tenant_id="default_tenant",
            site_id="default_site",
            name="ESP32_Hardware_Scanner",
            collector_type="wifi_scanner",
            network_scope="2.4GHz Wi-Fi / BLE Airspace"
        )
    else:
        collector, raw_token = collector_manager.rotate_token(
            collector_id=collector.id,
            tenant_id="default_tenant"
        )
    collector.status = "ACTIVE"
    from extensions import db
    db.session.commit()
    token = raw_token
    print(f"[*] Active Provisioned Sensor Token: {token}")

# 2. Test Exact ESP32 Payload (Single Wi-Fi Scan Observation)
exact_esp32_payload = {
    "collector_id": "ESP32_Hardware_Scanner",
    "observations": [
        {
            "observation_type": "wifi_scan",
            "src_mac": "E6:1F:D5:42:7A:6B",
            "src_ip": "0.0.0.0",
            "payload": {
                "ssid": "Veeru",
                "bssid": "E6:1F:D5:42:7A:6B",
                "rssi": -48,
                "channel": 6,
                "encryption_type": 4,
                "auto_discover": True
            }
        }
    ]
}

headers = {
    "X-Sensor-Token": token,
    "X-Tenant-ID": "default_tenant",
    "Content-Type": "application/json"
}

res1 = client.post("/api/v2/telemetry/ingest", headers=headers, json=exact_esp32_payload)
print(f"[+] Exact ESP32 Payload Test: Status={res1.status_code}")
print("    Response Body:", res1.json())
assert res1.status_code == 200
assert res1.json()["success"] is True
assert res1.json()["processed_count"] == 1

# 3. Test Multi-Observation Wi-Fi Batch (Realistic 5-network scan)
multi_esp32_payload = {
    "collector_id": "ESP32_Hardware_Scanner",
    "observations": [
        {
            "observation_type": "wifi_scan",
            "src_mac": "E6:1F:D5:42:7A:6B",
            "src_ip": "0.0.0.0",
            "payload": {
                "ssid": "Veeru",
                "bssid": "E6:1F:D5:42:7A:6B",
                "rssi": -45,
                "channel": 6,
                "encryption_type": 4,
                "auto_discover": True
            }
        },
        {
            "observation_type": "wifi_scan",
            "src_mac": "50:C7:BF:33:44:55",
            "src_ip": "0.0.0.0",
            "payload": {
                "ssid": "TP-Link_SmartPlug_99",
                "bssid": "50:C7:BF:33:44:55",
                "rssi": -62,
                "channel": 1,
                "encryption_type": 3,
                "auto_discover": True
            }
        },
        {
            "observation_type": "wifi_scan",
            "src_mac": "00:14:22:11:22:33",
            "src_ip": "0.0.0.0",
            "payload": {
                "ssid": "<hidden>",
                "bssid": "00:14:22:11:22:33",
                "rssi": -78,
                "channel": 11,
                "encryption_type": 5,
                "auto_discover": True
            }
        }
    ]
}

res2 = client.post("/api/v2/telemetry/ingest", headers=headers, json=multi_esp32_payload)
print(f"[+] Multi-Network Batch Test: Status={res2.status_code}")
print("    Response Body:", res2.json())
assert res2.status_code == 200
assert res2.json()["success"] is True
assert res2.json()["processed_count"] == 3

# 4. Verify Tenant Spoofing Rejected (403)
headers_spoof = {
    "X-Sensor-Token": token,
    "X-Tenant-ID": "unauthorized_tenant_xyz",
    "Content-Type": "application/json"
}
res3 = client.post("/api/v2/telemetry/ingest", headers=headers_spoof, json=exact_esp32_payload)
print(f"[+] Tenant Isolation Check: Status={res3.status_code} (Expected 403)")
assert res3.status_code == 403

# 5. Verify Database Records
with app.app_context():
    veeru_asset = Asset.query.filter_by(mac_address="E6:1F:D5:42:7A:6B", tenant_id="default_tenant").first()
    assert veeru_asset is not None
    assert veeru_asset.hostname == "Veeru"
    assert veeru_asset.discovery_source == "esp32_wifi_scan"
    print(f"[PASS] Database Asset Verified: ID={veeru_asset.id}, MAC={veeru_asset.mac_address}, SSID={veeru_asset.hostname}, Source={veeru_asset.discovery_source}")

print("\n========================================================")
print("[PASS] ALL LIVE ESP32 TELEMETRY INGESTION TESTS PASSED!")
print("========================================================\n")
