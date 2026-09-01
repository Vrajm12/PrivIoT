"""
Reproduce the exact ESP32 request and capture the full traceback of the HTTP 500.
"""
import sys
import os
import traceback
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from priviot.api.fastapi_app import app as fastapi_app
from starlette.testclient import TestClient
from models import Collector
from priviot.engines.telemetry import hash_sensor_token

with app.app_context():
    collector = Collector.query.filter_by(name="ESP32_Hardware_Scanner").first()
    if not collector:
        from collector_manager import collector_manager
        collector, raw_token = collector_manager.enroll_collector(
            tenant_id="default_tenant",
            site_id="default_site",
            name="ESP32_Hardware_Scanner",
            collector_type="wifi_scanner",
            network_scope="2.4GHz Wi-Fi / BLE Airspace"
        )
    else:
        from collector_manager import collector_manager
        collector, raw_token = collector_manager.rotate_token(
            collector_id=collector.id,
            tenant_id=collector.tenant_id
        )
    token = raw_token
    print(f"Provisioned Token: {token}")
    print(f"Collector in DB: ID={collector.id}, Name={collector.name}, Status={collector.status}, Tenant={collector.tenant_id}")

client = TestClient(fastapi_app, raise_server_exceptions=False)

esp32_payload = {
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

# Run client with raise_server_exceptions=True to get exact traceback
client_debug = TestClient(fastapi_app, raise_server_exceptions=True)

try:
    res = client_debug.post("/api/v2/telemetry/ingest", headers=headers, json=esp32_payload)
    print("Response Status:", res.status_code)
    print("Response Body:", res.json())
except Exception as e:
    print("\n================== CAUGHT EXCEPTION ==================")
    traceback.print_exc()
    print("======================================================\n")
