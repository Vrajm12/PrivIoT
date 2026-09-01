"""
Verify live FastAPI endpoint authentication with the provisioned sensor token.
"""
import sys
import os
import json
import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from priviot.api.fastapi_app import app as fastapi_app
from starlette.testclient import TestClient
from models import Collector

client = TestClient(fastapi_app)

with app.app_context():
    collector = Collector.query.filter_by(name="ESP32_Hardware_Scanner").first()
    print(f"[*] Collector in DB: ID={collector.id}, Name={collector.name}, Status={collector.status}, Tenant={collector.tenant_id}")

# 1. Test missing token -> Should return 401
res_missing = client.post("/api/v2/telemetry/ingest", json={"observations": [{"observation_type": "wifi_scan"}]})
print(f"[*] Missing Token Test: Status={res_missing.status_code} (Expected 401)")
assert res_missing.status_code == 401

# 2. Test invalid token -> Should return 401
res_invalid = client.post("/api/v2/telemetry/ingest", 
                          headers={"X-Sensor-Token": "invalid_fake_token_123", "X-Tenant-ID": "default_tenant"},
                          json={"observations": [{"observation_type": "wifi_scan"}]})
print(f"[*] Invalid Token Test: Status={res_invalid.status_code} (Expected 401)")
assert res_invalid.status_code == 401

# 3. Test valid provisioned token with ESP32 Wi-Fi scan payload
token = "priviot_sensor_hkjjf2d5BPTw7rUdXxyfyHXnAyL9z7alE8TJ04CLuok"
headers = {
    "X-Sensor-Token": token,
    "X-Tenant-ID": "default_tenant",
    "Content-Type": "application/json"
}

payload = {
    "collector_id": "ESP32_Hardware_Scanner",
    "observations": [
        {
            "observation_type": "wifi_scan",
            "src_mac": "00:14:22:AA:BB:CC",
            "src_ip": "0.0.0.0",
            "payload": {
                "ssid": "Live_Hotspot_Network",
                "bssid": "00:14:22:AA:BB:CC",
                "rssi": -48,
                "channel": 1,
                "auto_discover": True
            }
        }
    ]
}

res_valid = client.post("/api/v2/telemetry/ingest", headers=headers, json=payload)
print(f"[+] Valid Ingestion Test: Status={res_valid.status_code} (Expected 200)")
print("Response JSON:", res_valid.json())
assert res_valid.status_code == 200
assert res_valid.json()["success"] is True

print("\n========================================================")
print("[PASS] ALL LIVE TELEMETRY AUTHENTICATION TESTS SUCCEEDED!")
print("========================================================\n")
