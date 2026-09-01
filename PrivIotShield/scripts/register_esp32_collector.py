"""
PrivIoT Shield - Provision ESP32 Hardware Scanner Collector
Enrolls the physical ESP32 device as an authorized telemetry sensor in the database
and outputs the X-Sensor-Token for flashing into the Arduino sketch.
"""
import sys
import os

# Add repo root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from extensions import db
from models import Collector
from collector_manager import collector_manager
from priviot.engines.telemetry import telemetry_engine

def provision_esp32():
    with app.app_context():
        # Ensure database tables exist
        db.create_all()

        collector_name = "ESP32_Hardware_Scanner"
        tenant_id = "default_tenant"
        site_id = "default_site"

        existing = Collector.query.filter_by(tenant_id=tenant_id, name=collector_name).first()
        if existing:
            print(f"[*] Found existing collector '{collector_name}' (ID: {existing.id}, UUID: {existing.collector_uuid}).")
            # Rotate token to get a fresh raw token and activate
            collector, raw_token = collector_manager.rotate_token(
                collector_id=existing.id,
                tenant_id=tenant_id
            )
            collector.status = "ACTIVE"
            db.session.commit()
            print("[+] Token rotated and collector activated successfully!")
        else:
            print(f"[*] Enrolling new collector '{collector_name}'...")
            collector, raw_token = collector_manager.enroll_collector(
                tenant_id=tenant_id,
                site_id=site_id,
                name=collector_name,
                collector_type="wifi_scanner",
                network_scope="2.4GHz Wi-Fi / BLE Airspace"
            )
            collector.status = "ACTIVE"
            db.session.commit()
            print("[+] Collector enrolled successfully!")

        # Pre-Flight Self-Verification
        auth_test = telemetry_engine.authenticate_collector(raw_token)
        if not auth_test or auth_test.id != collector.id:
            raise RuntimeError("CRITICAL: Newly provisioned token failed local authentication test!")
        print("[PASS] Self-Verification SUCCESS: Sensor token is active and valid in the database.")

        print("\n========================================================")
        print("          ESP32 SENSOR PROVISIONING SUCCESSFUL          ")
        print("========================================================")
        print(f"Collector ID:   {collector.id}")
        print(f"Collector UUID: {collector.collector_uuid}")
        print(f"Collector Name: {collector.name}")
        print(f"Collector Type: {collector.collector_type}")
        print(f"Tenant ID:      {collector.tenant_id}")
        print(f"Site ID:        {collector.site_id}")
        print(f"Status:         {collector.status}")
        print("--------------------------------------------------------")
        print("YOUR SENSOR TOKEN (Put this in your ESP32 Arduino sketch):")
        print(f"\n   {raw_token}\n")
        print("--------------------------------------------------------")
        print("HTTP Headers used by ESP32:")
        print(f"   X-Sensor-Token: {raw_token}")
        print(f"   X-Tenant-ID: {tenant_id}")
        print("========================================================\n")
        return raw_token

if __name__ == "__main__":
    provision_esp32()

