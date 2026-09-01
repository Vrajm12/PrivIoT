"""
PrivIoT Shield - ESP32 Hardware Integration Automated Test Suite
Verifies collector token auth, Wi-Fi observation batch ingestion,
MAC/BSSID correlation without IP requirement, duplicate prevention, and real sensor attribution.
"""
import unittest
from app import app
from extensions import db
from models import User, Collector, Asset, Observation
from collector_manager import collector_manager
from telemetry_engine import telemetry_engine

class TestESP32HardwareIntegration(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            Observation.query.delete()
            Asset.query.delete()
            Collector.query.delete()
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_esp32_collector_and_wifi_telemetry_flow(self):
        with app.app_context():
            tenant_id = "test_esp32_tenant"
            site_id = "site_lab_01"

            # 1. Provision Collector
            collector, raw_token = collector_manager.enroll_collector(
                tenant_id=tenant_id,
                site_id=site_id,
                name="ESP32_Test_Scanner",
                collector_type="wifi_scanner",
                network_scope="2.4GHz Airspace"
            )
            self.assertIsNotNone(collector.id)
            self.assertEqual(collector.status, "ACTIVE")
            self.assertTrue(raw_token.startswith("priviot_sensor_"))

            # 2. Authenticate Collector Token
            auth_collector = telemetry_engine.authenticate_collector(raw_token)
            self.assertIsNotNone(auth_collector)
            self.assertEqual(auth_collector.id, collector.id)
            self.assertEqual(auth_collector.status, "online")

            # 3. Simulate ESP32 Wi-Fi Scan Batch
            bssid_cisco = "00:14:22:99:88:77"
            bssid_tplink = "50:C7:BF:AA:BB:CC"

            scan_batch = [
                {
                    "observation_type": "wifi_scan",
                    "src_mac": bssid_cisco,
                    "src_ip": "0.0.0.0",
                    "payload": {
                        "ssid": "Office_Corp_WiFi",
                        "bssid": bssid_cisco,
                        "rssi": -55,
                        "channel": 1,
                        "auto_discover": True
                    }
                },
                {
                    "observation_type": "wifi_scan",
                    "src_mac": bssid_tplink,
                    "src_ip": "0.0.0.0",
                    "payload": {
                        "ssid": "Guest_Smart_Plug_AP",
                        "bssid": bssid_tplink,
                        "rssi": -68,
                        "channel": 6,
                        "auto_discover": True
                    }
                }
            ]

            # Ingest First Scan
            res1 = telemetry_engine.ingest_telemetry_batch(
                collector=auth_collector,
                raw_events=scan_batch
            )
            self.assertEqual(res1["status"], "success")
            self.assertEqual(res1["total_ingested"], 2)
            self.assertEqual(res1["correlated_assets"], 2)

            # Verify Assets created with Real Sensor source & OUI vendor resolution
            asset_cisco = Asset.query.filter_by(tenant_id=tenant_id, mac_address=bssid_cisco).first()
            self.assertIsNotNone(asset_cisco)
            self.assertEqual(asset_cisco.vendor, "Cisco")
            self.assertEqual(asset_cisco.hostname, "Office_Corp_WiFi")
            self.assertEqual(asset_cisco.discovery_source, "esp32_wifi_scan")
            self.assertEqual(asset_cisco.reconciliation_method, "esp32_hardware_scanner")

            asset_tplink = Asset.query.filter_by(tenant_id=tenant_id, mac_address=bssid_tplink).first()
            self.assertIsNotNone(asset_tplink)
            self.assertEqual(asset_tplink.vendor, "TP-Link")
            self.assertEqual(asset_tplink.hostname, "Guest_Smart_Plug_AP")
            self.assertEqual(asset_tplink.discovery_source, "esp32_wifi_scan")

            # 4. Duplicate Prevention: Run Second Scan with same BSSIDs
            res2 = telemetry_engine.ingest_telemetry_batch(
                collector=auth_collector,
                raw_events=scan_batch
            )
            self.assertEqual(res2["status"], "success")
            self.assertEqual(res2["total_ingested"], 2)

            # Verify no duplicate assets created
            cisco_count = Asset.query.filter_by(tenant_id=tenant_id, mac_address=bssid_cisco).count()
            self.assertEqual(cisco_count, 1, "Duplicate asset created for same BSSID!")

            tplink_count = Asset.query.filter_by(tenant_id=tenant_id, mac_address=bssid_tplink).count()
            self.assertEqual(tplink_count, 1, "Duplicate asset created for same BSSID!")

            # Verify Observations accumulated
            obs_count = Observation.query.filter_by(tenant_id=tenant_id).count()
            self.assertEqual(obs_count, 4)

            # Clean up test tenant records
            Observation.query.filter_by(tenant_id=tenant_id).delete()
            Asset.query.filter_by(tenant_id=tenant_id).delete()
            Collector.query.filter_by(tenant_id=tenant_id).delete()
            db.session.commit()

    def test_exact_live_esp32_http_ingest_endpoint(self):
        from priviot.api.fastapi_app import app as fastapi_app
        from starlette.testclient import TestClient
        client = TestClient(fastapi_app, raise_server_exceptions=True)

        with app.app_context():
            tenant_id = "default_tenant"
            site_id = "default_site"

            # Create test admin user for authenticated API access
            from werkzeug.security import generate_password_hash
            user = User.query.filter_by(username="admin").first()
            if not user:
                user = User(
                    username="admin",
                    email="admin@priviot.shield",
                    role="admin",
                    password_hash=generate_password_hash("Admin@123"),
                    api_key="test_api_key_secops_123"
                )
                db.session.add(user)
                db.session.commit()

            collector, raw_token = collector_manager.enroll_collector(
                tenant_id=tenant_id,
                site_id=site_id,
                name="ESP32_Exact_Scanner",
                collector_type="wifi_scanner",
                network_scope="2.4GHz Airspace"
            )

            # Exact payload sent by ESP32 firmware
            esp32_payload = {
                "collector_id": "ESP32_Exact_Scanner",
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

            # 1. Valid Token First-Seen Discovery -> HTTP 200, processed=1, new_assets=1
            headers = {
                "X-Sensor-Token": raw_token,
                "X-Tenant-ID": tenant_id,
                "Content-Type": "application/json"
            }
            res = client.post("/api/v2/telemetry/ingest", headers=headers, json=esp32_payload)
            self.assertEqual(res.status_code, 200)
            self.assertTrue(res.json()["success"])
            self.assertEqual(res.json()["processed_count"], 1)
            self.assertEqual(res.json()["new_assets_discovered"], 1)

            # Verify Asset created in DB
            asset = Asset.query.filter_by(tenant_id=tenant_id, mac_address="E6:1F:D5:42:7A:6B").first()
            self.assertIsNotNone(asset)
            self.assertEqual(asset.hostname, "Veeru")
            self.assertEqual(asset.discovery_source, "esp32_wifi_scan")
            self.assertEqual(asset.reconciliation_method, "esp32_hardware_scanner")

            # Verify /api/v2/assets API returns the newly discovered asset
            res_assets = client.get("/api/v2/assets", headers={"X-Tenant-ID": tenant_id, "X-API-Key": "test_api_key_secops_123"})
            self.assertEqual(res_assets.status_code, 200)
            discovered_items = [item for item in res_assets.json()["items"] if item["mac_address"] == "E6:1F:D5:42:7A:6B"]
            self.assertEqual(len(discovered_items), 1)
            self.assertEqual(discovered_items[0]["hostname"], "Veeru")
            self.assertEqual(discovered_items[0]["discovery_source"], "esp32_wifi_scan")

            # 2. Repeat Scan with Same BSSID -> HTTP 200, processed=1, new_assets=0 (NO DUPLICATES)
            res_repeat = client.post("/api/v2/telemetry/ingest", headers=headers, json=esp32_payload)
            self.assertEqual(res_repeat.status_code, 200)
            self.assertTrue(res_repeat.json()["success"])
            self.assertEqual(res_repeat.json()["processed_count"], 1)
            self.assertEqual(res_repeat.json()["new_assets_discovered"], 0)

            # Verify only 1 Asset exists for this MAC
            asset_count = Asset.query.filter_by(tenant_id=tenant_id, mac_address="E6:1F:D5:42:7A:6B").count()
            self.assertEqual(asset_count, 1)

            # 3. Invalid Token -> HTTP 401
            res_bad = client.post("/api/v2/telemetry/ingest", headers={"X-Sensor-Token": "bad_token", "X-Tenant-ID": tenant_id}, json=esp32_payload)
            self.assertEqual(res_bad.status_code, 401)

            # 4. Tenant Mismatch -> HTTP 403
            res_spoof = client.post("/api/v2/telemetry/ingest", headers={"X-Sensor-Token": raw_token, "X-Tenant-ID": "foreign_tenant"}, json=esp32_payload)
            self.assertEqual(res_spoof.status_code, 403)

    def test_empty_db_and_four_distinct_esp32_scans_lifecycle(self):
        from priviot.api.fastapi_app import app as fastapi_app
        from starlette.testclient import TestClient
        client = TestClient(fastapi_app, raise_server_exceptions=True)

        with app.app_context():
            tenant_id = "default_tenant"
            site_id = "default_site"

            from werkzeug.security import generate_password_hash
            user = User.query.filter_by(username="admin").first()
            if not user:
                user = User(
                    username="admin",
                    email="admin@priviot.shield",
                    role="admin",
                    password_hash=generate_password_hash("Admin@123"),
                    api_key="test_api_key_secops_456"
                )
                db.session.add(user)
                db.session.commit()

            collector, raw_token = collector_manager.enroll_collector(
                tenant_id=tenant_id,
                site_id=site_id,
                name="ESP32_4Net_Scanner",
                collector_type="wifi_scanner",
                network_scope="2.4GHz Airspace"
            )

            headers = {
                "X-Sensor-Token": raw_token,
                "X-Tenant-ID": tenant_id,
                "Content-Type": "application/json"
            }
            api_headers = {
                "X-Tenant-ID": tenant_id,
                "X-API-Key": user.api_key
            }

            # 1. Empty DB Check: GET /api/v2/assets returns 0 assets
            res_initial = client.get("/api/v2/assets", headers=api_headers)
            self.assertEqual(res_initial.status_code, 200)
            self.assertEqual(res_initial.json()["total_count"], 0)
            self.assertEqual(len(res_initial.json()["items"]), 0)

            # 2. Four Distinct Wi-Fi Scan Observations
            four_networks_batch = {
                "collector_id": "ESP32_4Net_Scanner",
                "observations": [
                    {
                        "observation_type": "wifi_scan",
                        "src_mac": "AA:BB:CC:11:22:33",
                        "src_ip": "0.0.0.0",
                        "payload": {
                            "ssid": "Office_Primary_AP",
                            "bssid": "AA:BB:CC:11:22:33",
                            "rssi": -42,
                            "channel": 1,
                            "encryption_type": 4,
                            "auto_discover": True
                        }
                    },
                    {
                        "observation_type": "wifi_scan",
                        "src_mac": "AA:BB:CC:44:55:66",
                        "src_ip": "0.0.0.0",
                        "payload": {
                            "ssid": "Guest_Lounge_WiFi",
                            "bssid": "AA:BB:CC:44:55:66",
                            "rssi": -58,
                            "channel": 6,
                            "encryption_type": 3,
                            "auto_discover": True
                        }
                    },
                    {
                        "observation_type": "wifi_scan",
                        "src_mac": "AA:BB:CC:77:88:99",
                        "src_ip": "0.0.0.0",
                        "payload": {
                            "ssid": "IoT_Sensors_Mesh",
                            "bssid": "AA:BB:CC:77:88:99",
                            "rssi": -65,
                            "channel": 11,
                            "encryption_type": 4,
                            "auto_discover": True
                        }
                    },
                    {
                        "observation_type": "wifi_scan",
                        "src_mac": "AA:BB:CC:AA:BB:CC",
                        "src_ip": "0.0.0.0",
                        "payload": {
                            "ssid": "<hidden>",
                            "bssid": "AA:BB:CC:AA:BB:CC",
                            "rssi": -78,
                            "channel": 6,
                            "encryption_type": 5,
                            "auto_discover": True
                        }
                    }
                ]
            }

            # Ingest 4 networks -> processed=4, new_assets=4
            res_4 = client.post("/api/v2/telemetry/ingest", headers=headers, json=four_networks_batch)
            self.assertEqual(res_4.status_code, 200)
            self.assertEqual(res_4.json()["processed_count"], 4)
            self.assertEqual(res_4.json()["new_assets_discovered"], 4)

            # Query DB and API
            res_assets_4 = client.get("/api/v2/assets", headers=api_headers)
            self.assertEqual(res_assets_4.status_code, 200)
            self.assertEqual(res_assets_4.json()["total_count"], 4)
            self.assertEqual(len(res_assets_4.json()["items"]), 4)

            for item in res_assets_4.json()["items"]:
                self.assertEqual(item["discovery_source"], "esp32_wifi_scan")
                self.assertEqual(item["reconciliation_method"], "esp32_hardware_scanner")
                self.assertEqual(item["ip_address"], "0.0.0.0")

            # 3. Repeat Ingest of the Same 4 networks -> processed=4, new_assets=0
            res_repeat_4 = client.post("/api/v2/telemetry/ingest", headers=headers, json=four_networks_batch)
            self.assertEqual(res_repeat_4.status_code, 200)
            self.assertEqual(res_repeat_4.json()["processed_count"], 4)
            self.assertEqual(res_repeat_4.json()["new_assets_discovered"], 0)

            # Asset count remains strictly 4
            res_assets_final = client.get("/api/v2/assets", headers=api_headers)
            self.assertEqual(res_assets_final.status_code, 200)
            self.assertEqual(res_assets_final.json()["total_count"], 4)

if __name__ == "__main__":
    unittest.main()
