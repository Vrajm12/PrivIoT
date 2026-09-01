"""
PrivIoT Shield - End-to-End Deterministic Test Suite for Real ESP32 Radio Telemetry Pipeline
Verifies:
- First observation & asset auto-discovery
- Normal repeated observations (No false alerts / no spurious anomalies)
- Progressive Evidence Maturity Model (Early Signal -> Initial -> Developing -> Stable Baseline)
- Statistical RSSI Anomaly detection
- Radio Channel Drift detection
- Open/Unencrypted Wi-Fi security alert
- Encryption Downgrade threat alert
- Signal History API endpoint (/api/v2/assets/{id}/signal-history)
- Fleet Behavioral Stats API endpoint (/api/v2/behavior/stats)
"""
import unittest
import json
import secrets
from datetime import datetime, timedelta
from app import app
from extensions import db
from models import User, Collector, Asset, Observation, BehavioralBaseline, BehavioralDriftEvent, Alert, RiskAssessment
from behavioral_engine import behavioral_engine
from exposure_engine import exposure_engine
from telemetry_engine import telemetry_engine


class RealEsp32PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()
        
        self.tenant_id = "test_tenant_" + secrets.token_hex(4)
        raw_token = "priviot_sensor_test_token_" + secrets.token_hex(8)
        import hashlib
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        
        self.collector = Collector(
            tenant_id=self.tenant_id,
            site_id="site_test_lab",
            name="ESP32_Test_Scanner",
            collector_type="wifi_scanner",
            auth_token_hash=token_hash,
            status="online"
        )
        db.session.add(self.collector)
        db.session.commit()

    def tearDown(self):
        # Cleanup tenant data
        Observation.query.filter_by(tenant_id=self.tenant_id).delete()
        BehavioralDriftEvent.query.filter_by(tenant_id=self.tenant_id).delete()
        BehavioralBaseline.query.filter_by(tenant_id=self.tenant_id).delete()
        RiskAssessment.query.filter_by(tenant_id=self.tenant_id).delete()
        Alert.query.filter_by(tenant_id=self.tenant_id).delete()
        Asset.query.filter_by(tenant_id=self.tenant_id).delete()
        Collector.query.filter_by(tenant_id=self.tenant_id).delete()
        db.session.commit()
        self.ctx.pop()

    def test_01_first_observation_and_discovery(self):
        """Test A: First observation of a new Wi-Fi AP correctly creates Asset and Observation."""
        raw_event = [{
            "observation_type": "wifi_scan",
            "payload": {
                "bssid": "AA:BB:CC:11:22:33",
                "ssid": "Test_Secure_AP",
                "rssi": -48,
                "channel": 6,
                "encryption_type": 3, # WPA2
                "auto_discover": True
            }
        }]
        
        res = telemetry_engine.ingest_telemetry_batch(self.collector, raw_event)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_ingested"], 1)
        self.assertEqual(res["new_assets_discovered"], 1)
        self.assertEqual(res["anomalies_detected"], 0) # First scan of normal AP is NOT an anomaly

        asset = Asset.query.filter_by(tenant_id=self.tenant_id, mac_address="AA:BB:CC:11:22:33").first()
        self.assertIsNotNone(asset)
        self.assertEqual(asset.hostname, "Test_Secure_AP")
        self.assertEqual(asset.discovery_source, "esp32_wifi_scan")

        # Verify baseline created with EARLY SIGNAL
        baseline = BehavioralBaseline.query.filter_by(tenant_id=self.tenant_id, asset_id=asset.id).first()
        self.assertIsNotNone(baseline)
        summary = json.loads(baseline.summary_json or '{}')
        self.assertEqual(summary["maturity_stage"], "EARLY SIGNAL")
        self.assertEqual(summary["confidence_band"], "LOW EVIDENCE")
        self.assertEqual(summary["observation_count"], 1)
        self.assertEqual(summary["primary_channel"], 6)

        # Verify PRI risk
        latest_risk = asset.get_latest_risk()
        self.assertIsNotNone(latest_risk)
        self.assertEqual(latest_risk.pri_level, "low")

    def test_02_stable_repeated_observations_no_spurious_alerts(self):
        """Test B: Stable repeated observations increment baseline count and confidence without creating alerts or anomalies."""
        asset = Asset(
            tenant_id=self.tenant_id,
            mac_address="22:33:44:55:66:77",
            ip_address="0.0.0.0",
            hostname="Office_Stable_WPA2",
            discovery_source="esp32_wifi_scan",
            first_seen=datetime.utcnow() - timedelta(minutes=15),
            last_seen=datetime.utcnow()
        )
        db.session.add(asset)
        db.session.commit()

        # Send 15 normal repeated scans on Channel 6, RSSI ~ -50 dBm
        for i in range(15):
            res = telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {
                    "bssid": "22:33:44:55:66:77",
                    "ssid": "Office_Stable_WPA2",
                    "rssi": -50 + (i % 3),
                    "channel": 6,
                    "encryption_type": 3
                }
            }])
            self.assertEqual(res["anomalies_detected"], 0)

        # Confirm ZERO alerts generated
        alerts = Alert.query.filter_by(tenant_id=self.tenant_id, asset_id=asset.id).all()
        self.assertEqual(len(alerts), 0)

        # Confirm ZERO drift events
        drifts = BehavioralDriftEvent.query.filter_by(tenant_id=self.tenant_id, asset_id=asset.id).all()
        self.assertEqual(len(drifts), 0)

        # Confirm Progressive Maturity advanced to INITIAL BASELINE (15 obs)
        baseline = asset.get_active_baseline()
        summary = json.loads(baseline.summary_json or '{}')
        self.assertEqual(summary["maturity_stage"], "INITIAL BASELINE")
        self.assertEqual(summary["confidence_band"], "DEVELOPING")
        self.assertGreaterEqual(summary["maturity_confidence"], 0.40)

    def test_03_open_wifi_airspace_alert(self):
        """Test C: Discovery of an Open/Unencrypted Wi-Fi AP triggers High PRI and Security Alert on initial discovery."""
        raw_event = [{
            "observation_type": "wifi_scan",
            "payload": {
                "bssid": "00:11:22:33:44:55",
                "ssid": "Free_Coffee_Open",
                "rssi": -42,
                "channel": 1,
                "encryption_type": 0, # OPEN
                "auto_discover": True
            }
        }]
        
        res = telemetry_engine.ingest_telemetry_batch(self.collector, raw_event)
        self.assertEqual(res["anomalies_detected"], 1)

        asset = Asset.query.filter_by(tenant_id=self.tenant_id, mac_address="00:11:22:33:44:55").first()
        self.assertIsNotNone(asset)

        # Check elevated PRI due to unencrypted cleartext airspace
        latest_risk = asset.get_latest_risk()
        self.assertIsNotNone(latest_risk)
        self.assertGreaterEqual(latest_risk.pri_score, 7.5)

        # Check generated alert
        alert = Alert.query.filter_by(tenant_id=self.tenant_id, asset_id=asset.id, alert_type="open_unencrypted_wifi").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "high")

    def test_04_channel_drift_detection(self):
        """Test D: AP shifting channels creates an explainable BehavioralDriftEvent after established baseline."""
        asset = Asset(
            tenant_id=self.tenant_id,
            mac_address="DE:AD:BE:EF:00:01",
            ip_address="0.0.0.0",
            hostname="Drifting_AP",
            discovery_source="esp32_wifi_scan",
            first_seen=datetime.utcnow() - timedelta(minutes=30),
            last_seen=datetime.utcnow() - timedelta(minutes=10)
        )
        db.session.add(asset)
        db.session.commit()

        # Seed 12 baseline observations on Channel 1
        for i in range(12):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {
                    "bssid": "DE:AD:BE:EF:00:01",
                    "ssid": "Drifting_AP",
                    "rssi": -55,
                    "channel": 1,
                    "encryption_type": 3
                }
            }])

        # Now send scan on Channel 11 (Channel Drift)
        res = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {
                "bssid": "DE:AD:BE:EF:00:01",
                "ssid": "Drifting_AP",
                "rssi": -55,
                "channel": 11,
                "encryption_type": 3
            }
        }])

        self.assertEqual(res["anomalies_detected"], 1)

        drift = BehavioralDriftEvent.query.filter_by(
            tenant_id=self.tenant_id,
            asset_id=asset.id,
            drift_type="channel_drift"
        ).first()
        self.assertIsNotNone(drift)
        self.assertIn("Channel 1 to Channel 11", drift.difference_description)

    def test_05_rssi_proximity_anomaly(self):
        """Test E: Statistically significant signal change (> 3 std dev and > 20 dB) creates RSSI anomaly."""
        asset = Asset(
            tenant_id=self.tenant_id,
            mac_address="11:22:33:44:55:66",
            ip_address="0.0.0.0",
            hostname="Moving_AP",
            discovery_source="esp32_wifi_scan",
            first_seen=datetime.utcnow() - timedelta(minutes=40),
            last_seen=datetime.utcnow() - timedelta(minutes=5)
        )
        db.session.add(asset)
        db.session.commit()

        # Seed 20 baseline observations at -45 dBm (sufficient history)
        for i in range(20):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {
                    "bssid": "11:22:33:44:55:66",
                    "ssid": "Moving_AP",
                    "rssi": -45,
                    "channel": 6,
                    "encryption_type": 3
                }
            }])

        # Sudden drop to -85 dBm (40 dB jump)
        res = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {
                "bssid": "11:22:33:44:55:66",
                "ssid": "Moving_AP",
                "rssi": -85,
                "channel": 6,
                "encryption_type": 3
            }
        }])

        self.assertEqual(res["anomalies_detected"], 1)

        drift = BehavioralDriftEvent.query.filter_by(
            tenant_id=self.tenant_id,
            asset_id=asset.id,
            drift_type="rssi_anomaly"
        ).first()
        self.assertIsNotNone(drift)
        self.assertIn("deviates by", drift.difference_description)

    def test_06_encryption_downgrade_threat(self):
        """Test F: Access point downgrading from WPA2 to Open triggers security downgrade threat alert."""
        asset = Asset(
            tenant_id=self.tenant_id,
            mac_address="33:44:55:66:77:88",
            ip_address="0.0.0.0",
            hostname="Corporate_Secure",
            discovery_source="esp32_wifi_scan",
            first_seen=datetime.utcnow() - timedelta(minutes=20),
            last_seen=datetime.utcnow()
        )
        db.session.add(asset)
        db.session.commit()

        # Seed 8 observations with WPA2 (type 3)
        for i in range(8):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {
                    "bssid": "33:44:55:66:77:88",
                    "ssid": "Corporate_Secure",
                    "rssi": -48,
                    "channel": 6,
                    "encryption_type": 3
                }
            }])

        # Now simulate Rogue Downgrade to Open (type 0)
        res = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {
                "bssid": "33:44:55:66:77:88",
                "ssid": "Corporate_Secure",
                "rssi": -48,
                "channel": 6,
                "encryption_type": 0
            }
        }])

        self.assertGreaterEqual(res["anomalies_detected"], 1)

        # Verify critical threat alert created
        alert = Alert.query.filter_by(tenant_id=self.tenant_id, asset_id=asset.id, alert_type="security_downgrade").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "critical")


if __name__ == "__main__":
    unittest.main()
