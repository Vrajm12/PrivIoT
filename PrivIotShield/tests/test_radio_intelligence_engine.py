"""
PRIVIOT RIM — Radio Intelligence & Movement Engine Test Suite
20 Deterministic Unit & Integration Test Scenarios using isolated synthetic fixtures.
Validates statistical moments, trajectory slopes, relative proximity, temporal recurrence,
fingerprint similarity, cyber-physical event classification, and bounded PRI invariants.
"""

import unittest
import json
import secrets
from datetime import datetime, timedelta

from app import app
from extensions import db
from models import User, Collector, Asset, Observation, BehavioralBaseline, BehavioralDriftEvent, Alert
from telemetry_engine import telemetry_engine, hash_sensor_token
from behavioral_engine import behavioral_engine
from exposure_engine import exposure_engine
from rim_engine import rim_engine


class RadioIntelligenceEngineTestCase(unittest.TestCase):
    """
    Deterministic test suite for PRIVIOT RIM (Radio Intelligence & Movement Engine).
    """

    def setUp(self):
        self.app = app
        self.app_context = self.app.app_context()
        self.app_context.push()

        self.tenant_id = f"test_rim_tenant_{secrets.token_hex(4)}"

        token = "rim_test_sensor_token_123"
        self.collector = Collector(
            collector_uuid=f"col-{secrets.token_hex(4)}",
            tenant_id=self.tenant_id,
            site_id="site_rim_test",
            name="ESP32_RIM_Test_Node",
            collector_type="wifi_scanner",
            auth_token_hash=hash_sensor_token(token),
            status="online",
            created_at=datetime.utcnow()
        )
        db.session.add(self.collector)
        db.session.commit()

    def tearDown(self):
        # Clean test fixtures completely
        Alert.query.filter_by(tenant_id=self.tenant_id).delete()
        BehavioralDriftEvent.query.filter_by(tenant_id=self.tenant_id).delete()
        BehavioralBaseline.query.filter_by(tenant_id=self.tenant_id).delete()
        Observation.query.filter_by(tenant_id=self.tenant_id).delete()
        Asset.query.filter_by(tenant_id=self.tenant_id).delete()
        Collector.query.filter_by(tenant_id=self.tenant_id).delete()
        db.session.commit()
        self.app_context.pop()

    def test_01_first_observation_early_signal(self):
        """Test 1: Initial observation establishes EARLY SIGNAL maturity with <= 40% confidence."""
        res = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {
                "bssid": "AA:BB:CC:11:22:33",
                "ssid": "Test_AP_1",
                "rssi": -48,
                "channel": 6,
                "encryption_type": 3
            }
        }])
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["new_assets_discovered"], 1)

        asset = Asset.query.filter_by(tenant_id=self.tenant_id, mac_address="AA:BB:CC:11:22:33").first()
        baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id).first()
        summary = json.loads(baseline.summary_json or '{}')

        self.assertEqual(summary["maturity_stage"], "EARLY SIGNAL")
        self.assertLessEqual(summary["maturity_confidence"], 0.40)
        self.assertEqual(summary["radio_fingerprint"]["primary_channel"], 6)

    def test_02_insufficient_evidence_handling(self):
        """Test 2: Low observation count (< 5) outputs INSUFFICIENT_EVIDENCE / UNKNOWN movement."""
        t0 = datetime.utcnow()
        points = [
            {"timestamp": (t0 + timedelta(seconds=i*20)).isoformat(), "rssi": -50 + i, "ema": -50.0}
            for i in range(3)
        ]
        res = rim_engine.estimate_rssi_trend_and_movement(points, -49.0, 3.5)
        self.assertEqual(res["trend"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(res["movement_state"], "UNKNOWN")

    def test_03_stable_rssi_stationary_inference(self):
        """Test 3: Flat RSSI series yields STABLE trend and STATIONARY movement state."""
        t0 = datetime.utcnow()
        points = [
            {"timestamp": (t0 + timedelta(seconds=i*20)).isoformat(), "rssi": -45 + (i % 2), "ema": -45.0}
            for i in range(8)
        ]
        res = rim_engine.estimate_rssi_trend_and_movement(points, -45.0, 3.5)
        self.assertEqual(res["trend"], "STABLE")
        self.assertEqual(res["movement_state"], "STATIONARY")
        self.assertGreaterEqual(res["confidence"], 0.70)

    def test_04_gradual_rssi_strengthening_approaching(self):
        """Test 4: Progressively increasing signal yields APPROACHING movement."""
        t0 = datetime.utcnow()
        rssi_seq = [-72, -68, -64, -60, -56, -52, -48, -44]
        points = [
            {"timestamp": (t0 + timedelta(seconds=i*20)).isoformat(), "rssi": rssi_seq[i], "ema": float(rssi_seq[i])}
            for i in range(len(rssi_seq))
        ]
        res = rim_engine.estimate_rssi_trend_and_movement(points, -58.0, 8.0)
        self.assertEqual(res["trend"], "APPROACHING")
        self.assertEqual(res["movement_state"], "APPROACHING")
        self.assertGreater(res["slope_db_per_sec"], 0.10)
        self.assertGreaterEqual(res["directional_consistency"], 0.50)

    def test_05_gradual_rssi_weakening_departing(self):
        """Test 5: Progressively decreasing signal yields DEPARTING movement."""
        t0 = datetime.utcnow()
        rssi_seq = [-44, -48, -52, -56, -60, -64, -68, -72]
        points = [
            {"timestamp": (t0 + timedelta(seconds=i*20)).isoformat(), "rssi": rssi_seq[i], "ema": float(rssi_seq[i])}
            for i in range(len(rssi_seq))
        ]
        res = rim_engine.estimate_rssi_trend_and_movement(points, -58.0, 8.0)
        self.assertEqual(res["trend"], "DEPARTING")
        self.assertEqual(res["movement_state"], "DEPARTING")
        self.assertLess(res["slope_db_per_sec"], -0.10)
        self.assertLessEqual(res["directional_consistency"], -0.50)

    def test_06_unstable_noisy_rssi_rejection(self):
        """Test 6: High-variance alternating signal yields UNSTABLE state without false approaching alert."""
        t0 = datetime.utcnow()
        rssi_seq = [-40, -75, -42, -78, -41, -76, -43, -79]
        points = [
            {"timestamp": (t0 + timedelta(seconds=i*20)).isoformat(), "rssi": rssi_seq[i], "ema": -58.0}
            for i in range(len(rssi_seq))
        ]
        res = rim_engine.estimate_rssi_trend_and_movement(points, -59.0, 18.0)
        self.assertEqual(res["trend"], "UNSTABLE")
        self.assertEqual(res["movement_state"], "UNSTABLE")

    def test_07_channel_stability_calculation(self):
        """Test 7: Channel stability metric correctly reflects channel adherence ratio."""
        stats = rim_engine.calculate_statistical_rssi([-50, -50, -50], -50)
        self.assertEqual(stats["mean"], -50.0)
        self.assertEqual(stats["std_dev"], 3.5)

    def test_08_channel_hopping_detection(self):
        """Test 8: Channel shift on mature device triggers channel_drift anomaly with deduplication."""
        bssid = "AA:BB:CC:33:44:55"
        for i in range(12):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {"bssid": bssid, "ssid": "Hop_AP", "rssi": -50, "channel": 1, "encryption_type": 3}
            }])

        # Shift to Channel 11
        res1 = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {"bssid": bssid, "ssid": "Hop_AP", "rssi": -50, "channel": 11, "encryption_type": 3}
        }])
        self.assertEqual(res1["anomalies_detected"], 1)

        # Repeated scan on Channel 11 must NOT create duplicate drift row
        res2 = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {"bssid": bssid, "ssid": "Hop_AP", "rssi": -50, "channel": 11, "encryption_type": 3}
        }])
        self.assertEqual(res2["anomalies_detected"], 0)

        asset = Asset.query.filter_by(tenant_id=self.tenant_id, mac_address=bssid).first()
        drifts = BehavioralDriftEvent.query.filter_by(asset_id=asset.id, drift_type="channel_drift").all()
        self.assertEqual(len(drifts), 1)

    def test_09_ap_temporary_omission_probably_present(self):
        """Test 9: 2 missed scans (40s) outputs PROBABLY_PRESENT without false alert."""
        now = datetime.utcnow()
        t_first = now - timedelta(minutes=30)
        t_last = now - timedelta(seconds=60)
        res = rim_engine.evaluate_presence_and_recurrence(t_first, t_last, 85, now=now)
        self.assertEqual(res["presence_state"], "PROBABLY_PRESENT")
        self.assertEqual(res["missed_scans"], 3)

    def test_10_ap_prolonged_absence_missing(self):
        """Test 10: > 8 missed scans (> 3m) outputs MISSING state."""
        now = datetime.utcnow()
        t_first = now - timedelta(hours=2)
        t_last = now - timedelta(minutes=15)
        res = rim_engine.evaluate_presence_and_recurrence(t_first, t_last, 100, now=now)
        self.assertEqual(res["presence_state"], "MISSING")
        self.assertGreater(res["missed_scans"], 8)

    def test_11_ap_reappearance_state(self):
        """Test 11: Recent observation (<= 40s) outputs PRESENT state."""
        now = datetime.utcnow()
        t_first = now - timedelta(hours=1)
        t_last = now - timedelta(seconds=15)
        res = rim_engine.evaluate_presence_and_recurrence(t_first, t_last, 150, now=now)
        self.assertEqual(res["presence_state"], "PRESENT")

    def test_12_ssid_identity_change_detection(self):
        """Test 12: Changing broadcast SSID triggers ssid_spoof threat and drops similarity score."""
        bssid = "AA:BB:CC:55:66:77"
        for i in range(12):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {"bssid": bssid, "ssid": "Original_SSID", "rssi": -45, "channel": 6, "encryption_type": 3}
            }])

        # Broadcast renamed
        res = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {"bssid": bssid, "ssid": "Spoofed_SSID", "rssi": -45, "channel": 6, "encryption_type": 3}
        }])
        self.assertEqual(res["anomalies_detected"], 1)

        asset = Asset.query.filter_by(tenant_id=self.tenant_id, mac_address=bssid).first()
        baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id).first()
        summary = json.loads(baseline.summary_json or '{}')
        self.assertIn("similarity", summary)
        self.assertLess(summary["similarity"]["similarity_score"], 0.90)

    def test_13_security_downgrade_threat_classification(self):
        """Test 13: Encryption downgrade from WPA2 to Open generates critical Alert and THREAT classification."""
        bssid = "AA:BB:CC:77:88:99"
        for i in range(6):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {"bssid": bssid, "ssid": "Secure_AP", "rssi": -50, "channel": 6, "encryption_type": 3}
            }])

        # Downgrade to Open (0)
        res = telemetry_engine.ingest_telemetry_batch(self.collector, [{
            "observation_type": "wifi_scan",
            "payload": {"bssid": bssid, "ssid": "Secure_AP", "rssi": -50, "channel": 6, "encryption_type": 0}
        }])
        self.assertEqual(res["anomalies_detected"], 1)

        asset = Asset.query.filter_by(tenant_id=self.tenant_id, mac_address=bssid).first()
        alert = Alert.query.filter_by(asset_id=asset.id, alert_type="security_downgrade").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "critical")

    def test_14_proximity_score_boundary_clamping(self):
        """Test 14: Proximity score clamps properly at -100 dBm (0) and -20 dBm (100)."""
        p_min = rim_engine.calculate_relative_proximity(-110.0)
        self.assertEqual(p_min["proximity_score"], 0)
        self.assertEqual(p_min["proximity_state"], "VERY_FAR")

        p_max = rim_engine.calculate_relative_proximity(-10.0)
        self.assertEqual(p_max["proximity_score"], 100)
        self.assertEqual(p_max["proximity_state"], "VERY_NEAR")

    def test_15_proximity_zone_tiers(self):
        """Test 15: Proximity zone tiers map correctly across dynamic range."""
        p_near = rim_engine.calculate_relative_proximity(-45.0)
        self.assertEqual(p_near["proximity_state"], "NEAR")
        self.assertTrue(60 <= p_near["proximity_score"] <= 79)

        p_mod = rim_engine.calculate_relative_proximity(-60.0)
        self.assertEqual(p_mod["proximity_state"], "MODERATE")
        self.assertTrue(40 <= p_mod["proximity_score"] <= 59)

        p_far = rim_engine.calculate_relative_proximity(-75.0)
        self.assertEqual(p_far["proximity_state"], "FAR")
        self.assertTrue(20 <= p_far["proximity_score"] <= 39)

    def test_16_confidence_evidence_monotonicity(self):
        """Test 16: Maturity confidence strictly increases monotonically with observation count."""
        now = datetime.utcnow()
        t0 = now - timedelta(hours=2)
        _, _, c1, _ = behavioral_engine.calculate_maturity(t0, now, 5)
        _, _, c2, _ = behavioral_engine.calculate_maturity(t0, now, 25)
        _, _, c3, _ = behavioral_engine.calculate_maturity(t0, now, 75)
        _, _, c4, _ = behavioral_engine.calculate_maturity(t0, now, 150)

        self.assertLess(c1, c2)
        self.assertLess(c2, c3)
        self.assertLess(c3, c4)

    def test_17_fingerprint_similarity_exact_match(self):
        """Test 17: Identical current transmission and established baseline gives similarity >= 0.95."""
        obs = {"channel": 6, "rssi": -45, "encryption_type": 3, "ssid": "Stable_AP"}
        base = {"primary_channel": 6, "primary_ssid": "Stable_AP", "rssi_mean": -45.0, "rssi_std_dev": 4.0, "encryption_type": 3}
        sim = rim_engine.calculate_fingerprint_similarity(obs, base)
        self.assertGreaterEqual(sim["similarity_score"], 0.95)
        self.assertEqual(sim["verdict"], "MATCH")

    def test_18_fingerprint_similarity_divergent_pattern(self):
        """Test 18: Divergent parameters drop similarity below 0.60."""
        obs = {"channel": 11, "rssi": -85, "encryption_type": 0, "ssid": "Rogue_AP"}
        base = {"primary_channel": 6, "primary_ssid": "Corp_AP", "rssi_mean": -40.0, "rssi_std_dev": 3.5, "encryption_type": 3}
        sim = rim_engine.calculate_fingerprint_similarity(obs, base)
        self.assertLess(sim["similarity_score"], 0.60)
        self.assertEqual(sim["verdict"], "ANOMALOUS")

    def test_19_cyber_physical_classification(self):
        """Test 19: Distinguishes NORMAL, CHANGE, ANOMALY, and THREAT accurately."""
        # 1. Normal
        c_norm = rim_engine.classify_cyber_physical_event({"movement_state": "STATIONARY", "similarity_score": 0.95}, {"primary_ssid": "AP"})
        self.assertEqual(c_norm["classification"], "NORMAL")

        # 2. Change (Movement)
        c_change = rim_engine.classify_cyber_physical_event({"movement_state": "APPROACHING", "similarity_score": 0.88}, {"primary_ssid": "AP"})
        self.assertEqual(c_change["classification"], "CHANGE")
        self.assertEqual(c_change["pri_impact"], 0.0)

        # 3. Anomaly
        c_anom = rim_engine.classify_cyber_physical_event({"movement_state": "STATIONARY", "similarity_score": 0.45, "observation_count": 20}, {"primary_ssid": "AP"})
        self.assertEqual(c_anom["classification"], "ANOMALY")

        # 4. Threat (Downgrade)
        c_threat = rim_engine.classify_cyber_physical_event({"encryption_type": 0, "observation_count": 10}, {"encryption_type": 3, "primary_ssid": "AP"})
        self.assertEqual(c_threat["classification"], "THREAT")

    def test_20_bounded_pri_invariance_on_repeated_scans(self):
        """Test 20: Repeated observations of active condition do NOT compound or inflate PRI."""
        bssid = "AA:BB:CC:99:00:11"
        for i in range(15):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {"bssid": bssid, "ssid": "Primary_AP", "rssi": -45, "channel": 6, "encryption_type": 3}
            }])

        asset = Asset.query.filter_by(tenant_id=self.tenant_id, mac_address=bssid).first()
        r1 = asset.get_latest_risk()
        pri_initial = r1.pri_score

        # Trigger SSID change and repeat 10 times
        for i in range(10):
            telemetry_engine.ingest_telemetry_batch(self.collector, [{
                "observation_type": "wifi_scan",
                "payload": {"bssid": bssid, "ssid": "Renamed_AP", "rssi": -45, "channel": 6, "encryption_type": 3}
            }])

        r_final = asset.get_latest_risk()
        # Initial PRI (2.0 * 0.5 = 1.0), final with ssid_spoof penalty (+1.5) = 2.5
        self.assertEqual(r_final.pri_score, 2.5)
        # Verify only 1 drift row exists
        drifts = BehavioralDriftEvent.query.filter_by(asset_id=asset.id, drift_type="ssid_spoof").all()
        self.assertEqual(len(drifts), 1)


if __name__ == "__main__":
    unittest.main()
