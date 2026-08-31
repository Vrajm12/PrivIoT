"""
PrivIoT Shield - Phase 2 Comprehensive Test Suite
Validates Continuous Device Trust Profile, Sensor Auth, Telemetry Ingestion, Asset Correlation,
DNS Intelligence, 48h Baseline & Drift Detection, PRI-v2, Containment State Machine, and Verification.
"""

import unittest
import json
from datetime import datetime, timedelta

from app import app, db
from models import User, Asset, Collector, Observation, BehavioralBaseline, BehavioralDriftEvent, Alert, ContainmentIntent, ScheduledScan
from telemetry_engine import telemetry_engine
from dns_intel import dns_intel_engine
from behavioral_engine import behavioral_engine
from exposure_engine import exposure_engine
from containment_engine import containment_engine
from alert_engine import alert_engine
from scheduler_engine import scheduler_engine


class TestPhase2ContinuousTrust(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user = User(username='sec_admin', email='admin@priviot.io', password_hash='hash123')
            db.session.add(self.user)
            db.session.commit()
            self.api_key = self.user.api_key
            self.headers = {
                "X-API-Key": self.api_key,
                "X-Tenant-ID": "tenant_enterprise",
                "Content-Type": "application/json"
            }

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_collector_registration_and_token_auth(self):
        with app.app_context():
            # 1. Register Collector
            collector, raw_token = telemetry_engine.register_collector(
                tenant_id="tenant_enterprise",
                site_id="hq_datacenter",
                name="HQ_Edge_Sensor_01",
                collector_type="passive_packet"
            )
            self.assertIsNotNone(collector.id)
            self.assertTrue(raw_token.startswith("priviot_sensor_"))

            # 2. Authenticate with valid token
            auth_node = telemetry_engine.authenticate_collector(raw_token)
            self.assertIsNotNone(auth_node)
            self.assertEqual(auth_node.name, "HQ_Edge_Sensor_01")
            self.assertEqual(auth_node.status, "online")

            # 3. Authenticate with invalid token
            bad_auth = telemetry_engine.authenticate_collector("invalid_token_xyz")
            self.assertIsNone(bad_auth)

    def test_telemetry_security_and_oversized_batch_rejection(self):
        with app.app_context():
            collector, token = telemetry_engine.register_collector(
                tenant_id="tenant_enterprise", site_id="hq", name="Sensor_02"
            )

        # 1. Ingestion without token -> 401
        res = self.app.post("/api/v2/telemetry/ingest", json=[{"src_ip": "10.0.1.5"}])
        self.assertEqual(res.status_code, 401)

        # 2. Ingestion with fake token -> 403
        res = self.app.post("/api/v2/telemetry/ingest", json=[{"src_ip": "10.0.1.5"}], headers={"X-Sensor-Token": "fake_token"})
        self.assertEqual(res.status_code, 403)

        # 3. Oversized batch (> 500 events) -> 400
        oversized = [{"src_ip": f"10.0.1.{i % 250}", "dst_ip": "8.8.8.8", "dst_port": 53} for i in range(501)]
        res = self.app.post("/api/v2/telemetry/ingest", json=oversized, headers={"X-Sensor-Token": token})
        self.assertEqual(res.status_code, 400)
        self.assertIn("exceeds limit", res.get_json()["error"])

    def test_asset_traffic_correlation_and_null_fallback(self):
        with app.app_context():
            # Create a known Asset
            asset = Asset(
                tenant_id="tenant_enterprise",
                user_id=self.user.id,
                ip_address="192.168.1.105",
                mac_address="00:12:17:AA:BB:CC",
                vendor="Hikvision",
                device_type="IP Camera"
            )
            db.session.add(asset)
            db.session.commit()

            # 1. Correlate by MAC
            corr_mac = telemetry_engine.correlate_asset(
                tenant_id="tenant_enterprise",
                src_ip="192.168.1.105",
                mac_address="00:12:17:AA:BB:CC"
            )
            self.assertEqual(corr_mac.id, asset.id)

            # 2. Correlate by IP
            corr_ip = telemetry_engine.correlate_asset(
                tenant_id="tenant_enterprise",
                src_ip="192.168.1.105"
            )
            self.assertEqual(corr_ip.id, asset.id)

            # 3. Unknown unassigned IP -> NULL (Do NOT fabricate attribution)
            corr_unknown = telemetry_engine.correlate_asset(
                tenant_id="tenant_enterprise",
                src_ip="10.254.254.99"
            )
            self.assertIsNone(corr_unknown)

    def test_dns_intelligence_classification(self):
        # 1. Known Good Infrastructure
        cat, _, _ = dns_intel_engine.classify_domain("time.google.com")
        self.assertEqual(cat, "KNOWN_GOOD")

        # 2. Known Vendor Cloud
        cat, _, _ = dns_intel_engine.classify_domain("dev.hik-connect.com")
        self.assertEqual(cat, "KNOWN_VENDOR")

        # 3. Internal LAN / mDNS
        cat, _, _ = dns_intel_engine.classify_domain("printer.local")
        self.assertEqual(cat, "INTERNAL")

        # 4. Confirmed Threat Intelligence C2 Match
        cat, _, _ = dns_intel_engine.classify_domain("mirai-botnet.cc")
        self.assertEqual(cat, "THREAT_INTEL_MATCH")

        # 5. Dynamic DNS Suspicious
        cat, _, _ = dns_intel_engine.classify_domain("c2broker.duckdns.org")
        self.assertEqual(cat, "SUSPICIOUS")

    def test_synthetic_mud_baseline_and_behavioral_drift(self):
        with app.app_context():
            asset = Asset(
                tenant_id="tenant_enterprise",
                user_id=self.user.id,
                ip_address="192.168.1.200",
                mac_address="50:C7:BF:00:11:22",
                vendor="TP-Link",
                device_type="Smart Plug"
            )
            db.session.add(asset)
            db.session.commit()

            start_time = datetime.utcnow()

            # Phase 1: Ingest normal flows during 48h LEARNING period
            flow1 = {"src_ip": "192.168.1.200", "dst_ip": "192.168.1.1", "dst_port": 53, "protocol": "UDP", "domain": "time.google.com"}
            flow2 = {"src_ip": "192.168.1.200", "dst_ip": "52.20.10.5", "dst_port": 443, "protocol": "TCP", "domain": "tplinkcloud.com"}

            behavioral_engine.process_telemetry_flow("tenant_enterprise", asset, flow1, now=start_time)
            behavioral_engine.process_telemetry_flow("tenant_enterprise", asset, flow2, now=start_time)

            baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id).first()
            self.assertEqual(baseline.status, "LEARNING")
            self.assertIn("192.168.1.1", json.loads(baseline.allowed_destinations))
            self.assertIn("52.20.10.5", json.loads(baseline.allowed_destinations))

            # Phase 2: Advance time past 48h learning window -> STABLE
            day3_time = start_time + timedelta(hours=49)
            
            # Flow matching baseline -> No drift
            res_normal = behavioral_engine.process_telemetry_flow("tenant_enterprise", asset, flow2, now=day3_time)
            self.assertIsNone(res_normal)
            self.assertEqual(baseline.status, "STABLE")

            # Phase 3: Observe anomalous outbound egress to unknown external IP
            anomalous_flow = {
                "src_ip": "192.168.1.200",
                "dst_ip": "203.0.113.88",
                "dst_port": 9001,
                "protocol": "TCP",
                "domain": "unfamiliar-broker.com"
            }
            drift_event = behavioral_engine.process_telemetry_flow("tenant_enterprise", asset, anomalous_flow, now=day3_time)
            
            self.assertIsNotNone(drift_event)
            self.assertEqual(drift_event.drift_type, "new_destination_ip")
            self.assertEqual(baseline.status, "DRIFT_DETECTED")

            # Check that an Alert was automatically generated
            alert = Alert.query.filter_by(asset_id=asset.id, alert_type="behavioral_drift").first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.status, "OPEN")
            self.assertIn("203.0.113.88", alert.description)

    def test_pri_v2_risk_calculation_with_behavioral_penalties(self):
        asset_dict = {"vendor": "Hikvision", "device_type": "IP Camera", "criticality": "tier_1"}
        vulns = [{"cvss_score": 7.5, "cisa_kev": False, "epss_score": 0.20}]

        # 1. Baseline calculation without behavioral anomalies
        pri_clean = exposure_engine.calculate_pri(asset_dict, vulns, behavioral_penalties=0.0)
        self.assertEqual(pri_clean["risk_model_version"], "pri-v2")
        score_clean = pri_clean["pri_score"]

        # 2. Re-calculation with evidence-backed behavioral drift (+0.6)
        pri_drift = exposure_engine.calculate_pri(asset_dict, vulns, behavioral_penalties=0.6)
        self.assertGreater(pri_drift["pri_score"], score_clean)
        self.assertEqual(pri_drift["behavioral_penalty"], 0.6)

    def test_containment_state_machine_strict_transitions(self):
        # Valid Transitions
        s1 = containment_engine.transition_state("DRAFT", "PREVIEWED")
        self.assertEqual(s1, "PREVIEWED")

        s2 = containment_engine.transition_state("PREVIEWED", "VALIDATED")
        self.assertEqual(s2, "VALIDATED")

        s3 = containment_engine.transition_state("VALIDATED", "APPROVED")
        self.assertEqual(s3, "APPROVED")

        s4 = containment_engine.transition_state("APPROVED", "APPLYING")
        self.assertEqual(s4, "APPLYING")

        s5 = containment_engine.transition_state("APPLYING", "VERIFIED")
        self.assertEqual(s5, "VERIFIED")

        # Invalid Transition: DRAFT -> VERIFIED MUST FAIL
        with self.assertRaises(ValueError):
            containment_engine.transition_state("DRAFT", "VERIFIED")

        # Invalid Transition: APPROVED -> ROLLED_BACK MUST FAIL
        with self.assertRaises(ValueError):
            containment_engine.transition_state("APPROVED", "ROLLED_BACK")

    def test_containment_verification_states(self):
        intent = {
            "reason": "High PRI Exposure Containment",
            "allowed_destinations": ["192.168.1.1:53"],
            "blocked_destinations": ["0.0.0.0/0"]
        }
        # pfSense provider verification
        verified, msg = containment_engine.execute_verify(intent, "192.168.1.50", provider_name="pfsense")
        self.assertTrue(verified)
        self.assertIn("active filter state confirmed", msg)

    def test_alert_lifecycle_and_deduplication(self):
        with app.app_context():
            # 1. Create Alert
            alert1 = alert_engine.create_alert(
                tenant_id="tenant_enterprise",
                alert_type="suspicious_dns",
                severity="high",
                title="Suspicious Dynamic DNS Egress",
                description="Device queried duckdns endpoint",
                evidence={"domain": "test.duckdns.org"},
                asset_id=1
            )
            self.assertEqual(alert1.status, "OPEN")

            # 2. Duplicate Alert inside 1 hour -> deduplicated
            alert2 = alert_engine.create_alert(
                tenant_id="tenant_enterprise",
                alert_type="suspicious_dns",
                severity="high",
                title="Suspicious Dynamic DNS Egress",
                description="Repeated query",
                evidence={"domain": "test.duckdns.org"},
                asset_id=1
            )
            self.assertEqual(alert1.id, alert2.id)

            # 3. Acknowledge Alert
            ack = alert_engine.acknowledge_alert(alert1.id, self.user.id, "tenant_enterprise")
            self.assertEqual(ack.status, "ACKNOWLEDGED")

            # 4. Resolve Alert
            res = alert_engine.resolve_alert(alert1.id, self.user.id, "tenant_enterprise")
            self.assertEqual(res.status, "RESOLVED")
            self.assertIsNotNone(res.resolved_at)

    def test_canonical_device_trust_profile_aggregation(self):
        with app.app_context():
            asset = Asset(
                tenant_id="tenant_enterprise",
                user_id=self.user.id,
                ip_address="192.168.1.110",
                mac_address="00:12:17:11:22:33",
                vendor="Hikvision",
                model="DS-2CD2042WD-I",
                device_type="IP Camera",
                identity_confidence=0.88
            )
            db.session.add(asset)
            db.session.commit()

            profile = asset.get_trust_profile()
            
            # Validate 11 core categories exist in Trust Profile
            self.assertIn("identity", profile)
            self.assertIn("network", profile)
            self.assertIn("services", profile)
            self.assertIn("vulnerabilities", profile)
            self.assertIn("exposure", profile)
            self.assertIn("behavior", profile)
            self.assertIn("risk", profile)
            self.assertIn("remediation", profile)
            self.assertIn("alerts", profile)
            self.assertEqual(profile["identity"]["vendor"], "Hikvision")
            self.assertEqual(profile["identity"]["identity_confidence"], 0.88)

    def test_e2e_continuous_security_loop(self):
        """
        Complete E2E Demonstration:
        Sensor Registration -> Telemetry Ingest -> Asset Correlation -> Baseline Learning ->
        Drift -> Alert -> PRI-v2 Update -> Containment Recommendation -> Approval -> Apply -> Verification.
        """
        with app.app_context():
            # 1. Register Sensor
            collector, token = telemetry_engine.register_collector(
                tenant_id="tenant_enterprise", site_id="hq", name="Sensor_E2E"
            )

            # 2. Discover Asset
            asset = Asset(
                tenant_id="tenant_enterprise",
                user_id=self.user.id,
                ip_address="10.0.1.75",
                mac_address="00:12:17:EE:FF:00",
                vendor="Hikvision",
                device_type="IP Camera",
                identity_confidence=0.90
            )
            db.session.add(asset)
            db.session.commit()

            # 3. Stream Telemetry via API
            telemetry_payload = [
                {"src_ip": "10.0.1.75", "dst_ip": "10.0.1.1", "dst_port": 53, "protocol": "UDP", "domain": "time.google.com"},
                {"src_ip": "10.0.1.75", "dst_ip": "198.51.100.22", "dst_port": 443, "protocol": "TCP", "domain": "hik-connect.com"}
            ]
            res = self.app.post("/api/v2/telemetry/ingest", json=telemetry_payload, headers={"X-Sensor-Token": token})
            self.assertEqual(res.status_code, 200)

            # 4. Advance baseline past learning and inject rogue drift flow
            baseline = BehavioralBaseline.query.filter_by(asset_id=asset.id).first()
            baseline.status = "STABLE"
            baseline.allowed_destinations = json.dumps(["10.0.1.1", "198.51.100.22"])
            db.session.commit()

            rogue_flow = [{"src_ip": "10.0.1.75", "dst_ip": "203.0.113.99", "dst_port": 6667, "protocol": "TCP"}]
            self.app.post("/api/v2/telemetry/ingest", json=rogue_flow, headers={"X-Sensor-Token": token})

            # Verify Drift Event & Alert Generated
            drift = BehavioralDriftEvent.query.filter_by(asset_id=asset.id).first()
            self.assertIsNotNone(drift)
            self.assertEqual(drift.drift_type, "new_destination_ip")

            # 5. Create Containment Intent
            intent_data = containment_engine.create_intent_for_asset(asset, {"pri_score": 8.5, "pri_level": "critical", "cisa_kev_boost": 1.5})
            intent = ContainmentIntent(
                tenant_id="tenant_enterprise",
                asset_id=asset.id,
                reason=intent_data["reason"],
                status="APPROVED",
                applied_provider="pfsense"
            )
            db.session.add(intent)
            db.session.commit()

            # 6. Apply Containment via API
            apply_res = self.app.post(f"/api/v2/assets/{asset.id}/containment/apply", headers=self.headers)
            self.assertEqual(apply_res.status_code, 200)
            data = apply_res.get_json()
            self.assertEqual(data["containment"]["status"], "VERIFIED")

    def test_device_trust_profile_sub_endpoints(self):
        with app.app_context():
            asset = Asset(
                tenant_id="tenant_enterprise",
                user_id=self.user.id,
                ip_address="10.0.2.55",
                mac_address="00:12:17:33:44:55",
                vendor="Hikvision"
            )
            db.session.add(asset)
            db.session.commit()
            aid = asset.id

        # 1. Observations endpoint
        res = self.app.get(f"/api/v2/assets/{aid}/observations", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("observations", res.get_json())

        # 2. Behavior endpoint
        res = self.app.get(f"/api/v2/assets/{aid}/behavior", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("drifts", res.get_json())

        # 3. Traffic endpoint
        res = self.app.get(f"/api/v2/assets/{aid}/traffic", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("flows", res.get_json())

        # 4. Alerts endpoint
        res = self.app.get(f"/api/v2/assets/{aid}/alerts", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("alerts", res.get_json())

        # 5. Timeline endpoint
        res = self.app.get(f"/api/v2/assets/{aid}/timeline", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("timeline", res.get_json())

    def test_alert_detail_and_scheduler_lifecycle(self):
        with app.app_context():
            # Create Alert
            alert = alert_engine.create_alert(
                tenant_id="tenant_enterprise",
                alert_type="behavioral_drift",
                severity="high",
                title="Rogue Outbound Flow",
                description="Observed communication to external IP",
                evidence={"dst_ip": "198.51.100.99"},
                asset_id=1
            )
            alert_id = alert.id

        # Query Alert Detail
        res = self.app.get(f"/api/v2/alerts/{alert_id}", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["alert"]["title"], "Rogue Outbound Flow")

        # Create Scheduled Scan
        sched_payload = {
            "target_scope": "192.168.1.0/24",
            "profile": "safe",
            "frequency": "daily"
        }
        res = self.app.post("/api/v2/scheduled-scans", json=sched_payload, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.get_json()["schedule"]["frequency"], "daily")

        # List Scheduled Scans
        res = self.app.get("/api/v2/scheduled-scans", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(len(res.get_json()["schedules"]) >= 1)

    def test_three_device_continuous_telemetry_loop(self):
        """
        Test 3 distinct IoT devices:
        Device A: Camera (RTSP / Port 554)
        Device B: Smart Plug (MQTT / Port 1883)
        Device C: Unknown IoT device with unclassified DNS
        """
        with app.app_context():
            collector, token = telemetry_engine.register_collector(
                tenant_id="tenant_enterprise", site_id="plant_1", name="Floor_Sensor"
            )

            # Device A: Camera
            dev_a = Asset(tenant_id="tenant_enterprise", user_id=self.user.id, ip_address="10.10.1.10", mac_address="00:12:17:11:11:11", vendor="Hikvision", device_type="IP Camera")
            # Device B: Smart Plug
            dev_b = Asset(tenant_id="tenant_enterprise", user_id=self.user.id, ip_address="10.10.1.20", mac_address="50:C7:BF:22:22:22", vendor="TP-Link", device_type="Smart Plug")
            # Device C: Unknown IoT
            dev_c = Asset(tenant_id="tenant_enterprise", user_id=self.user.id, ip_address="10.10.1.30", mac_address="94:E6:86:33:33:33", vendor="Unknown", device_type="Generic IoT")
            db.session.add_all([dev_a, dev_b, dev_c])
            db.session.commit()

            batch = [
                {"src_ip": "10.10.1.10", "dst_ip": "10.10.1.1", "dst_port": 554, "protocol": "TCP"},
                {"src_ip": "10.10.1.20", "dst_ip": "52.20.10.5", "dst_port": 1883, "protocol": "TCP"},
                {"src_ip": "10.10.1.30", "dst_ip": "1.1.1.1", "dst_port": 53, "protocol": "UDP", "domain": "mozi-dht-seed.org"}
            ]

            res = self.app.post("/api/v2/telemetry/ingest", json=batch, headers={"X-Sensor-Token": token})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["correlated_assets"], 3)

            # Check that Device C's Mozi C2 domain generated a critical alert
            c2_alert = Alert.query.filter_by(asset_id=dev_c.id, alert_type="threat_intel_dns_match").first()
            self.assertIsNotNone(c2_alert)
            self.assertEqual(c2_alert.severity, "critical")


if __name__ == '__main__':
    unittest.main()
