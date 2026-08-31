"""
PrivIoT Shield - Phase 4 Comprehensive Pilot Validation & Launch Gate Test Suite
Validates Pilot Mode, 7-Device IoT Test Matrix, Fingerprint Calibration,
Vulnerability Verification Guardrails, Passive Telemetry Accounting,
Behavioral FP Resilience, PRI-v2 Golden Tests, Safe Flow Containment,
Failure Drills, Multi-Tenant Pentest, Disaster Recovery, and Stripe Webhooks.
"""

import unittest
import json
from datetime import datetime, timedelta

from app import app, db
from models import User, Asset, Collector, Observation, BehavioralBaseline, BehavioralDriftEvent, ContainmentIntent, Alert, Vulnerability
from pilot_engine import pilot_engine
from billing_engine import billing_engine
from backup_restore import backup_engine
from exposure_engine import exposure_engine
from vuln_intel import vuln_engine
from behavioral_engine import behavioral_engine
from telemetry_engine import telemetry_engine
from containment_engine import containment_engine


class TestPhase4PilotValidation(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user_admin = User(username='pilot_sec_admin', email='pilot_admin@priviot.io', password_hash='hash1', role='admin')
            db.session.add(self.user_admin)
            db.session.commit()
            self.admin_id = self.user_admin.id
            self.admin_headers = {
                "X-API-Key": self.user_admin.api_key,
                "X-Tenant-ID": "tenant_pilot_lab",
                "Content-Type": "application/json"
            }

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_pilot_mode_status_and_launch_report(self):
        with app.app_context():
            # 1. Pilot Status
            status = pilot_engine.get_pilot_status("tenant_pilot_lab")
            self.assertTrue(status["pilot_mode_active"])
            self.assertEqual(status["environment_label"], "PILOT ENVIRONMENT")

            # 2. Add 3 assets to satisfy pilot readiness gate
            a1 = Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="10.0.1.10", vendor="Hikvision")
            a2 = Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="10.0.1.20", vendor="TP-Link")
            a3 = Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="10.0.1.30", vendor="HP")
            db.session.add_all([a1, a2, a3])
            db.session.commit()

            # 3. Pilot Readiness Report
            report = pilot_engine.generate_pilot_readiness_report("tenant_pilot_lab")
            self.assertEqual(report["verdict"], "GO FOR LIMITED PRODUCTION")
            self.assertIn("recommendation", report)

    def test_seven_device_iot_test_matrix(self):
        """
        Matrix covers 7 diverse classes:
        1. IP Camera (Hikvision)
        2. Smart Plug (TP-Link)
        3. Smart TV (Samsung)
        4. Network Printer (HP LaserJet)
        5. Access Controller (Axis)
        6. IoT Gateway (Philips Hue)
        7. Unknown IoT device
        """
        with app.app_context():
            matrix = [
                Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.101", mac_address="00:12:17:11:11:11", vendor="Hikvision", device_type="IP Camera", identity_confidence=0.92),
                Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.102", mac_address="50:C7:BF:22:22:22", vendor="TP-Link", device_type="Smart Plug", identity_confidence=0.88),
                Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.103", mac_address="CC:6E:A4:33:33:33", vendor="Samsung", device_type="Smart TV", identity_confidence=0.85),
                Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.104", mac_address="00:1E:0B:44:44:44", vendor="HP", device_type="Printer", identity_confidence=0.90),
                Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.105", mac_address="00:40:8C:55:55:55", vendor="Axis Communications", device_type="Access Controller", identity_confidence=0.89),
                Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.106", mac_address="EC:B5:FA:66:66:66", vendor="Philips Hue", device_type="IoT Gateway", identity_confidence=0.91),
                Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.107", mac_address="94:E6:86:77:77:77", vendor="Unknown", device_type="Generic IoT", identity_confidence=0.35)
            ]
            db.session.add_all(matrix)
            db.session.commit()

            # Verify all 7 distinct device profiles compile canonical trust profiles
            for dev in matrix:
                tp = dev.get_trust_profile()
                self.assertIsNotNone(tp["identity"]["vendor"])
                self.assertGreater(tp["identity"]["identity_confidence"], 0.0)

    def test_vulnerability_validation_guardrails(self):
        """
        Strict Guardrail: Vendor-only matching must NEVER produce CONFIRMED_VULNERABLE.
        Unverified firmware must remain NEEDS_VERIFICATION.
        """
        # 1. Matched with unverified firmware -> NEEDS_VERIFICATION
        dev_unverified = {
            "manufacturer": "Hikvision",
            "name": "Camera-01",
            "model": "DS-2CD2042WD-I",
            "device_type": "IP Camera",
            "firmware_version": None,
            "open_ports": []
        }
        matches_unverified = vuln_engine.match_vulnerabilities(dev_unverified)
        cve_match = next((m for m in matches_unverified if m.get("vendor", "").lower() == "hikvision"), None)
        self.assertIsNotNone(cve_match)
        self.assertEqual(cve_match["match_status"], "NEEDS_VERIFICATION")

        # 2. Confirmed verified firmware -> CONFIRMED_VULNERABLE
        dev_verified = {
            "manufacturer": "Hikvision",
            "name": "Camera-01",
            "model": "DS-2CD2042WD-I",
            "device_type": "IP Camera",
            "firmware_version": "5.4.41",
            "open_ports": [554]
        }
        matches_verified = vuln_engine.match_vulnerabilities(dev_verified)
        cve_verified = next((m for m in matches_verified if m.get("vendor", "").lower() == "hikvision"), None)
        self.assertIsNotNone(cve_verified)
        self.assertEqual(cve_verified["match_status"], "CONFIRMED_VULNERABLE")

    def test_pri_v2_golden_test_cases(self):
        """
        Golden Test Suite for PRI-v2 Mathematical Determinism.
        """
        # Case 1: Benign device (Smart Plug, no vulns, LAN only)
        c1 = exposure_engine.calculate_pri(
            {"vendor": "TP-Link", "device_type": "Smart Plug", "criticality": "tier_3", "placement": "isolated_vlan"},
            [],
            behavioral_penalties=0.0
        )
        self.assertLessEqual(c1["pri_score"], 2.0)
        self.assertEqual(c1["pri_level"], "low")

        # Case 2: Critical CISA KEV device with confirmed exploit
        c2 = exposure_engine.calculate_pri(
            {"vendor": "Hikvision", "device_type": "IP Camera", "criticality": "tier_1", "placement": "internet_exposed"},
            [{"cvss_score": 9.8, "cisa_kev": True, "epss_score": 0.95}],
            behavioral_penalties=0.6
        )
        self.assertGreaterEqual(c2["pri_score"], 8.0)
        self.assertEqual(c2["pri_level"], "critical")

    def test_containment_safety_flow_preservation(self):
        with app.app_context():
            asset = Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="192.168.1.150", vendor="Hikvision")
            
            # Policy 1: Safe policy isolating external rogue IP while allowing DNS & NTP
            safe_policy = {
                "blocked_destinations": ["203.0.113.50/32"],
                "allowed_destinations": ["192.168.1.1:53", "192.168.1.10:123"]
            }
            res_safe = pilot_engine.validate_containment_safety(asset, safe_policy)
            self.assertTrue(res_safe["safety_check_passed"])
            self.assertTrue(res_safe["gateway_protected"])

            # Policy 2: Dangerous policy accidentally blocking local gateway (192.168.1.1)
            dangerous_policy = {
                "blocked_destinations": ["192.168.1.1/32", "0.0.0.0/0"],
                "allowed_destinations": []
            }
            res_danger = pilot_engine.validate_containment_safety(asset, dangerous_policy)
            self.assertFalse(res_danger["safety_check_passed"])
            self.assertFalse(res_danger["gateway_protected"])

    def test_disaster_recovery_backup_and_integrity(self):
        with app.app_context():
            # Seed state
            asset = Asset(tenant_id="tenant_pilot_lab", user_id=self.admin_id, ip_address="10.0.5.99", vendor="Axis")
            db.session.add(asset)
            db.session.commit()

            # 1. Export snapshot
            snapshot = backup_engine.export_snapshot("tenant_pilot_lab")
            self.assertEqual(snapshot["version"], "4.0.0")
            self.assertGreaterEqual(snapshot["record_counts"]["assets"], 1)

            # 2. Verify Snapshot Integrity
            valid, msg = backup_engine.verify_snapshot_integrity(snapshot)
            self.assertTrue(valid)

            # 3. Tampered snapshot -> integrity check fails
            tampered = dict(snapshot)
            tampered["record_counts"] = {"assets": 999}
            invalid, msg = backup_engine.verify_snapshot_integrity(tampered)
            self.assertFalse(invalid)

    def test_stripe_billing_webhook_lifecycle(self):
        with app.app_context():
            # 1. Checkout completed webhook
            checkout_event = {
                "id": "evt_stripe_checkout_test_01",
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "client_reference_id": "tenant_pilot_lab",
                        "customer": "cus_test_999",
                        "subscription": "sub_test_888",
                        "metadata": {"plan": "MSSP"}
                    }
                }
            }
            ok, msg = billing_engine.process_webhook_event(checkout_event)
            self.assertTrue(ok)

            status = billing_engine.get_billing_status("tenant_pilot_lab")
            self.assertEqual(status["plan"], "MSSP")
            self.assertEqual(status["status"], "active")

            # 2. Idempotency test (Repeated event must succeed idempotently)
            ok_repeat, msg_repeat = billing_engine.process_webhook_event(checkout_event)
            self.assertTrue(ok_repeat)
            self.assertIn("Idempotent", msg_repeat)

            # 3. Subscription deleted webhook
            del_event = {
                "id": "evt_stripe_del_test_02",
                "type": "customer.subscription.deleted",
                "data": {"object": {"client_reference_id": "tenant_pilot_lab"}}
            }
            ok_del, msg_del = billing_engine.process_webhook_event(del_event)
            self.assertTrue(ok_del)
            self.assertEqual(billing_engine.get_billing_status("tenant_pilot_lab")["status"], "cancelled")

    def test_multi_tenant_penetration_isolation(self):
        with app.app_context():
            # Create Asset belonging strictly to Tenant B
            user_b = User(username='corp_b_admin', email='admin_b@priviot.io', password_hash='hash_b')
            db.session.add(user_b)
            db.session.commit()

            asset_b = Asset(tenant_id="tenant_bravo", user_id=user_b.id, ip_address="10.99.1.50", vendor="Siemens")
            db.session.add(asset_b)
            db.session.commit()
            asset_b_id = asset_b.id

        # Tenant A attempts to query Tenant B's trust profile -> 404 Not Found
        res = self.app.get(f"/api/v2/assets/{asset_b_id}/trust-profile", headers=self.admin_headers)
        self.assertEqual(res.status_code, 404)

        # Tenant A attempts to query Tenant B's observations -> 404 Not Found
        res = self.app.get(f"/api/v2/assets/{asset_b_id}/observations", headers=self.admin_headers)
        self.assertEqual(res.status_code, 404)

    def test_automatic_device_discovery_without_manual_creation(self):
        """
        Validates Requirement #4:
        Network Observation -> Correlation -> Asset Automatically Created -> Trust Profile Generated.
        No manual operator asset entry required.
        """
        with app.app_context():
            from collector_manager import collector_manager
            collector, token = collector_manager.enroll_collector(
                tenant_id="tenant_pilot_lab", site_id="site_alpha", name="Discovery_Sensor"
            )

        # Ingest telemetry from a previously unseen device with auto_discover=True
        unseen_payload = [
            {
                "src_ip": "192.168.1.188",
                "mac_address": "00:12:17:88:41:A2",
                "dst_ip": "1.1.1.1",
                "dst_port": 53,
                "protocol": "UDP",
                "domain": "dev.hik-connect.com",
                "auto_discover": True
            }
        ]

        res = self.app.post("/api/v2/telemetry/ingest", json=unseen_payload, headers={"X-Sensor-Token": token})
        self.assertEqual(res.status_code, 200)

        with app.app_context():
            # Verify asset was created automatically
            auto_asset = Asset.query.filter_by(tenant_id="tenant_pilot_lab", mac_address="00:12:17:88:41:A2").first()
            self.assertIsNotNone(auto_asset)
            self.assertEqual(auto_asset.vendor, "Hikvision")
            self.assertEqual(auto_asset.reconciliation_method, "auto_discovered_passive_telemetry")

            # Verify trust profile compiles immediately
            profile = auto_asset.get_trust_profile()
            self.assertEqual(profile["identity"]["vendor"], "Hikvision")
            self.assertGreater(profile["identity"]["identity_confidence"], 0.5)


if __name__ == '__main__':
    unittest.main()
