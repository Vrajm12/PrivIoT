import unittest
import json
from app import app, db
from models import User, Asset, AssetService, RiskAssessment, ContainmentIntent, AuditEvent
from fingerprint_pipeline import FingerprintPipeline
from vuln_intel import vuln_engine
from exposure_engine import exposure_engine
from containment_engine import containment_engine, validate_ip_address, validate_mac_address, sanitize_input_string

class TestAdversarialHardening(unittest.TestCase):
    def setUp(self):
        self.fp = FingerprintPipeline()
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            # Create Tenant A user
            self.user_a = User(username='tenant_a_user', email='a@priviot.io', password_hash='hash123')
            # Create Tenant B user
            self.user_b = User(username='tenant_b_user', email='b@priviot.io', password_hash='hash456')
            db.session.add_all([self.user_a, self.user_b])
            db.session.commit()
            self.key_a = self.user_a.api_key
            self.key_b = self.user_b.api_key
            self.headers_a = {"X-API-Key": self.key_a, "X-Tenant-ID": "tenant_a", "Content-Type": "application/json"}
            self.headers_b = {"X-API-Key": self.key_b, "X-Tenant-ID": "tenant_b", "Content-Type": "application/json"}

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_dhcp_ip_reassignment_conflict_handling(self):
        with app.app_context():
            # Day 1: 192.168.1.50 assigned to Hikvision Camera
            obs_day1 = {
                "ip_address": "192.168.1.50",
                "mac_address": "00:12:17:AA:BB:CC",
                "open_ports": [554, 8000],
                "upnp_info": {"manufacturer": "Hikvision", "model": "DS-2CD2042WD-I"}
            }
            asset1, is_new1 = self.fp.reconcile_asset(db.session, self.user_a.id, obs_day1, tenant_id="tenant_a")
            self.assertTrue(is_new1)
            self.assertEqual(asset1.vendor, "Hikvision")

            # Day 2: 192.168.1.50 reassigned by DHCP to a TP-Link Smart Plug (different MAC, different vendor)
            obs_day2 = {
                "ip_address": "192.168.1.50",
                "mac_address": "50:C7:BF:11:22:33",
                "open_ports": [9999],
                "banners": {"9999": "TP-Link Smart Home"}
            }
            asset2, is_new2 = self.fp.reconcile_asset(db.session, self.user_a.id, obs_day2, tenant_id="tenant_a")
            
            # Must NOT merge into Hikvision Camera! Must create new Asset for TP-Link
            self.assertTrue(is_new2)
            self.assertNotEqual(asset1.id, asset2.id)
            self.assertEqual(asset2.vendor, "TP-Link")
            self.assertEqual(Asset.query.filter_by(tenant_id="tenant_a").count(), 2)

    def test_multi_tenant_isolation_idor_prevention(self):
        with app.app_context():
            # Create Asset belonging to Tenant A
            asset_a = Asset(
                tenant_id="tenant_a",
                user_id=self.user_a.id,
                ip_address="10.0.1.50",
                mac_address="00:11:22:33:44:55",
                vendor="Hikvision"
            )
            db.session.add(asset_a)
            db.session.commit()
            asset_a_id = asset_a.id

        # Tenant B attempts to read Tenant A's asset -> Must return 404
        res = self.app.get(f"/api/v2/assets/{asset_a_id}", headers=self.headers_b)
        self.assertEqual(res.status_code, 404)

        # Tenant B attempts to preview containment on Tenant A's asset -> Must return 404
        res = self.app.post(f"/api/v2/assets/{asset_a_id}/containment/preview", data=json.dumps({"provider": "pfsense"}), headers=self.headers_b)
        self.assertEqual(res.status_code, 404)

        # Tenant A can access it cleanly
        res = self.app.get(f"/api/v2/assets/{asset_a_id}", headers=self.headers_a)
        self.assertEqual(res.status_code, 200)

    def test_threat_feed_health_and_version_match_status(self):
        # Test Feed Health Endpoint
        res = self.app.get("/api/v2/threat-intel/health", headers=self.headers_a)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["threat_intel_health"]["nvd_feed_status"], "HEALTHY")
        self.assertEqual(data["threat_intel_health"]["cisa_kev_status"], "HEALTHY")

        # Test Version Match Status
        # 1. Device with unverified firmware -> NEEDS_VERIFICATION
        unverified_dev = {
            "manufacturer": "Hikvision",
            "model": "DS-2CD2042WD-I",
            "firmware_version": "unknown",
            "device_type": "IP Camera",
            "open_ports": [554]
        }
        vulns_unverified = vuln_engine.match_vulnerabilities(unverified_dev)
        hik_cve = next((v for v in vulns_unverified if v["cve_id"] == "CVE-2021-36260"), None)
        self.assertIsNotNone(hik_cve)
        self.assertEqual(hik_cve["match_status"], "NEEDS_VERIFICATION")

        # 2. Device with confirmed vulnerable firmware -> CONFIRMED_VULNERABLE
        confirmed_dev = {
            "manufacturer": "Hikvision",
            "model": "DS-2CD2042WD-I",
            "firmware_version": "5.3.0",
            "device_type": "IP Camera",
            "open_ports": [554]
        }
        vulns_confirmed = vuln_engine.match_vulnerabilities(confirmed_dev)
        hik_cve_conf = next((v for v in vulns_confirmed if v["cve_id"] == "CVE-2021-36260"), None)
        self.assertEqual(hik_cve_conf["match_status"], "CONFIRMED_VULNERABLE")

    def test_command_injection_and_input_sanitization(self):
        # Invalid / Malicious IP with shell metacharacters
        with self.assertRaises(ValueError):
            validate_ip_address("192.168.1.50; rm -rf /")

        with self.assertRaises(ValueError):
            validate_ip_address("192.168.1.50 && cat /etc/passwd")

        # Invalid MAC with shell metacharacters
        with self.assertRaises(ValueError):
            validate_mac_address("00:11:22:33:44:55; reboot")

        # Sanitize comment
        clean = sanitize_input_string('Quarantine Camera `rm -rf /` ; reboot && echo "pwn"')
        self.assertNotIn("`", clean)
        self.assertNotIn(";", clean)
        self.assertNotIn("&", clean)

if __name__ == '__main__':
    unittest.main()
