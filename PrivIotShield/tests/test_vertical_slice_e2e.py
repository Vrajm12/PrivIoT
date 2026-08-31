import unittest
import json
from app import app, db
from models import User, Asset, AssetService, RiskAssessment, ContainmentIntent, AuditEvent, ScanJob
from fingerprint_pipeline import fingerprint_pipeline
from exposure_engine import exposure_engine
from vuln_intel import vuln_engine

class TestVerticalSliceE2E(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user = User(username='e2e_admin', email='admin@priviot.io', password_hash='hash123')
            db.session.add(self.user)
            db.session.commit()
            self.user_id = self.user.id
            self.api_key = self.user.api_key
            self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_full_e2e_vertical_slice_pipeline(self):
        with app.app_context():
            # 1. Simulate safe observation from discovery
            obs = {
                "ip_address": "192.168.1.150",
                "mac_address": "00:12:17:88:99:AA",
                "open_ports": [80, 554, 8000],
                "banners": {"8000/http": "Hikvision Web Server"},
                "tls_cert": {"subject_cn": "hikvision.camera.internal"},
                "upnp_info": {"manufacturer": "Hikvision", "model": "DS-2CD2042WD-I", "device_type": "IP Camera"}
            }

            # 2. Asset Reconciliation
            asset, is_new = fingerprint_pipeline.reconcile_asset(db.session, self.user_id, obs, network_scope="192.168.1.0/24")
            self.assertTrue(is_new)
            self.assertEqual(asset.vendor, "Hikvision")
            self.assertEqual(asset.model, "DS-2CD2042WD-I")
            self.assertTrue(asset.identity_confidence >= 0.85)
            self.assertEqual(asset.services.count(), 3)

            # 3. Vulnerability Matching
            device_dict = {
                "manufacturer": asset.vendor,
                "model": asset.model,
                "device_type": asset.device_type,
                "open_ports": [80, 554, 8000],
                "services": ["http", "rtsp", "custom"]
            }
            vulns = vuln_engine.get_vulnerabilities_for_device(device_dict)
            self.assertTrue(len(vulns) >= 2)
            cve_ids = [v["cve_id"] for v in vulns]
            self.assertIn("CVE-2021-36260", cve_ids)

            # 4. Exposure & PRI Scoring
            pri = exposure_engine.calculate_pri(
                asset_dict={"criticality": asset.criticality, "device_type": asset.device_type},
                vulnerabilities=vulns,
                network_placement="flat_lan"
            )
            self.assertTrue(pri["pri_score"] >= 8.0)
            self.assertEqual(pri["pri_level"], "critical")
            self.assertEqual(pri["cisa_kev_boost"], 1.5)

            # 5. Save Risk Assessment
            risk = RiskAssessment(
                asset_id=asset.id,
                threat_base=pri["threat_base"],
                cisa_kev_boost=pri["cisa_kev_boost"],
                epss_signal=pri["epss_signal"],
                exposure_factor=pri["exposure_factor"],
                criticality_weight=pri["criticality_weight"],
                pri_score=pri["pri_score"],
                pri_level=pri["pri_level"],
                explanation_json=json.dumps(pri["explanation"])
            )
            db.session.add(risk)
            db.session.commit()
            asset_id = asset.id

        # 6. Test REST API v2 endpoints
        # 6a. GET /api/v2/assets
        res = self.app.get("/api/v2/assets", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["assets"][0]["vendor"], "Hikvision")

        # 6b. GET /api/v2/assets/{id}
        res = self.app.get(f"/api/v2/assets/{asset_id}", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["asset"]["ip_address"], "192.168.1.150")
        self.assertEqual(len(data["services"]), 3)
        self.assertEqual(data["latest_risk"]["pri_level"], "critical")

        # 6c. POST /api/v2/assets/{id}/containment/preview
        res = self.app.post(f"/api/v2/assets/{asset_id}/containment/preview", data=json.dumps({"provider": "pfsense"}), headers=self.headers)
        self.assertEqual(res.status_code, 200)
        preview_data = res.get_json()
        self.assertIn("expected_impact", preview_data["preview"])
        self.assertIn("easyrule block lan any 192.168.1.150", preview_data["preview"]["proposed_policy"])

        # 6d. POST /api/v2/assets/{id}/containment/approve
        res = self.app.post(f"/api/v2/assets/{asset_id}/containment/approve", data=json.dumps({"provider": "pfsense"}), headers=self.headers)
        self.assertEqual(res.status_code, 200)
        approve_data = res.get_json()
        self.assertEqual(approve_data["containment"]["status"], "approved")

        # 6e. POST /api/v2/assets/{id}/containment/rollback
        res = self.app.post(f"/api/v2/assets/{asset_id}/containment/rollback", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        rollback_data = res.get_json()
        self.assertEqual(rollback_data["containment"]["status"], "rolled_back")
        self.assertIn("pfctl -k 192.168.1.150", rollback_data["rollback_script"])

        # 6f. GET /api/v2/audit-logs
        res = self.app.get("/api/v2/audit-logs", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        audit_data = res.get_json()
        actions = [ev["action"] for ev in audit_data["events"]]
        self.assertIn("asset_created", actions)
        self.assertIn("containment_previewed", actions)
        self.assertIn("containment_approved", actions)
        self.assertIn("containment_rolled_back", actions)

if __name__ == '__main__':
    unittest.main()
