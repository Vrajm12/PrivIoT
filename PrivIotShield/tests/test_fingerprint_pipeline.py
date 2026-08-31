import unittest
import json
from app import app, db
from models import User, Asset, AssetService
from fingerprint_pipeline import FingerprintPipeline

class TestFingerprintPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = FingerprintPipeline()
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user = User(username='fp_user', email='fp@priviot.io', password_hash='hash123')
            db.session.add(self.user)
            db.session.commit()
            self.user_id = self.user.id

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_evidence_weighted_fingerprint(self):
        obs = {
            "ip_address": "192.168.1.50",
            "mac_address": "00:12:17:44:55:66",
            "open_ports": [80, 554, 8000],
            "banners": {"8000/http": "Hikvision Digital Technology DVR/DVS"},
            "tls_cert": {"subject_cn": "hikvision.camera.local", "issuer_cn": "Hikvision CA"},
            "upnp_info": {"manufacturer": "Hikvision", "model": "DS-2CD2042WD-I", "device_type": "IP Camera"}
        }
        fp = self.pipeline.process_observation(obs)
        self.assertEqual(fp["vendor"], "Hikvision")
        self.assertTrue(fp["confidence"] >= 0.80)
        self.assertTrue(len(fp["evidence"]["claims"]) >= 3)

    def test_deterministic_asset_reconciliation_no_duplicates(self):
        obs = {
            "ip_address": "192.168.1.100",
            "mac_address": "00:12:17:AA:BB:CC",
            "open_ports": [554, 80],
            "banners": {},
            "tls_cert": None,
            "upnp_info": {"manufacturer": "Dahua", "model": "DH-IPC-HFW"}
        }
        with app.app_context():
            # First reconciliation -> Creates asset
            asset1, is_new1 = self.pipeline.reconcile_asset(db.session, self.user_id, obs)
            self.assertTrue(is_new1)
            self.assertEqual(asset1.vendor, "Dahua")
            self.assertEqual(asset1.services.count(), 2)

            # Second reconciliation with same MAC but new port -> Updates existing asset
            obs["open_ports"] = [554, 80, 37777]
            asset2, is_new2 = self.pipeline.reconcile_asset(db.session, self.user_id, obs)
            self.assertFalse(is_new2)
            self.assertEqual(asset1.id, asset2.id)
            self.assertEqual(Asset.query.count(), 1)
            self.assertEqual(asset2.services.count(), 3)

if __name__ == '__main__':
    unittest.main()
