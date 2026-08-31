import unittest
import json
from app import app
from extensions import db
from models import User, Device, Scan
from security_scanner import scan_device

class TestPrivIoTIntegration(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user = User(username='test_engineer', email='test@priviot.io', password_hash='hash123')
            db.session.add(self.user)
            db.session.commit()
            self.api_key = self.user.api_key

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_production_scan_pipeline(self):
        with app.app_context():
            device = Device(
                name="Office Hikvision Camera",
                device_type="Smart Camera",
                manufacturer="Hikvision",
                model="DS-2CD2042WD-I",
                firmware_version="5.4.0",
                ip_address="192.168.1.88",
                user_id=self.user.id
            )
            db.session.add(device)
            db.session.commit()

            # Execute scan
            results = scan_device(device)
            self.assertIn("vulnerabilities", results)
            self.assertIn("compliance_audit", results)
            self.assertIn("remediation_scripts", results)
            self.assertTrue(len(results["vulnerabilities"]) >= 1)
            self.assertIn("iptables", results["remediation_scripts"])
            self.assertIn("etsi_en_303_645", results["compliance_audit"])

    def test_api_v2_intelligence_lookup(self):
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        payload = {
            "name": "Tapo Smart Bulb",
            "manufacturer": "TP-Link",
            "model": "L530E",
            "device_type": "Smart Bulb"
        }
        res = self.app.post("/api/v2/intelligence/lookup", data=json.dumps(payload), headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(len(data["vulnerabilities"]) >= 1)
        self.assertIn("risk_profile", data)

    def test_api_v2_compliance_audit(self):
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        payload = {
            "name": "Smart Lock",
            "device_type": "Smart Lock",
            "manufacturer": "Generic",
            "open_ports": [80, 23]
        }
        res = self.app.post("/api/v2/compliance/audit", data=json.dumps(payload), headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("compliance_audit", data)
        self.assertIn("etsi_en_303_645", data["compliance_audit"])

if __name__ == '__main__':
    unittest.main()
