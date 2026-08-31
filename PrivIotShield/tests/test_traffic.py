import unittest
import json
from traffic_auditor import TrafficAuditor
from app import app
from extensions import db
from models import User

class TestTrafficAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = TrafficAuditor()
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user = User(username='traffic_tester', email='traffic@priviot.io', password_hash='hash123')
            db.session.add(self.user)
            db.session.commit()
            self.api_key = self.user.api_key

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_cleartext_password_leak_detection(self):
        sample_packet = 'POST /login HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\nusername=admin&password=SecretPassword123&device_id=CAM_99281'
        result = self.auditor.audit_payload(sample_packet, protocol='HTTP')
        self.assertTrue(result['findings_count'] >= 2)
        titles = [f['title'] for f in result['findings']]
        self.assertIn('Cleartext Password Exposure', titles)
        self.assertEqual(result['risk_score'], 9.5)

    def test_suspicious_dns_traffic_detection(self):
        domains = [
            'time.google.com',
            'api.tuyaus.com',
            'dev.hik-connect.com',
            'pool.ntp.org'
        ]
        result = self.auditor.audit_dns_traffic(domains, device_name='Front Camera')
        self.assertEqual(result['suspicious_queries_count'], 2)
        self.assertIn(result['privacy_rating'], ['POOR', 'FAIR'])

    def test_api_v2_traffic_payload_endpoint(self):
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        payload = {
            "payload": 'GET /stream?rtsp://admin:pass123@192.168.1.100:554/live HTTP/1.1',
            "protocol": "RTSP"
        }
        res = self.app.post("/api/v2/traffic/audit-payload", data=json.dumps(payload), headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["audit"]["findings_count"] >= 1)

if __name__ == '__main__':
    unittest.main()
