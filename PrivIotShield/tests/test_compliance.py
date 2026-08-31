import unittest
from compliance_engine import ComplianceEngine

class TestComplianceEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ComplianceEngine()

    def test_etsi_compliance_evaluation(self):
        device = {
            "name": "Living Room Cam",
            "device_type": "Smart Camera",
            "manufacturer": "Hikvision",
            "open_ports": [80, 554, 23]
        }
        vulns = [
            {"name": "Default Credentials Active", "severity": "critical", "cisa_kev": True}
        ]
        audit = self.engine.comprehensive_audit(device, vulns)
        self.assertIn("etsi_en_303_645", audit)
        self.assertIn("nist_ir_8259", audit)
        self.assertIn("owasp_top_10", audit)
        self.assertLess(audit["privacy_compliance_score"], 8.0)
        self.assertEqual(audit["etsi_en_303_645"]["status"], "NON_COMPLIANT")

    def test_clean_device_compliance(self):
        device = {
            "name": "Hardened Sensor",
            "device_type": "Smart Sensor",
            "manufacturer": "Philips",
            "model": "Hue Bridge v2",
            "mac_address": "00:17:88:01:02:03",
            "open_ports": [443, 8883]
        }
        vulns = []
        audit = self.engine.comprehensive_audit(device, vulns)
        self.assertGreaterEqual(audit["privacy_compliance_score"], 8.5)
        self.assertEqual(audit["overall_status"], "COMPLIANT")

if __name__ == '__main__':
    unittest.main()
