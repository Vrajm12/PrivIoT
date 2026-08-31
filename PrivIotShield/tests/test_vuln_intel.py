import unittest
from vuln_intel import VulnerabilityIntelEngine

class TestVulnerabilityIntel(unittest.TestCase):
    def setUp(self):
        self.engine = VulnerabilityIntelEngine()

    def test_hikvision_cve_match(self):
        device = {
            "name": "Front Porch Hikvision Camera",
            "manufacturer": "Hikvision",
            "model": "DS-2CD2042WD-I",
            "device_type": "Smart Camera",
            "open_ports": [80, 554, 8000]
        }
        matches = self.engine.match_vulnerabilities(device)
        self.assertTrue(len(matches) >= 1)
        cve_ids = [m["cve_id"] for m in matches]
        self.assertIn("CVE-2021-36260", cve_ids)
        self.assertTrue(any(m.get("cisa_kev") is True for m in matches))

    def test_generic_rtsp_match(self):
        device = {
            "name": "Generic IP Cam",
            "manufacturer": "Unknown",
            "device_type": "IP Camera",
            "open_ports": [554]
        }
        matches = self.engine.match_vulnerabilities(device)
        cve_ids = [m["cve_id"] for m in matches]
        self.assertIn("GEN-VULN-RTSP-AUTH", cve_ids)

    def test_risk_profile_calculation(self):
        vulns = [
            {"cvss_score": 9.8, "severity": "critical", "cisa_kev": True, "epss_score": 0.974},
            {"cvss_score": 7.5, "severity": "high", "cisa_kev": False, "epss_score": 0.312}
        ]
        profile = self.engine.calculate_device_risk_profile(vulns)
        self.assertEqual(profile["risk_level"], "critical")
        self.assertEqual(profile["cisa_kev_count"], 1)
        self.assertEqual(profile["max_cvss"], 9.8)
        self.assertEqual(profile["max_epss"], 0.974)

if __name__ == '__main__':
    unittest.main()
