import unittest
from exposure_engine import ExposureEngine

class TestExposureEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ExposureEngine()

    def test_cisa_kev_boost_and_epss_calculation(self):
        asset = {"criticality": "tier_1", "device_type": "IP Camera"}
        vulns = [
            {"cve_id": "CVE-2021-36260", "cvss_score": 9.8, "cisa_kev": True, "epss_score": 0.974},
            {"cve_id": "CVE-2017-7921", "cvss_score": 8.8, "cisa_kev": True, "epss_score": 0.850}
        ]
        res = self.engine.calculate_pri(asset, vulns, network_placement="flat_lan")
        
        self.assertEqual(res["threat_base"], 9.8)
        self.assertEqual(res["cisa_kev_boost"], 1.5)
        self.assertEqual(res["epss_signal"], 1.0)
        self.assertEqual(res["exposure_factor"], 0.8)
        self.assertEqual(res["criticality_weight"], 1.2)
        self.assertTrue(res["pri_score"] >= 9.0)
        self.assertEqual(res["pri_level"], "critical")
        self.assertIn("formula", res["explanation"])

    def test_network_placement_exposure_scaling(self):
        asset = {"criticality": "tier_2", "device_type": "Smart Plug"}
        vulns = [{"cve_id": "CVE-2020-0001", "cvss_score": 7.5, "cisa_kev": False, "epss_score": 0.05}]
        
        wan_res = self.engine.calculate_pri(asset, vulns, network_placement="direct_wan")
        isolated_res = self.engine.calculate_pri(asset, vulns, network_placement="isolated_subnet")
        
        self.assertTrue(wan_res["pri_score"] > isolated_res["pri_score"])
        self.assertEqual(wan_res["exposure_factor"], 1.0)
        self.assertEqual(isolated_res["exposure_factor"], 0.1)

if __name__ == '__main__':
    unittest.main()
