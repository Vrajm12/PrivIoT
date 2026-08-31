import unittest
from remediation_engine import RemediationEngine

class TestRemediationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RemediationEngine()

    def test_iptables_generation(self):
        rules = self.engine.generate_iptables_rules("192.168.1.150", "AA:BB:CC:DD:EE:FF")
        self.assertIn("192.168.1.150", rules)
        self.assertIn("AA:BB:CC:DD:EE:FF", rules)
        self.assertIn("-d 10.0.0.0/8 -j DROP", rules)

    def test_pfsense_rule_generation(self):
        xml_rules = self.engine.generate_pfsense_rules("192.168.1.150", "Smart Camera")
        self.assertIn("<address>192.168.1.150</address>", xml_rules)
        self.assertIn("<type>block</type>", xml_rules)

    def test_dns_sinkhole_generation(self):
        blocklist = self.engine.generate_dns_sinkhole_blocklist("Tuya")
        self.assertTrue(any("tuya" in d for d in blocklist))

if __name__ == '__main__':
    unittest.main()
