import unittest
from safe_discovery import validate_target_scope

class TestSecurityBoundaries(unittest.TestCase):
    def test_ssrf_cloud_metadata_blocked(self):
        # 169.254.169.254 AWS/Azure/GCP metadata endpoint
        is_valid, err, _ = validate_target_scope("169.254.169.254")
        self.assertFalse(is_valid)
        self.assertIn("forbidden", err.lower())

        is_valid, err, _ = validate_target_scope("169.254.0.0/16")
        self.assertFalse(is_valid)
        self.assertIn("forbidden", err.lower())

    def test_loopback_scanning_blocked_by_default(self):
        is_valid, err, _ = validate_target_scope("127.0.0.1", allow_loopback=False)
        self.assertFalse(is_valid)
        self.assertIn("loopback", err.lower())

        is_valid, err, _ = validate_target_scope("127.0.0.0/8", allow_loopback=False)
        self.assertFalse(is_valid)
        self.assertIn("loopback", err.lower())

    def test_multicast_and_broadcast_blocked(self):
        is_valid, err, _ = validate_target_scope("224.0.0.1")
        self.assertFalse(is_valid)
        
        is_valid, err, _ = validate_target_scope("255.255.255.255")
        self.assertFalse(is_valid)

    def test_oversized_cidr_range_blocked(self):
        # Entire internet /0 or /8 or /16
        is_valid, err, _ = validate_target_scope("0.0.0.0/0")
        self.assertFalse(is_valid)
        self.assertTrue("too large" in err.lower() or "forbidden" in err.lower())

        is_valid, err, _ = validate_target_scope("10.0.0.0/8")
        self.assertFalse(is_valid)
        self.assertIn("too large", err.lower())

    def test_valid_authorized_subnets_allowed(self):
        is_valid, err, hosts = validate_target_scope("192.168.1.0/24")
        self.assertTrue(is_valid)
        self.assertIsNone(err)
        self.assertEqual(len(hosts), 254)

        is_valid, err, hosts = validate_target_scope("10.50.1.100")
        self.assertTrue(is_valid)
        self.assertEqual(len(hosts), 1)

if __name__ == '__main__':
    unittest.main()
