import unittest
from app import app, db
from models import User, Asset, ContainmentIntent, AuditEvent
from containment_engine import ContainmentEngine

class TestContainmentLifecycle(unittest.TestCase):
    def setUp(self):
        self.engine = ContainmentEngine()
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user = User(username='contain_user', email='contain@priviot.io', password_hash='hash123')
            db.session.add(self.user)
            db.session.commit()
            self.user_id = self.user.id
            self.asset = Asset(
                ip_address="192.168.1.55",
                mac_address="00:11:22:33:44:55",
                vendor="Hikvision",
                device_type="IP Camera",
                user_id=self.user_id
            )
            db.session.add(self.asset)
            db.session.commit()
            self.asset_id = self.asset.id

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_providers_policy_generation(self):
        intent = {
            "asset_id": self.asset_id,
            "reason": "CISA KEV Exploit Active",
            "severity": "critical",
            "blocked_destinations": ["*.hik-connect.com", "*.tuyaus.com"]
        }
        
        # Test pfSense
        pfsense = self.engine.generate_provider_policy(intent, "192.168.1.55", provider_name="pfsense")
        self.assertIn("easyrule block lan any 192.168.1.55", pfsense["apply_policy"])
        self.assertIn("pfctl -k 192.168.1.55", pfsense["rollback_policy"])

        # Test UniFi
        unifi = self.engine.generate_provider_policy(intent, "192.168.1.55", provider_name="unifi")
        self.assertIn("UBIOS_LAN_IN_USER", unifi["apply_policy"])
        self.assertIn("-D UBIOS_LAN_IN_USER", unifi["rollback_policy"])

        # Test iptables
        iptables = self.engine.generate_provider_policy(intent, "192.168.1.55", mac_address="00:11:22:33:44:55", provider_name="iptables")
        self.assertIn("PRIVIOT_ISOLATION_192_168_1_55", iptables["apply_policy"])
        self.assertIn("-D FORWARD", iptables["rollback_policy"])

        # Test Pi-hole
        pihole = self.engine.generate_provider_policy(intent, "192.168.1.55", provider_name="pihole")
        self.assertIn("pihole -b -wild hik-connect.com", pihole["apply_policy"])
        self.assertIn("pihole -b -d -wild hik-connect.com", pihole["rollback_policy"])

    def test_safe_preview_impact(self):
        intent = {"asset_id": self.asset_id, "reason": "Test Containment"}
        preview = self.engine.preview_containment(intent, "192.168.1.55", provider_name="pfsense")
        self.assertIn("expected_impact", preview)
        self.assertIn("known_safe_flows", preview)
        self.assertIn("potential_breakage", preview)
        self.assertIn("rollback_plan", preview)

if __name__ == '__main__':
    unittest.main()
