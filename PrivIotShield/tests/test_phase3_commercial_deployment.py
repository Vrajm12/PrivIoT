"""
PrivIoT Shield - Phase 3 Comprehensive Test Suite
Validates Commercial Deployment, Fleet Management, Multi-Site & MSSP Triage,
RBAC, Reports Engine, Notifications, Entitlements Quotas, and Health Probes.
"""

import unittest
import json
from datetime import datetime, timedelta

from app import app, db
from models import User, Asset, Collector, Observation, BehavioralDriftEvent, ContainmentIntent, Alert
from collector_manager import collector_manager
from mssp_manager import mssp_manager
from rbac_engine import get_role_level, approval_engine
from reports_engine import reports_engine
from notification_engine import notification_engine
from entitlements_engine import entitlements_engine


class TestPhase3CommercialDeployment(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.user_admin = User(username='corp_admin', email='admin@priviot.io', password_hash='hash1', role='admin')
            self.user_viewer = User(username='auditor_viewer', email='viewer@priviot.io', password_hash='hash2', role='viewer')
            self.user_approver = User(username='sec_approver', email='approver@priviot.io', password_hash='hash3', role='approver')
            db.session.add_all([self.user_admin, self.user_viewer, self.user_approver])
            db.session.commit()

            self.user_admin_id = self.user_admin.id
            self.user_viewer_id = self.user_viewer.id
            self.user_approver_id = self.user_approver.id

            self.admin_headers = {
                "X-API-Key": self.user_admin.api_key,
                "X-Tenant-ID": "tenant_enterprise_01",
                "Content-Type": "application/json"
            }
            self.viewer_headers = {
                "X-API-Key": self.user_viewer.api_key,
                "X-Tenant-ID": "tenant_enterprise_01",
                "Content-Type": "application/json"
            }

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_production_health_readiness_and_metrics_endpoints(self):
        # 1. Health Probe
        res = self.app.get('/health')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()['status'], 'healthy')

        # 2. Readiness Probe
        res = self.app.get('/ready')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()['database'], 'connected')

        # 3. Prometheus Metrics Endpoint
        res = self.app.get('/metrics')
        self.assertEqual(res.status_code, 200)
        self.assertIn("priviot_assets_total", res.get_data(as_text=True))
        self.assertIn("priviot_collectors_total", res.get_data(as_text=True))

    def test_collector_fleet_lifecycle_and_rotation(self):
        with app.app_context():
            # 1. Enroll Collector
            collector, raw_token = collector_manager.enroll_collector(
                tenant_id="tenant_enterprise_01",
                site_id="plant_austin",
                name="Austin_Edge_01"
            )
            self.assertEqual(collector.status, "ACTIVE")
            self.assertTrue(raw_token.startswith("priviot_sensor_"))

            # 2. Token Rotation
            c_rotated, new_token = collector_manager.rotate_token(collector.id, "tenant_enterprise_01")
            self.assertNotEqual(raw_token, new_token)
            self.assertEqual(c_rotated.status, "ACTIVE")

            # 3. Revocation
            c_revoked = collector_manager.revoke_collector(collector.id, "tenant_enterprise_01")
            self.assertEqual(c_revoked.status, "REVOKED")

            # 4. Reactivation
            c_reactivated, react_token = collector_manager.reactivate_collector(collector.id, "tenant_enterprise_01")
            self.assertEqual(c_reactivated.status, "ACTIVE")
            self.assertTrue(react_token.startswith("priviot_sensor_"))

    def test_fleet_health_evaluation(self):
        with app.app_context():
            c1, _ = collector_manager.enroll_collector("tenant_enterprise_01", "hq", "Sensor_Active")
            c2, _ = collector_manager.enroll_collector("tenant_enterprise_01", "branch_a", "Sensor_Stale")
            
            # Make c2 stale
            c2.last_heartbeat = datetime.utcnow() - timedelta(minutes=10)
            db.session.commit()

            fleet = collector_manager.evaluate_fleet_health("tenant_enterprise_01")
            self.assertEqual(fleet["total_collectors"], 2)
            self.assertEqual(fleet["active"], 1)
            self.assertEqual(fleet["offline"], 1)

    def test_multi_site_posture_and_mssp_triage(self):
        with app.app_context():
            # Create Assets across two sites
            a1 = Asset(tenant_id="tenant_enterprise_01", user_id=self.user_admin.id, ip_address="10.1.0.10", network_scope="austin_site", vendor="Hikvision")
            a2 = Asset(tenant_id="tenant_enterprise_01", user_id=self.user_admin.id, ip_address="10.2.0.20", network_scope="london_site", vendor="Siemens")
            db.session.add_all([a1, a2])
            db.session.commit()

            # 1. Site Posture
            posture = mssp_manager.get_site_posture("tenant_enterprise_01", "austin_site")
            self.assertEqual(posture["tenant_id"], "tenant_enterprise_01")
            self.assertGreaterEqual(posture["total_assets"], 1)

            # 2. MSSP Triage
            mssp_summary = mssp_manager.get_mssp_triage_dashboard(["tenant_enterprise_01", "tenant_enterprise_02"])
            self.assertEqual(mssp_summary["total_customers"], 2)
            self.assertIn("customer_rankings", mssp_summary)

    def test_rbac_role_hierarchy_and_containment_approvals(self):
        with app.app_context():
            user_admin = User.query.get(self.user_admin_id)
            user_approver = User.query.get(self.user_approver_id)
            user_viewer = User.query.get(self.user_viewer_id)

            # 1. Level checking
            self.assertLess(get_role_level("viewer"), get_role_level("analyst"))
            self.assertLess(get_role_level("analyst"), get_role_level("operator"))
            self.assertLess(get_role_level("operator"), get_role_level("approver"))
            self.assertLess(get_role_level("approver"), get_role_level("admin"))

            # 2. Containment Approval Validation
            valid, msg = approval_engine.validate_approval_request(
                requester_id=user_admin.id,
                approver_user=user_approver,
                intent=None
            )
            self.assertTrue(valid)

            invalid, msg = approval_engine.validate_approval_request(
                requester_id=user_admin.id,
                approver_user=user_viewer,
                intent=None
            )
            self.assertFalse(invalid)
            self.assertIn("does not hold", msg)

    def test_all_seven_enterprise_security_reports(self):
        with app.app_context():
            # Seed an asset
            asset = Asset(tenant_id="tenant_enterprise_01", user_id=self.user_admin.id, ip_address="192.168.1.55", vendor="Hikvision")
            db.session.add(asset)
            db.session.commit()

            report_types = [
                "EXECUTIVE_SECURITY_SUMMARY",
                "DEVICE_EXPOSURE_REPORT",
                "VULNERABILITY_REPORT",
                "BEHAVIORAL_DRIFT_REPORT",
                "CONTAINMENT_ACTIVITY_REPORT",
                "COMPLIANCE_EVIDENCE_REPORT",
                "SITE_RISK_REPORT"
            ]

            for r_type in report_types:
                res = reports_engine.generate_report(r_type, "tenant_enterprise_01")
                self.assertIsNotNone(res)
                self.assertEqual(res["metadata"]["report_type"], r_type)

    def test_notification_dispatch_and_cooldown_deduplication(self):
        # 1. First alert -> should deliver
        should_send = notification_engine.should_deliver(
            tenant_id="tenant_enterprise_01",
            alert_type="critical_cve",
            severity="critical",
            target_id="asset:42",
            threshold="medium"
        )
        self.assertTrue(should_send)

        # 2. Immediate duplicate -> suppressed by cooldown
        duplicate_send = notification_engine.should_deliver(
            tenant_id="tenant_enterprise_01",
            alert_type="critical_cve",
            severity="critical",
            target_id="asset:42",
            threshold="medium"
        )
        self.assertFalse(duplicate_send)

        # 3. Payload formatting
        slack = notification_engine.format_slack_payload("Exploit Alert", "CVE-2021-36260 Detected", "critical", {"cvss": 9.8})
        self.assertIn("attachments", slack)

        teams = notification_engine.format_teams_payload("Exploit Alert", "CVE-2021-36260 Detected", "critical", {"cvss": 9.8})
        self.assertEqual(teams["@type"], "MessageCard")

    def test_entitlements_quota_and_retention_purge(self):
        with app.app_context():
            entitlements_engine.set_tenant_plan("tenant_enterprise_01", "TRIAL")
            
            # Quota Check
            ok, msg = entitlements_engine.check_asset_quota("tenant_enterprise_01")
            self.assertTrue(ok)

            # Insert expired observation (10 days old on 7-day plan)
            old_obs = Observation(
                tenant_id="tenant_enterprise_01",
                observation_type="network",
                payload_json=json.dumps({"test": "data"}),
                timestamp=datetime.utcnow() - timedelta(days=10)
            )
            db.session.add(old_obs)
            db.session.commit()

            # Execute Purge
            purged = entitlements_engine.purge_expired_telemetry("tenant_enterprise_01")
            self.assertEqual(purged, 1)

    def test_e2e_commercial_pipeline(self):
        """
        Complete Commercial Journey:
        Enroll Sensor -> Ingest -> View Posture -> Generate Exec Report -> Send Alert -> Purge Retention.
        """
        with app.app_context():
            collector, token = collector_manager.enroll_collector(
                tenant_id="tenant_enterprise_01", site_id="hq", name="Sensor_E2E_Phase3"
            )

        # 1. Ingest
        ingest_res = self.app.post("/api/v2/telemetry/ingest", json=[{"src_ip": "10.0.5.5", "dst_ip": "1.1.1.1", "dst_port": 53, "protocol": "UDP"}], headers={"X-Sensor-Token": token})
        self.assertEqual(ingest_res.status_code, 200)

        # 2. Query Fleet Health API
        fleet_res = self.app.get("/api/v3/fleet/health", headers=self.admin_headers)
        self.assertEqual(fleet_res.status_code, 200)

        # 3. Generate Executive Report API
        rep_res = self.app.post("/api/v3/reports/generate", json={"report_type": "EXECUTIVE_SECURITY_SUMMARY"}, headers=self.admin_headers)
        self.assertEqual(rep_res.status_code, 200)
        self.assertIn("executive_summary", rep_res.get_json()["report"])

        # 4. Trigger Retention Purge API
        purge_res = self.app.post("/api/v3/retention/purge", headers=self.admin_headers)
        self.assertEqual(purge_res.status_code, 200)


if __name__ == '__main__':
    unittest.main()
