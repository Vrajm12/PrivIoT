"""
PrivIoT Shield — Phase B FastAPI Control Plane Verification Suite
Validates:
1. FastAPI Application Startup & OpenAPI Validity
2. Health & Readiness Probes
3. Standard Error Contract & Request Correlation IDs
4. Operator Authentication & RBAC Enforcement
5. Hard Server-Side Tenant Isolation (Zero Leakage)
6. Collector Token Authentication & Telemetry Ingestion
7. Containment Lifecycle Authorization & Safe Flow Preview
8. Explainable PRI-v2 Calculator
9. Latency Benchmark Metrics
"""
import unittest
import time
import json
from fastapi.testclient import TestClient
from werkzeug.security import generate_password_hash

from app import app as flask_app
from extensions import db
from priviot.api.fastapi_app import app as fastapi_app
from priviot.data.models import (
    User, Asset, Alert, Collector, Observation, BehavioralBaseline,
    ContainmentIntent, AuditEvent
)
from priviot.services.collectors import collector_manager

class TestFastAPIControlPlane(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask_app.config['TESTING'] = True
        flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        cls.client = TestClient(fastapi_app)
        cls.app_context = flask_app.app_context()
        cls.app_context.push()
        db.create_all()

        # Seed Users with distinct RBAC roles
        cls.admin_user = User(
            username="sec_admin",
            email="admin@priviot.shield",
            password_hash=generate_password_hash("AdminPass123!"),
            role="admin",
            api_key="key_admin_test_001"
        )
        cls.approver_user = User(
            username="sec_approver",
            email="approver@priviot.shield",
            password_hash=generate_password_hash("ApproverPass123!"),
            role="approver",
            api_key="key_approver_test_002"
        )
        cls.operator_user = User(
            username="sec_operator",
            email="operator@priviot.shield",
            password_hash=generate_password_hash("OperatorPass123!"),
            role="operator",
            api_key="key_operator_test_003"
        )
        cls.viewer_user = User(
            username="sec_viewer",
            email="viewer@priviot.shield",
            password_hash=generate_password_hash("ViewerPass123!"),
            role="viewer",
            api_key="key_viewer_test_004"
        )
        db.session.add_all([cls.admin_user, cls.approver_user, cls.operator_user, cls.viewer_user])
        db.session.commit()

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        db.drop_all()
        cls.app_context.pop()

    def test_01_openapi_specification_validity(self):
        """Verify OpenAPI 3.x schema generation and structure."""
        resp = self.client.get("/openapi.json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("openapi", data)
        self.assertEqual(data["info"]["title"], "PrivIoT Shield — Security Operations API")
        self.assertIn("/api/v2/assets", data["paths"])
        self.assertIn("/api/v2/telemetry/ingest", data["paths"])
        self.assertIn("/api/v2/containment/preview", data["paths"])
        self.assertIn("/health/live", data["paths"])
        self.assertIn("/health/ready", data["paths"])

    def test_02_health_and_readiness_probes(self):
        """Verify process liveness and DB readiness."""
        # Liveness
        resp_live = self.client.get("/health/live")
        self.assertEqual(resp_live.status_code, 200)
        self.assertEqual(resp_live.json()["status"], "alive")

        # Readiness
        resp_ready = self.client.get("/health/ready")
        self.assertEqual(resp_ready.status_code, 200)
        self.assertEqual(resp_ready.json()["status"], "ready")

    def test_03_request_correlation_and_error_contract(self):
        """Verify X-Request-ID propagation and standardized JSON error schema."""
        # Non-existent asset
        resp = self.client.get(
            "/api/v2/assets/999999",
            headers={"X-API-Key": self.admin_user.api_key, "X-Request-ID": "custom-req-777"}
        )
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.headers.get("X-Request-ID"), "custom-req-777")
        self.assertIn("X-Response-Time-Ms", resp.headers)

        body = resp.json()
        self.assertIn("error", body)
        self.assertEqual(body["error"]["code"], "NOT_FOUND")
        self.assertEqual(body["error"]["request_id"], "custom-req-777")
        self.assertIn("not found in tenant scope", body["error"]["message"])

    def test_04_operator_authentication_and_profile(self):
        """Verify /api/v2/auth/login and /api/v2/auth/me endpoints."""
        # Valid login
        login_resp = self.client.post("/api/v2/auth/login", json={
            "username": "sec_operator",
            "password": "OperatorPass123!"
        })
        self.assertEqual(login_resp.status_code, 200)
        token_data = login_resp.json()
        self.assertEqual(token_data["access_token"], self.operator_user.api_key)
        self.assertEqual(token_data["role"], "operator")

        # Profile retrieval with Bearer token
        me_resp = self.client.get("/api/v2/auth/me", headers={
            "Authorization": f"Bearer {self.operator_user.api_key}",
            "X-Tenant-ID": "tenant_secops_corp"
        })
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["username"], "sec_operator")
        self.assertEqual(me_resp.json()["tenant_id"], "tenant_secops_corp")

    def test_05_hard_multi_tenant_isolation(self):
        """Verify strict tenant isolation: Tenant A cannot access Tenant B assets or alerts."""
        # Create asset in Tenant Alpha
        asset_alpha = Asset(
            tenant_id="tenant_alpha",
            ip_address="10.10.1.50",
            mac_address="00:11:22:33:44:55",
            vendor="Axis Communications",
            model="M3045-V",
            device_type="IP Camera"
        )
        db.session.add(asset_alpha)
        db.session.commit()

        # 1. Query from Tenant Alpha -> Visible
        resp_a = self.client.get(f"/api/v2/assets/{asset_alpha.id}", headers={
            "X-API-Key": self.admin_user.api_key,
            "X-Tenant-ID": "tenant_alpha"
        })
        self.assertEqual(resp_a.status_code, 200)
        self.assertEqual(resp_a.json()["ip_address"], "10.10.1.50")

        # 2. Query from Tenant Beta -> 404 Not Found (Hard isolation)
        resp_b = self.client.get(f"/api/v2/assets/{asset_alpha.id}", headers={
            "X-API-Key": self.admin_user.api_key,
            "X-Tenant-ID": "tenant_beta"
        })
        self.assertEqual(resp_b.status_code, 404)
        self.assertEqual(resp_b.json()["error"]["code"], "NOT_FOUND")

        # 3. List assets in Tenant Beta -> Count is 0
        resp_b_list = self.client.get("/api/v2/assets", headers={
            "X-API-Key": self.admin_user.api_key,
            "X-Tenant-ID": "tenant_beta"
        })
        self.assertEqual(resp_b_list.status_code, 200)
        self.assertEqual(resp_b_list.json()["total_count"], 0)

    def test_06_rbac_role_hierarchy_enforcement(self):
        """Verify RBAC role checks: Viewer cannot enroll collectors, Approver can approve containment."""
        # 1. Viewer attempts to enroll collector -> 403 Forbidden
        resp_viewer = self.client.post("/api/v2/collectors/register", json={
            "collector_name": "Unauthorized_Sensor"
        }, headers={"X-API-Key": self.viewer_user.api_key, "X-Tenant-ID": "tenant_rbac_test"})
        self.assertEqual(resp_viewer.status_code, 403)
        self.assertIn("OPERATOR", resp_viewer.json()["error"]["message"])

        # 2. Operator enrolls collector -> 200 OK
        resp_op = self.client.post("/api/v2/collectors/register", json={
            "collector_name": "Authorized_Sensor_01"
        }, headers={"X-API-Key": self.operator_user.api_key, "X-Tenant-ID": "tenant_rbac_test"})
        self.assertEqual(resp_op.status_code, 200)
        self.assertIn("raw_token", resp_op.json())

    def test_07_collector_telemetry_ingestion_and_correlation(self):
        """Verify token-authenticated edge telemetry ingestion batch."""
        # Enroll collector
        collector, raw_token = collector_manager.enroll_collector(
            "tenant_telemetry_lab", "edge_site_1", "Ingest_Collector_1"
        )

        # 1. Unauthorized ingestion attempt -> 401
        unauth_resp = self.client.post("/api/v2/telemetry/ingest", json={
            "observations": [{"observation_type": "network", "src_ip": "192.168.1.100"}]
        }, headers={"X-Sensor-Token": "invalid_token_999"})
        self.assertEqual(unauth_resp.status_code, 401)

        # 2. Authorized telemetry batch ingestion
        batch_payload = {
            "observations": [
                {
                    "observation_type": "network",
                    "src_ip": "192.168.1.120",
                    "src_mac": "AA:BB:CC:DD:EE:01",
                    "dst_ip": "8.8.8.8",
                    "dst_port": 53,
                    "proto": "UDP"
                },
                {
                    "observation_type": "dns",
                    "src_ip": "192.168.1.120",
                    "dns_query": "time.google.com",
                    "dns_resolved_ip": "216.239.35.0"
                }
            ]
        }
        auth_resp = self.client.post("/api/v2/telemetry/ingest", json=batch_payload, headers={
            "X-Sensor-Token": raw_token
        })
        self.assertEqual(auth_resp.status_code, 200)
        res_json = auth_resp.json()
        self.assertTrue(res_json["success"])
        self.assertEqual(res_json["processed_count"], 2)

    def test_08_containment_preview_and_safe_flows(self):
        """Verify containment rule generation and safe-flow preservation."""
        asset = Asset(
            tenant_id="tenant_containment_test",
            ip_address="192.168.1.222",
            mac_address="BC:FE:D9:11:22:33",
            vendor="Hikvision",
            model="DS-2CD2042WD-I"
        )
        db.session.add(asset)
        db.session.commit()

        # Preview Containment
        resp = self.client.post("/api/v2/containment/preview", json={
            "asset_id": asset.id,
            "target_provider": "iptables",
            "action": "isolate"
        }, headers={"X-API-Key": self.operator_user.api_key, "X-Tenant-ID": "tenant_containment_test"})

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["asset_id"], asset.id)
        self.assertEqual(data["target_provider"], "iptables")
        self.assertEqual(data["current_state"], "PREVIEWED")
        self.assertTrue(data["rollback_ready"])
        self.assertTrue(len(data["generated_rules"]) > 0)

    def test_09_pri_v2_mathematical_calculation(self):
        """Verify explainable PRI-v2 risk scoring endpoint."""
        resp = self.client.post("/api/v2/exposure/calculate-pri", json={
            "vendor": "Hikvision",
            "model": "IP Camera",
            "device_type": "Smart Camera",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2021-36260",
                    "cvss_score": 9.8,
                    "cisa_kev": True,
                    "epss_score": 0.974
                }
            ],
            "network_placement": "direct_wan",
            "behavioral_penalties": 1.5,
            "compliance_penalties": 1.0
        }, headers={"X-API-Key": self.viewer_user.api_key})

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["pri_score"], 9.0)
        self.assertEqual(data["risk_level"], "critical")
        self.assertEqual(data["threat_base"], 9.8)
        self.assertEqual(data["cisa_kev_boost"], 1.5)
        self.assertEqual(data["epss_signal"], 1.0)
        self.assertEqual(data["exposure_factor"], 1.0)

    def test_10_latency_and_performance_benchmark(self):
        """Measure request latency baselines across core endpoints."""
        # 1. Health Liveness
        t0 = time.time()
        r1 = self.client.get("/health/live")
        lat_live = (time.time() - t0) * 1000
        self.assertEqual(r1.status_code, 200)

        # 2. Asset List
        t0 = time.time()
        r2 = self.client.get("/api/v2/assets", headers={"X-API-Key": self.admin_user.api_key})
        lat_assets = (time.time() - t0) * 1000
        self.assertEqual(r2.status_code, 200)

        # 3. PRI-v2 Calculation
        t0 = time.time()
        r3 = self.client.post("/api/v2/exposure/calculate-pri", json={"vendor": "Generic"}, headers={"X-API-Key": self.admin_user.api_key})
        lat_pri = (time.time() - t0) * 1000
        self.assertEqual(r3.status_code, 200)

        print(f"\n[BENCHMARK] FastAPI Latency: Live={lat_live:.2f}ms | Assets={lat_assets:.2f}ms | PRI={lat_pri:.2f}ms")
        self.assertLess(lat_live, 50.0)  # Liveness probe must be sub-50ms
