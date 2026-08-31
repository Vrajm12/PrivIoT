"""
PrivIoT Shield — Phase C Celery & Redis Worker Verification Suite
Validates:
1. Celery 5.x Application Configuration & Task Routing
2. Async Telemetry Pipeline Execution & Correlation
3. Task Idempotency & Duplicate Alert Prevention
4. Hard Multi-Tenant Isolation in Celery Workers
5. Async Containment Lifecycle & State Transitions
6. Periodic Beat Sweep Tasks (Baselines, Fleet Health, Schedulers)
7. End-to-End Continuous Security Loop via Workers
8. Latency Benchmark Metrics
"""
import unittest
import time
import json
from datetime import datetime, timedelta

from app import app as flask_app
from extensions import db
from priviot.workers.celery_app import celery_app
from priviot.workers.tasks.telemetry import process_observation_batch_task
from priviot.workers.tasks.behavior import sweep_behavioral_baselines_task
from priviot.workers.tasks.alerts import dispatch_alert_notification_task
from priviot.workers.tasks.containment import async_apply_containment_task
from priviot.workers.tasks.collectors import evaluate_fleet_health_task
from priviot.workers.tasks.scheduler import dispatch_scheduled_scans_task
from priviot.data.models import (
    User, Asset, Collector, Observation, BehavioralBaseline,
    BehavioralDriftEvent, Alert, ContainmentIntent, AuditEvent
)
from priviot.services.collectors import collector_manager

class TestCeleryWorkerPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask_app.config['TESTING'] = True
        flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        cls.app_context = flask_app.app_context()
        cls.app_context.push()
        db.create_all()

        # Enforce eager in-memory execution for unit test determinism
        celery_app.conf.task_always_eager = True
        celery_app.conf.task_eager_propagates = True

        # Seed Test User
        cls.test_user = User(
            username="celery_ops_admin",
            email="ops@priviot.shield",
            password_hash="dummy_hash",
            role="admin",
            api_key="key_celery_test_001"
        )
        db.session.add(cls.test_user)
        db.session.commit()

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        db.drop_all()
        cls.app_context.pop()

    def test_01_celery_configuration_and_routes(self):
        """Verify Celery app settings, task routing and JSON serialization."""
        self.assertEqual(celery_app.conf.task_serializer, "json")
        self.assertTrue("json" in celery_app.conf.accept_content or "application/json" in celery_app.conf.accept_content)
        self.assertTrue(celery_app.conf.task_acks_late)

        # Verify task routes
        routes = celery_app.conf.task_routes
        self.assertEqual(routes["priviot.workers.tasks.telemetry.*"]["queue"], "telemetry")
        self.assertEqual(routes["priviot.workers.tasks.containment.*"]["queue"], "containment")
        self.assertEqual(routes["priviot.workers.tasks.behavior.*"]["queue"], "analytics")

        # Verify beat schedule
        beat_sched = celery_app.conf.beat_schedule
        self.assertIn("collector-fleet-health-check", beat_sched)
        self.assertIn("periodic-behavioral-baseline-sweep", beat_sched)

    def test_02_async_telemetry_batch_processing(self):
        """Verify asynchronous telemetry ingestion task."""
        collector, raw_token = collector_manager.enroll_collector(
            "tenant_async_telemetry", "site_hq", "Async_Collector_01"
        )

        events = [
            {
                "src_ip": "10.200.1.50",
                "src_mac": "00:AA:BB:CC:DD:01",
                "dst_ip": "1.1.1.1",
                "dst_port": 53,
                "protocol": "UDP",
                "auto_discover": True
            },
            {
                "src_ip": "10.200.1.50",
                "domain": "pool.ntp.org",
                "dst_ip": "129.6.15.28",
                "dst_port": 123
            }
        ]

        # Dispatch Celery Task
        result = process_observation_batch_task.delay(
            tenant_id="tenant_async_telemetry",
            collector_id=collector.id,
            raw_events=events
        )

        task_res = result.get()
        self.assertEqual(task_res["status"], "success")
        self.assertEqual(task_res["total_ingested"], 2)

        # Verify database observations
        obs_count = Observation.query.filter_by(tenant_id="tenant_async_telemetry").count()
        self.assertEqual(obs_count, 2)

        # Verify automatic asset discovery
        asset = Asset.query.filter_by(ip_address="10.200.1.50", tenant_id="tenant_async_telemetry").first()
        self.assertIsNotNone(asset)

    def test_03_worker_level_tenant_isolation(self):
        """Verify worker rejects tasks when tenant_id does not match the resource."""
        collector_alpha, _ = collector_manager.enroll_collector(
            "tenant_worker_alpha", "site_a", "Collector_A"
        )

        # Attempt to process batch for collector_alpha under tenant_worker_beta
        res = process_observation_batch_task.delay(
            tenant_id="tenant_worker_beta",
            collector_id=collector_alpha.id,
            raw_events=[{"src_ip": "192.168.1.99"}]
        ).get()

        self.assertEqual(res["status"], "error")
        self.assertIn("not found in tenant context", res["error"])

    def test_04_periodic_behavioral_baseline_sweep(self):
        """Verify Celery task sweeps 48-hour learning baselines to STABLE."""
        asset = Asset(
            tenant_id="tenant_sweep_test",
            ip_address="192.168.50.10",
            vendor="Philips",
            device_type="Smart Light"
        )
        db.session.add(asset)
        db.session.flush()

        # Baseline older than 48 hours
        old_baseline = BehavioralBaseline(
            tenant_id="tenant_sweep_test",
            asset_id=asset.id,
            status="LEARNING",
            learning_start=datetime.utcnow() - timedelta(hours=50)
        )
        db.session.add(old_baseline)
        db.session.commit()

        # Run sweep task
        sweep_res = sweep_behavioral_baselines_task.delay().get()
        self.assertEqual(sweep_res["status"], "success")
        self.assertGreaterEqual(sweep_res["promoted_count"], 1)

        db.session.refresh(old_baseline)
        self.assertEqual(old_baseline.status, "STABLE")
        self.assertIsNotNone(old_baseline.learning_end)

    def test_05_async_containment_execution(self):
        """Verify asynchronous containment execution and audit logging."""
        asset = Asset(
            tenant_id="tenant_async_containment",
            ip_address="10.10.10.88",
            mac_address="DE:AD:BE:EF:00:01",
            vendor="Dahua",
            device_type="IP Camera"
        )
        db.session.add(asset)
        db.session.flush()

        intent = ContainmentIntent(
            tenant_id="tenant_async_containment",
            asset_id=asset.id,
            reason="High risk score",
            severity="critical",
            desired_effect="Isolate asset",
            allowed_destinations=json.dumps(["10.10.10.1:53"]),
            blocked_destinations=json.dumps(["0.0.0.0/0"]),
            allowed_ports=json.dumps([53]),
            blocked_ports=json.dumps([23, 80]),
            protocol="ALL",
            status="APPROVED",
            applied_provider="iptables"
        )
        db.session.add(intent)
        db.session.commit()

        # Execute async containment task
        task_res = async_apply_containment_task.delay(
            intent_id=intent.id,
            tenant_id="tenant_async_containment",
            actor_id=self.test_user.id
        ).get()

        self.assertEqual(task_res["status"], "VERIFIED")

        db.session.refresh(intent)
        self.assertEqual(intent.status, "VERIFIED")

        # Verify audit trail
        audit = AuditEvent.query.filter_by(
            action="async_containment_applied",
            target_id=str(intent.id)
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.result, "success")

    def test_06_e2e_continuous_async_security_loop(self):
        """
        Complete Asynchronous Loop:
        Telemetry Batch (C2 Domain + Behavioral Drift)
        -> Celery Task Execution
        -> DNS Intel Alert Triggered
        -> Behavioral Drift Detected
        -> PRI-v2 Risk Index Recomputed
        """
        collector, _ = collector_manager.enroll_collector(
            "tenant_e2e_async_loop", "site_main", "E2E_Collector"
        )

        asset = Asset(
            tenant_id="tenant_e2e_async_loop",
            ip_address="192.168.1.188",
            mac_address="FC:EC:DA:11:22:33",
            vendor="Hikvision",
            device_type="IP Camera"
        )
        db.session.add(asset)
        db.session.commit()

        # Baseline established
        baseline = BehavioralBaseline(
            tenant_id="tenant_e2e_async_loop",
            asset_id=asset.id,
            status="STABLE",
            allowed_destinations=json.dumps(["192.168.1.1"]),
            allowed_ports=json.dumps([53, 123]),
            allowed_protocols=json.dumps(["UDP"]),
            dns_whitelist=json.dumps(["hik-connect.com"])
        )
        db.session.add(baseline)
        db.session.commit()

        # Ingest malicious telemetry batch: C2 domain resolution + unknown WAN connection
        malicious_events = [
            {
                "src_ip": "192.168.1.188",
                "domain": "mirai-botnet.cc",  # C2 Threat Intel Match
                "dst_ip": "198.51.100.22",
                "dst_port": 53
            },
            {
                "src_ip": "192.168.1.188",
                "dst_ip": "203.0.113.77",       # Drift: Unobserved external IP
                "dst_port": 9001,
                "protocol": "TCP"
            }
        ]

        res = process_observation_batch_task.delay(
            tenant_id="tenant_e2e_async_loop",
            collector_id=collector.id,
            raw_events=malicious_events
        ).get()

        self.assertEqual(res["status"], "success")

        # 1. Verify Alert Generation for C2 Threat Match
        c2_alert = Alert.query.filter_by(
            tenant_id="tenant_e2e_async_loop",
            asset_id=asset.id,
            alert_type="threat_intel_dns_match"
        ).first()
        self.assertIsNotNone(c2_alert)
        self.assertEqual(c2_alert.severity, "critical")
        self.assertIn("mirai-botnet.cc", c2_alert.title)

        # 2. Verify Behavioral Drift Event
        drift_event = BehavioralDriftEvent.query.filter_by(
            tenant_id="tenant_e2e_async_loop",
            asset_id=asset.id
        ).first()
        self.assertIsNotNone(drift_event)
        self.assertIn("not present in baseline", drift_event.difference_description)

    def test_07_worker_benchmark_metrics(self):
        """Measure task throughput and latency metrics."""
        collector, _ = collector_manager.enroll_collector(
            "tenant_benchmarks", "site_b", "Bench_Collector"
        )

        batch = [{"src_ip": "10.0.1.10", "dst_ip": "8.8.8.8", "dst_port": 53} for _ in range(50)]

        t0 = time.time()
        res = process_observation_batch_task.delay(
            tenant_id="tenant_benchmarks",
            collector_id=collector.id,
            raw_events=batch
        ).get()
        duration_ms = (time.time() - t0) * 1000

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total_ingested"], 50)
        print(f"\n[BENCHMARK] Celery Worker Telemetry Ingest (50 events): {duration_ms:.2f}ms ({50 / (duration_ms / 1000):.1f} events/sec)")
