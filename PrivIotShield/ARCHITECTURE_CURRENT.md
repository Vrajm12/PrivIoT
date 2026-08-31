# PRIVIOT SHIELD — CURRENT ARCHITECTURE AUDIT (2026)
**Document Version:** 1.0.0-PROD-AUDIT  
**Audit Date:** August 31, 2026  
**Auditor:** Chief Product Architect & Principal Security Engineer  
**Repository State:** Verified (62/62 automated tests passing, Phase 1–4 complete)

---

## 1. Executive Summary

PrivIoT Shield has evolved from an initial single-tenant Flask/HTML prototype into an agentless continuous IoT security operations platform. While the backend capabilities (telemetry ingestion, 48-hour behavioral baselines, PRI-v2 risk scoring, containment state machine, and multi-tenant isolation) have reached enterprise maturity, the system's runtime architecture is still anchored around a monolithic Flask application serving server-rendered Jinja2 HTML templates alongside REST APIs.

```
+-------------------------------------------------------------------------------+
|                       CURRENT MONOLITHIC RUNTIME                               |
+-------------------------------------------------------------------------------+
|  Edge Collectors (Python / Scapy / ARP / Pcap)                                 |
|       |                                                                       |
|       v HTTP POST /api/v2/telemetry/ingest                                    |
|  +-------------------------------------------------------------------------+  |
|  | Flask Monolith (app.py, routes.py, api.py)                             |  |
|  |  - Server-Side Jinja2 Rendering (25 HTML templates, static CSS/JS)       |  |
|  |  - REST APIs (107 routes: /api/v1 legacy, /api/v2 core, /api/v3 mssp,   |  |
|  |                /api/v4 pilot)                                           |  |
|  |  - Synchronous Security Pipelines (Fingerprint, Drift, PRI-v2, Contain)  |  |
|  |  - In-Process Threading Scheduler (scheduler_engine.py)                 |  |
|  +-------------------------------------------------------------------------+  |
|       |                                                                       |
|       v SQLAlchemy 2.0 ORM                                                    |
|  +-------------------------------------------------------------------------+  |
|  | Database Layer                                                          |  |
|  |  - Development: SQLite (priviot.db)                                     |  |
|  |  - Production: PostgreSQL 15 (Docker)                                   |  |
|  +-------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------+
```

---

## 2. Component Inventory & Dependency Map

### 2.1 File & Module Statistics
* **Python Modules:** 45 files (14,432 lines of code)
* **Automated Test Modules:** 14 files (1,785 lines of test code; 62 distinct automated tests)
* **HTML Templates:** 25 Jinja2 templates (including error pages)
* **Static Assets:** 4 CSS files (`soc_theme.css`, `modern.css`, `neumorphic.css`, `style.css`), 4 JS files (`charts.js`, `dashboard.js`, `reports.js`, `scan.js`)
* **Total Registered Endpoints:** 107 routes

### 2.2 Core Component Architecture

| Component Layer | Primary Files | Responsibilities | Current Architecture & Limitations |
| :--- | :--- | :--- | :--- |
| **Application & Routing** | `app.py`, `routes.py`, `api.py`, `extensions.py` | Route dispatch, Flask-Login session management, CSRF middleware, Blueprint registration. | Monolithic coupling: Flask serves both HTML templates and high-throughput JSON telemetry. CSRF exemptions required manual route decorators. |
| **Data Models** | `models.py` | 13 SQLAlchemy models (`User`, `Asset`, `Observation`, `BehavioralBaseline`, `Alert`, `ContainmentIntent`, `Collector`, `Scan`, `Device`, `Vulnerability`, `PrivacyIssue`, `Report`, `DeviceGroup`). | Dual-schema coexistence: Legacy prototype models (`Device`, `Scan`, `Vulnerability`) exist alongside canonical Phase 2–4 models (`Asset`, `Observation`, `BehavioralBaseline`). |
| **Asset Identity & Fingerprinting** | `fingerprint_pipeline.py`, `device_fingerprinting.py`, `deep_discovery.py`, `safe_discovery.py` | Multi-priority DHCP/mDNS/SSDP evidence aggregation, MAC OUI lookup, calibrated confidence scoring, `NEEDS_VERIFICATION` guardrails. | High-quality deterministic logic. Tightly bound to SQLAlchemy session inside helper classes. |
| **Telemetry & Ingestion** | `telemetry_engine.py`, `sensor/priviot_sensor.py` | Collector authentication (SHA-256), payload schema validation, batch limit enforcement (1000 items), unmanaged asset auto-discovery, correlation. | Synchronous ingestion: Processing occurs during the HTTP POST request lifecycle. High packet volumes can cause collector timeout. |
| **Behavioral & Threat Intelligence** | `behavioral_engine.py`, `dns_intel.py`, `vuln_intel.py`, `exposure_engine.py` | 48-hour Synthetic MUD baseline creation, egress drift detection, DGA Shannon entropy, C2 domain matching, CISA KEV/EPSS matching, PRI-v2 risk scoring. | Pure Python mathematical & analytical logic. Completely decoupled from presentation, highly portable. |
| **Containment & Remediation** | `containment_engine.py`, `remediation_engine.py`, `vulnerability_remediation.py` | Micro-segmentation rule generation (iptables/nftables, Pi-hole, pfSense, UniFi), strict state machine (`DRAFT` $\to$ `VERIFIED`), safe flow preservation. | Solid state transitions and fixture verification. Rule execution runs in-process or via CLI subprocesses. |
| **Fleet & Operations** | `collector_manager.py`, `scheduler_engine.py`, `rbac_engine.py`, `mssp_manager.py`, `entitlements_engine.py` | Collector token rotation, heartbeat monitoring, background sweep scheduling, server-side RBAC, cross-tenant MSSP aggregation, quota enforcement. | Scheduler uses Python `threading.Thread` and `time.sleep()`. No durable background worker queue (Celery/Redis). |
| **Commercial & Pilot Gate** | `pilot_engine.py`, `billing_engine.py`, `backup_restore.py`, `reports_engine.py` | Pilot mode isolation, containment safety validator, Stripe webhook idempotency, JSON/cryptographic backup snapshots, 7 enterprise database reports. | Enterprise-grade validation and reporting logic. |

---

## 3. Database Architecture & Schema Audit

### 3.1 Dual-Schema Analysis
The database (`models.py`) currently hosts two generations of models:

1. **Legacy Prototype Schema (Phase 1):**
   * `Device`: User-owned hardware object.
   * `Scan`: Point-in-time vulnerability assessment.
   * `Vulnerability`: Scored finding attached to a `Scan`.
   * `PrivacyIssue`, `Report`, `DeviceGroup`, `UserActivity`.
   * *Status:* Maintained for backward compatibility with legacy `/api/scans` and `/api/devices` routes.

2. **Canonical Continuous Exposure Schema (Phase 2–4):**
   * `Asset`: Multi-tenant, network-scoped device identity (`tenant_id`, `ip_address`, `mac_address`, `identity_confidence`, `is_managed`).
   * `Observation`: Append-only, chronological telemetry event store (`event_type`, `payload`, `observed_at`).
   * `BehavioralBaseline`: Versioned 48-hour Synthetic MUD baseline (`authorized_flows`, `authorized_domains`, `is_active`).
   * `Alert`: Deterministic security incident (`deduplication_key`, `pri_impact`, `evidence`, `status`).
   * `ContainmentIntent`: 8-state firewall micro-segmentation lifecycle (`current_state`, `target_provider`, `rule_payload`, `rollback_payload`).
   * `Collector`: Distributed sensor fleet registry (`token_hash`, `ingestion_rate`, `last_heartbeat`).

### 3.2 Database Engine & Transactions
* **Engines Supported:** SQLite (local development/tests) and PostgreSQL 15 (containerized/production).
* **ORM:** SQLAlchemy 2.0 with Flask-SQLAlchemy 3.1.
* **Migration Tool:** Flask-Migrate (Alembic).
* **Schema Integrity:** Foreign keys enforced on PostgreSQL; manual session management (`db.session.commit()`, `db.session.rollback()`).

---

## 4. API & Communication Architecture

The application currently serves 107 endpoints partitioned into 4 generations:

```
[ Incoming Requests ]
   ├── HTML Web Console (25 routes: /dashboard, /devices, /device/<id>, /alerts, /remediation, /reports...)
   ├── Legacy API v1 (/api/devices, /api/scan, /api/scans, /api/reports)
   ├── Core Operations API v2 (/api/v2/telemetry/ingest, /api/v2/assets, /api/v2/alerts, /api/v2/containment/...)
   ├── MSSP & Fleet API v3 (/api/v3/fleet/health, /api/v3/mssp/dashboard, /api/v3/reports/generate)
   └── Pilot & Commercial API v4 (/api/v4/pilot/status, /api/v4/billing/stripe/webhook, /api/v4/backup/export)
```

### Limitations of Current API Architecture:
1. **Synchronous Ingestion:** `/api/v2/telemetry/ingest` processes batches of up to 1,000 observations inline inside the web worker request cycle.
2. **Authentication Fragmentation:** Mixed authentication schemes (Flask-Login session cookie for browser users, `X-API-Key` header for users, `X-Sensor-Token` / `Bearer` for edge collectors, Stripe webhook signatures for billing).
3. **Implicit Request Validation:** Request bodies are manually unpacked from `request.get_json()` with ad-hoc dictionary validation rather than formal Pydantic schema validation.

---

## 5. Security & Isolation Architecture

1. **Multi-Tenant Isolation:** `Asset`, `Observation`, `Alert`, `ContainmentIntent`, and `Collector` enforce `tenant_id` filtering at the query layer.
2. **Collector Authentication:** Collectors authenticate using pre-shared tokens hashed with SHA-256 in the database; plaintext tokens are never stored.
3. **RBAC Engine:** Server-side role hierarchy (`admin` $\to$ `soc_operator` $\to$ `approver` $\to$ `viewer`) guards containment approval and rule application.
4. **Network Scanning Boundaries:** `safe_discovery.py` enforces CIDR size limits (/24 max), blocks multicast (224.0.0.0/4), broadcast, loopback (127.0.0.0/8), and cloud metadata endpoints (169.254.169.254).

---

## 6. Runtime & Deployment Architecture

* **Web Process:** Gunicorn WSGI server running Flask (`gunicorn app:app --bind 0.0.0.0:5000`).
* **Background Scheduling:** Native Python daemon threads started in `app.py` via `scheduler_engine.start_continuous_discovery_scheduler()`.
* **Containerization:** Multi-container `docker-compose.yml` defining `postgres`, `web` (Flask control plane), and `sensor` (Scapy edge collector).
* **Observability:** Custom `/health` (liveness), `/ready` (readiness), and `/metrics` (Prometheus-formatted metrics) endpoints.

---

## 7. Current Architecture Limitations Summary

1. **Coupled Presentation & API:** Jinja2 server-rendering limits frontend interactivity, real-time visual streaming, and operator dashboard responsiveness.
2. **In-Process Synchronous Execution:** Long-running deep network scans and heavy telemetry processing block WSGI workers without a dedicated message queue (Redis/Celery).
3. **Thread-Based Background Jobs:** In-memory threading does not survive multi-replica horizontally scaled control planes.
4. **Lack of Compile-Time Schema Contracts:** No OpenAPI/Pydantic contract generation between backend APIs and frontend UI clients.
