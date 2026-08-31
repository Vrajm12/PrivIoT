# PRIVIOT SHIELD — TARGET ARCHITECTURE SPECIFICATION (2026–2027)
**Document Version:** 2.0.0-PROD-TARGET  
**Design Authority:** Chief Product Architect & Principal Security Engineer  
**Architecture Model:** Modular Monolith Control Plane + Decoupled Async Workers + Distributed Edge Collectors

---

## 1. Architectural Strategy: Modular Monolith vs Microservices

### Decision: MODULAR MONOLITH CONTROL PLANE
**Verdict:** **APPROVED (Modular Monolith)**. Microservices are explicitly **REJECTED** for the PrivIoT Shield control plane.

### Rationale:
1. **Domain Cohesion:** Device identity, behavioral baselines, vulnerability intelligence, PRI risk scoring, and containment state machines operate on deeply interrelated data entities (`Asset`, `Observation`, `Alert`, `ContainmentIntent`). Microservices would introduce distributed transactions, dual-write consistency hazards, network serialization overhead, and heavy DevOps operational drag.
2. **Pilot Simplicity:** Commercial mid-market enterprise and MSSP pilots require single-node or lightweight multi-node cluster deployments with zero architectural fragility.
3. **Internal Modular Boundaries:** Clear Python module boundaries (Domain Packages: `identity/`, `behavior/`, `intel/`, `containment/`, `fleet/`, `tenancy/`) provide all the maintainability benefits of microservices without distributed network latency.

```
+-------------------------------------------------------------------------------+
|                      TARGET MODULAR MONOLITH TOPOLOGY                         |
+-------------------------------------------------------------------------------+
|                                                                               |
|   +-----------------------------------------------------------------------+   |
|   |                        Next.js Frontend (SPA)                         |   |
|   |   - React 19 / TypeScript / Tailwind CSS / Radix UI (Dark SOC Theme)  |   |
|   |   - TanStack Query (Data Fetching) + SSE Client (Live Telemetry)      |   |
|   +-----------------------------------------------------------------------+   |
|                                      │                                        |
|                        HTTPS / JSON  │  Server-Sent Events (SSE)              |
|                                      ▼                                        |
|   +-----------------------------------------------------------------------+   |
|   |                 FastAPI Control Plane (Python 3.12)                   |   |
|   |                                                                       |   |
|   |   [ API Gateway & Ingestion Layer ]                                   |   |
|   |     ├── /api/v1 (REST Management: Assets, Alerts, Reports, RBAC)      |   |
|   |     ├── /api/v1/telemetry/ingest (High-Speed Ingestion Gateway)        |   |
|   |     └── /api/v1/events/stream (Server-Sent Events Real-Time Feed)     |   |
|   |                                                                       |   |
|   |   [ Modular Security Engines (Pure Domain Logic) ]                    |   |
|   |     ├── Asset Reconciliation & Calibrated Fingerprinting              |   |
|   |     ├── 48h Synthetic MUD Behavioral Baseline & Drift Engine          |   |
|   |     ├── Authoritative CVE / CISA KEV / EPSS / DGA Threat Intel        |   |
|   |     ├── Mathematical PRI-v2 Dynamic Risk Engine                       |   |
|   |     └── Deterministic 8-State Containment Engine (iptables/Pi-hole)   |   |
|   +-----------------------------------------------------------------------+   |
|                         │                               │                     |
|           SQLAlchemy 2  │                               │ Redis Protocol      |
|           AsyncPG       ▼                               ▼                     |
|   +--------------------------+             +--------------------------+       |
|   |      PostgreSQL 16       |             |         Redis 7          |       |
|   | - Canonical Assets       |             | - Telemetry Ingest Queue |       |
|   | - Append-Only Events     |             | - Pub/Sub (SSE Feed)     |       |
|   | - Baselines & Intents    |             | - Ephemeral Rate Limits  |       |
|   | - Tenant RBAC & Audit    |             | - Celery Task Broker     |       |
|   +--------------------------+             +--------------------------+       |
|                                                         │                     |
|                                                         ▼                     |
|                                            +--------------------------+       |
|                                            |      Celery Workers      |       |
|                                            | - Deep Network Probing   |       |
|                                            | - 48h Baseline Sweeps    |       |
|                                            | - PDF Report Generation  |       |
|                                            | - Webhook Dispatch       |       |
|                                            +--------------------------+       |
+-------------------------------------------------------------------------------+
```

---

## 2. End-to-End Real-Time Data Flow

```
[ Distributed Edge Collectors ]
  │
  ▼ 1. HTTPS POST /api/v1/telemetry/ingest (Bearer Token + JSON Batch <= 1000)
[ FastAPI Ingestion Gateway ]
  │
  ├── 2. Authenticate Collector (SHA-256 Token Lookup)
  ├── 3. Validate Pydantic Schema
  └── 4. Push Batch to Redis Ingestion Queue & Return 202 Accepted (<10ms)
        │
        ▼
[ Background Processing Pipeline (Celery / Async Task Worker) ]
  │
  ├── 5. Asset Reconciliation & Correlation (IP / MAC / DHCP Option 55/60)
  ├── 6. Append Immutable Observation Event (PostgreSQL)
  ├── 7. Evaluate 48h Synthetic MUD Baseline (Authorized Flows & Domains)
  ├── 8. Run DGA Entropy & C2 Threat Intelligence on DNS Queries
  ├── 9. Detect Behavioral Drift (Unauthorized External Egress / C2 Contact)
  │        │
  │        ├──► No Drift: Update Asset last_seen timestamp
  │        │
  │        └──► Drift Detected:
  │               ├── 10. Generate Deterministic Alert (Deduplicated SHA-256)
  │               ├── 11. Calculate PRI-v2 Score Update (+0.6 egress / +1.5 C2)
  │               ├── 12. Evaluate Containment Intent (Draft iptables/Pi-hole rule)
  │               ├── 13. Preserve Safe Flows (NTP / DNS / Gateway verified)
  │               ├── 14. Record Audit Log Entry
  │               └── 15. Publish Event to Redis Pub/Sub channel "tenant:{id}:events"
  │                           │
  │                           ▼
  │               [ FastAPI SSE Endpoint: /api/v1/events/stream ]
  │                           │
  │                           ▼
  │               [ Next.js SOC Dashboard (Real-Time Update without page reload) ]
```

---

## 3. Technology Stack & Component Specifications

### 3.1 Frontend (Next.js 14+ SPA Architecture)
* **Framework:** Next.js 14+ (App Router, Static/Client SPA mode, zero Node.js server dependencies if deployed as static bundle behind reverse proxy or standalone container).
* **Language:** TypeScript 5.x (Strict mode enabled, compile-time schema safety).
* **Styling:** Tailwind CSS 3.4+ configured with the locked **Dark SOC Design System** tokens (`#0B0D0F` bg, `#111418` surface, `#5EE6C1` accent, semantic severity colors).
* **UI Components:** Radix UI primitives / shadcn-ui (accessible dialogs, dropdowns, tabs, dense data tables).
* **State & Data Fetching:** TanStack Query v5 (React Query) for caching, optimistic updates, and background refetching.
* **Real-Time Client:** `EventSource` (SSE) listener with automatic reconnect and state reconciliation.

### 3.2 Backend (FastAPI Control Plane)
* **Framework:** FastAPI (ASGI, Python 3.12).
* **Data Validation:** Pydantic v2 (sub-millisecond parsing and validation, automatic OpenAPI 3.1 JSON schema generation).
* **ORM & Database Client:** SQLAlchemy 2.0 (AsyncIO with `asyncpg` driver for PostgreSQL).
* **Authentication & RBAC:** OAuth2 / JWT bearer tokens for operators and API keys; SHA-256 pre-shared tokens for edge collectors. Server-side dependency injection for RBAC enforcement (`Depends(require_role("soc_operator"))`).

### 3.3 Asynchronous Queue & Workers
* **Task Broker & Result Backend:** Redis 7 (Alpine).
* **Worker Framework:** Celery 5.x or Python RQ.
* **Workloads Handled by Workers:**
  1. Deep Network Probes (Nmap / ARP subnet sweep).
  2. Batch Baseline Re-calculation (48-hour rolling window decay).
  3. Retention Purging & Telemetry Expiry (Daily scheduled cron).
  4. Enterprise Report Generation (PDF/CSV compiling via ReportLab/Pandas).
  5. Outbound Webhook & Notification Dispatch (Twilio, Webhooks, Slack).

### 3.4 Collector Architecture (Edge Sensors)
* **Short-Term (Phase 1–4 Compatible):** Python 3.11 Scapy daemon (`sensor/priviot_sensor.py`) containerized or run as a Linux `systemd` service.
* **Mid/Long-Term Evaluation (Go Daemon):**
  * *Recommendation:* Build `priviot-collector-go` (using Google `gopacket` / `pcap`).
  * *Justification:* Single static binary (<15MB RAM vs 120MB for Python Scapy), zero runtime dependency on Python interpreters, seamless execution on resource-constrained IoT gateways, pfSense/FreeBSD appliances, and Ubiquiti UniFi OS.

---

## 4. Security & Hardening Architecture

1. **Strict Tenant Separation:** PostgreSQL Row-Level Security (RLS) or mandatory ORM query filters enforced via FastAPI middleware.
2. **Deterministic IDOR Elimination:** All entity mutations require explicit compound lookups (`tenant_id == current_user.tenant_id` and `id == requested_id`).
3. **No Dynamic CLI String Interpolation:** Firewall adapters continue using parameterized subprocess calls (`subprocess.run(["iptables", "-A", ...])`) or direct REST APIs.
4. **Zero Unencrypted Telemetry:** Edge collectors enforce HTTPS (TLS 1.3) with optional mutual TLS (mTLS) or SHA-256 token verification.
5. **Rate Limiting:** Ephemeral sliding-window rate limiting in Redis (100 req/min for general API, 10,000 req/min for collector ingestion).

---

## 5. Production Observability & Monitoring

* **Health Probes:** `/healthz` (liveness: process responsive) and `/readyz` (readiness: PostgreSQL + Redis connections verified).
* **Metrics:** Prometheus exporter (`/metrics`) exposing ingestion rate, drift detection latency, active containment count, collector heartbeat lag, and queue depth.
* **Structured Logging:** Structured JSON logging (Loguru / Python logging) with correlation IDs (`X-Request-ID`, `tenant_id`, `asset_id`).
