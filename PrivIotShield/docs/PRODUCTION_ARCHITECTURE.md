# PRIVIOT SHIELD — ENTERPRISE PRODUCTION ARCHITECTURE
**Version:** 6.0.0-PRODUCTION  
**Date:** August 31, 2026  
**Status:** FULLY IMPLEMENTED & PRODUCTION READY  

---

## 1. Executive Summary

PrivIoT Shield is an enterprise continuous IoT Security Operations Center (SOC) platform designed for deterministic asset discovery, continuous behavioral drift detection, explainable PRI-v2 risk scoring, and verified firewall micro-segmentation.

The platform employs a hardened **Modular Monolith** architecture with strict separation between the Next.js frontend, FastAPI control plane, PostgreSQL source of truth, Redis event bus, Celery background workers, and distributed edge sensor collectors.

---

## 2. System Topology & Trust Boundaries

```
[ Edge Sensor Nodes ] ──(SHA-256 Token)──► [ FastAPI Ingestion API ] ──► [ PostgreSQL 16 (DB) ]
                                                   │                            ▲
                                         (Enqueue Observation)                 │ (Read/Write)
                                                   ▼                            │
                                           [ Redis 7 Broker ]                   │
                                                   │                            │
                                           (Prefetch Task)                      │
                                                   ▼                            │
                                       [ Celery Worker Fleet ] ─────────────────┘
                                       • Behavioral Engine (48h MUD)
                                       • DNS Intelligence & C2 Hunter
                                       • PRI-v2 Mathematical Engine
                                       • Containment Verification
                                                   │
                                            (Publish Event)
                                                   ▼
                                         [ Redis 7 Pub/Sub ]
                                         `priviot.events.{tenant_id}`
                                                   │
                                                   ▼
                                      [ FastAPI SSE (/events/stream) ]
                                                   │
                                            (Server-Sent Events)
                                                   ▼
[ Enterprise SOC Operator ] ◄────────── [ Next.js 14 Web Console ]
```

---

## 3. Core Component Responsibilities & Security Boundaries

| Component | Technology | Primary Responsibility | Security & Isolation Boundary |
| :--- | :--- | :--- | :--- |
| **Frontend Console** | Next.js 14 + React 18 + TypeScript | Real-time SOC dashboard, triage feeds, Device Trust Profile. | Strictly client-side presentation. Zero secrets in JS bundles. |
| **Control Plane API** | FastAPI 0.115 + Pydantic v2 | High-throughput REST API, SSE streaming, authentication, RBAC. | Enforces tenant scoping, role checks, and input schema validation. |
| **Authoritative DB** | PostgreSQL 16 | ACID durable persistence for assets, baselines, alerts, audit logs. | Row-level `tenant_id` scoping on all queries. Parameterized SQL. |
| **Event / Task Broker**| Redis 7 | Transient task queuing (`celery`) and Pub/Sub event transport. | Ephemeral transport only; protected via auth tokens; no durable secrets stored. |
| **Asynchronous Fleet**| Celery 5.4 + Python 3.10 | Telemetry correlation, drift sweep, scan dispatch, containment execution. | Isolated worker containers; retries bounded by exponential backoff. |
| **Edge Sensor Fleet** | Python / Scapy / BPF | Passive packet inspection, DNS observation, mDNS/SSDP extraction. | Authenticated via SHA-256 pre-shared tokens; restricted to ingest endpoints. |

---

## 4. Architectural Invariants

1. **PostgreSQL is the Sole Authority:** Redis and SSE are transient transport channels. If Redis or SSE goes down, zero security data is lost.
2. **Immutable Mathematical Determinism:** PRI-v2 scores are strictly calculated via $\text{PRI} = \min(10.0, [(\text{Threat} + \text{KEV} + \text{EPSS}) \times E] + B + C)$.
3. **8-State Containment Safety:** Containment rules cannot jump to `VERIFIED` without passing through approval, application, and real provider verification.
4. **Hard Multi-Tenant Isolation:** Zero cross-tenant data leakage across REST endpoints, Celery workers, or real-time SSE streams.
