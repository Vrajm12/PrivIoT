# PRIVIOT SHIELD — REDIS + CELERY WORKER ARCHITECTURE
**Version:** 3.0.0-PHASE-C  
**Date:** August 31, 2026  
**Status:** IMPLEMENTED & VERIFIED (79/79 Tests Passing)

---

## 1. Asynchronous Execution Topology

PrivIoT Shield integrates Redis 7.x and Celery 5.x as an asynchronous operational worker layer to handle compute-intensive telemetry processing, continuous baseline sweeps, and scheduled operations:

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│  Edge Collector │ ───►  │  FastAPI (ASGI) │ ───►  │ PostgreSQL (DB) │
│     Sensors     │       │ Control Plane   │       │ Authoritative   │
└─────────────────┘       └────────┬────────┘       └─────────────────┘
                                   │
                           (Enqueue Task ID)
                                   │
                                   ▼
                          ┌─────────────────┐
                          │   Redis 7 Queue │
                          │ (Transient FIFO)│
                          └────────┬────────┘
                                   │
                           (Prefetch Task)
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │      Celery Worker Fleet     │
                    ├──────────────────────────────┤
                    │ • Telemetry Ingest Pipeline  │
                    │ • 48h MUD Baseline Sweeps    │
                    │ • DNS C2 Intel & DGA Matches │
                    │ • Behavioral Drift Detection │
                    │ • Deterministic Alerts & PRI │
                    │ • Async Gateway Containment  │
                    └──────────────┬───────────────┘
                                   │
                        (Invoke Pure Engines)
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │     Pure Security Engines    │
                    │   (priviot.engines.*)        │
                    └──────────────────────────────┘
```

---

## 2. Dedicated Worker Queues & Task Routing

Task routing isolates execution queues by criticality to prevent telemetry floods from starving high-priority containment tasks:

| Queue | Routing Key Pattern | Dedicated Task Functions | SLA / Priority |
| :--- | :--- | :--- | :--- |
| **`telemetry`** | `priviot.workers.tasks.telemetry.*` | `process_observation_batch_task` | Normal (High throughput, 500 events/batch) |
| **`containment`** | `priviot.workers.tasks.containment.*` | `async_apply_containment_task` | High (Immediate gateway execution) |
| **`analytics`** | `priviot.workers.tasks.behavior.*` | `sweep_behavioral_baselines_task` | Low (Periodic background sweeps) |
| **`operations`** | `priviot.workers.tasks.collectors.*` | `evaluate_fleet_health_task` | Low (Heartbeat evaluation) |
| **`scheduler`** | `priviot.workers.tasks.scheduler.*` | `dispatch_scheduled_scans_task` | Low (Discovery sweep triggers) |

---

## 3. Celery Beat Periodic Schedules

Automated maintenance jobs are dispatched on deterministic intervals:
* **`collector-fleet-health-check`:** Runs every 60s to identify stale sensor heartbeats.
* **`periodic-behavioral-baseline-sweep`:** Runs every 300s to promote baselines past 48 hours to `STABLE`.
* **`continuous-scheduled-scan-dispatch`:** Runs every 60s to check due recurring scans.

---

## 4. Idempotency & Tenant Boundary Enforcement

1. **Primitive Parameters Only:** Tasks strictly receive primitive identifiers (`tenant_id: str`, `collector_id: int`, `intent_id: int`, `raw_events: list`). ORM models are never serialized across broker queues.
2. **Tenant Scoping Guard:** Every worker task executes a database query filtered by `tenant_id` before processing, guaranteeing that cross-tenant tasks are deterministically rejected.
3. **Deduplication:** State transitions (`APPROVED` $\to$ `APPLYING` $\to$ `VERIFIED`) and alert hashing prevent duplicate alerts upon task retries.

---

## 5. Failure Classification & Retry Policy

* **Transient Failures (Network / DB timeout):** Bounded retry up to 3 times with exponential backoff.
* **Permanent Failures (Malformed payloads / Invalid state transitions / Tenant mismatch):** Rejection without retry.
* **Audit Trail Preservation:** Every state transition and asynchronous action produces an immutable `AuditEvent` entry.
