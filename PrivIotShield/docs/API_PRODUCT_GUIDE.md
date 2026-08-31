# PRIVIOT SHIELD — FASTAPI REST CONTROL PLANE PRODUCT GUIDE
**Document Version:** 1.0.0-COMMERCIAL  
**Base URL:** `/api/v2`  
**Authentication:** HTTP Bearer JWT (`Authorization: Bearer <token>`) & `X-Sensor-Token` (Collectors)  

---

## 1. API Architecture Overview

The PrivIoT Shield control plane provides high-throughput, typed REST endpoints for all SOC operations, device management, and sensor telemetry.

```
/api/v2
├── /auth            (Login, Token Refresh, Current User)
├── /tenants         (Multi-Tenant Provisioning & Isolation)
├── /sites           (Facility Management & Scopes)
├── /collectors      (Sensor Enrollment, Heartbeats, Telemetry Ingest)
├── /assets          (Auto-Discovered Inventory & Trust Profiles)
├── /behavior        (48h Baselines, MUD Profiles & Drift Feeds)
├── /exposure        (PRI-v2 Risk Scoring Engine & Formula Forensics)
├── /alerts          (Incident Forensics, Triage, Ack, Resolve)
├── /containment     (Rule Preview, Approval Gate, Apply, Rollback)
├── /audit           (Immutable Audit Trail Records)
├── /reports         (Executive Posture & Inventory Summaries)
└── /system          (Health Probes, Queue Latencies, DR Readiness)
```

---

## 2. Core API Endpoint Reference

### 1. Ingest Batch Telemetry
* **Endpoint:** `POST /api/v2/collectors/telemetry`
* **Auth:** `X-Sensor-Token: <pre-shared-token>`
* **Payload:** Array of observation objects (timestamp, src_ip, dst_ip, src_mac, dst_port, protocol, dns_query).
* **Response:** `{ "status": "enqueued", "batch_id": "b-104", "count": 50 }` (Async worker offload).

### 2. Query Asset Trust Profile
* **Endpoint:** `GET /api/v2/assets/{id}`
* **Auth:** Bearer JWT (`VIEWER`, `OPERATOR`, `APPROVER`, `ADMIN`)
* **Response:** Complete 11-category asset metadata, confidence score, open ports, baseline state, and PRI score.

### 3. Containment Intent Preview & Approval
* **Preview:** `POST /api/v2/containment/preview` (Returns synthesized iptables rules and preserved safe flow list).
* **Approve:** `POST /api/v2/containment/approve` (Requires role `APPROVER` or `ADMIN`).
* **Apply:** `POST /api/v2/containment/apply` (Dispatches rules to gateway and records verification).
* **Rollback:** `POST /api/v2/containment/rollback` (1-click emergency state reversion).
