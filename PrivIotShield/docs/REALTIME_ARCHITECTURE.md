# PRIVIOT SHIELD — REAL-TIME SECURITY OPERATIONS & OBSERVABILITY ARCHITECTURE
**Version:** 5.0.0-PHASE-E  
**Date:** August 31, 2026  
**Status:** IMPLEMENTED & VERIFIED (86/86 Tests Passing, Next.js Build Verified)

---

## 1. Real-Time Security Operations Topology

PrivIoT Shield implements a high-throughput, non-blocking real-time event pipeline that streams live security events from the Python domain engines to the Next.js SOC console:

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
                    │ • Correlate Observations     │
                    │ • Detect Behavioral Drift    │
                    │ • Evaluate DNS C2 Intel      │
                    │ • Compute PRI-v2 Risk Score  │
                    │ • Apply Micro-Segmentation   │
                    └──────────────┬───────────────┘
                                   │
                          (Emit Typed Event)
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │     EventBus (Publisher)     │
                    │  `priviot.events.{tenant_id}`│
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │   FastAPI SSE (/stream)      │
                    │ (Tenant Scoped & Heartbeat)  │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │ Next.js Realtime SOC Client  │
                    │ (`frontend/lib/realtime.ts`) │
                    └──────────────┬───────────────┘
                                   │
                   (Invalidate TanStack Queries)
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │     Live React SOC UI        │
                    │ (Dashboard, Assets, Alerts)  │
                    └──────────────────────────────┘
```

---

## 2. Authoritative vs Transport vs Presentational Separation

* **AUTHORITATIVE (Source of Truth):** PostgreSQL Database & Pure Domain Security Engines (`priviot.engines.*`). State transitions and audits are committed before event publication.
* **TRANSPORT (Ephemeral Event Bus):** Redis Pub/Sub (`priviot.events.{tenant_id}`) and FastAPI Server-Sent Events (`/api/v2/events/stream`). If transport fails, security state is never lost; the UI reconnects and reconciles from authoritative REST APIs.
* **PRESENTATIONAL (Consumer):** Next.js App Router, TanStack Query, and Tailwind CSS dark SOC components.

---

## 3. Canonical Security Event Contract

All events published over the bus follow the strict, sanitized `SecurityEvent` envelope:

| Event Type | Trigger Origin | Payload Attributes | Severity |
| :--- | :--- | :--- | :--- |
| **`ASSET_DISCOVERED`** | Telemetry correlation of new MAC/IP | `asset_id`, `ip_address`, `vendor`, `model`, `status: NEW` | `info` |
| **`BEHAVIOR_DRIFT_DETECTED`**| Flow outside learned 48h MUD baseline | `asset_id`, `drift_type`, `difference`, `confidence` | `high` / `critical` |
| **`ALERT_CREATED`** | DNS C2 indicator or severe anomaly | `alert_id`, `alert_type`, `title` | `critical` |
| **`PRI_CHANGED`** | PRI-v2 recomputed on risk shift | `asset_id`, `old_pri`, `new_pri`, `pri_level` | `high` / `info` |
| **`CONTAINMENT_STATE_CHANGED`**| Gateway rule applied / rolled back | `intent_id`, `asset_id`, `provider`, `state` | `verified` / `info` |
| **`COLLECTOR_STATUS_CHANGED`**| Heartbeat timeout or recovery | `collector_id`, `collector_name`, `status` | `critical` / `info` |

---

## 4. Hard Multi-Tenant Isolation in Real-Time Streams

1. **Tenant-Scoped Redis Channels:** Events are published strictly to `priviot.events.{tenant_id}`.
2. **Server-Side Token Scoping:** The SSE streaming endpoint (`GET /api/v2/events/stream`) establishes the tenant context via server-side session/API key dependencies.
3. **No Arbitrary Subscriptions:** Clients cannot subscribe to arbitrary tenant channels.
4. **Secret Sanitization:** The event serializer recursively purges all sensitive credentials (`password`, `auth_token_hash`, `raw_token`, `api_key`, `gateway_credentials`).

---

## 5. Reconnection & Degradation Handling

* **Periodic Keepalive Ping:** SSE stream emits `: keepalive\n\n` comments every 15s to keep connections alive through proxies and detect disconnects.
* **Exponential Backoff:** `RealtimeClient` automatically reconnects upon stream interruptions ($1\text{s} \to 1.5\text{s} \to 2.25\text{s} \dots$ up to $15\text{s}$).
* **Truthful SOC Status Indicator:**
  - `SOC LIVE` (Green pulse) when EventSource is active.
  - `SOC RECONNECTING` (Amber pulse) during transient reconnects.
  - `SOC OFFLINE` (Gray) if backend stream is unreachable.
