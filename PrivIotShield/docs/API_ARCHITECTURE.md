# PRIVIOT SHIELD — API CONTROL PLANE ARCHITECTURE
**Version:** 2.0.0-PHASE-B  
**Date:** August 31, 2026  
**Status:** IMPLEMENTED & VERIFIED (72/72 Tests Passing)

---

## 1. Dual Control-Plane Topology (Side-by-Side)

PrivIoT Shield runs a dual control-plane topology where modern FastAPI ASGI routers coexist side-by-side with the legacy Flask WSGI application:

```
                  ┌──────────────────────────────────────────────┐
                  │                 API GATEWAYS                 │
                  ├──────────────────────┬───────────────────────┤
                  │     Flask WSGI       │     FastAPI ASGI      │
                  │ (Legacy Web + UI)    │ (v2 Control Plane)    │
                  │   Port 5000          │   Port 8000 / /api/v2 │
                  └──────────┬───────────┴───────────┬───────────┘
                             │                       │
                             ▼                       ▼
                  ┌──────────────────────────────────────────────┐
                  │          APPLICATION SERVICES LAYER          │
                  │  (CollectorManager, Reports, Scheduler, ...) │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │           PURE SECURITY ENGINES              │
                  │ (ExposureEngine, BehavioralEngine, DNSIntel, │
                  │  VulnIntel, ContainmentEngine, Telemetry)    │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │          PERSISTENCE & DATA MODELS           │
                  │     (SQLAlchemy: Asset, Observation, Alert)  │
                  └──────────────────────────────────────────────┘
```

### Core Invariants:
1. **Zero Duplicate Security Logic:** Both Flask and FastAPI call the exact same domain engines (`priviot.engines.*`).
2. **Single Database Session Model:** FastAPI and Flask share identical SQLAlchemy entity schemas with zero database alterations.
3. **Seamless Independent Execution:** FastAPI can start independently (`uvicorn priviot.api.fastapi_app:app`) while Flask continues serving existing web dashboards.

---

## 2. Pydantic v2 Schema Registry & Contracts

All FastAPI endpoints validate requests and responses against strict Pydantic v2 schemas:

| Domain | Entity / Endpoint | Schema Class | Purpose |
| :--- | :--- | :--- | :--- |
| **Common** | All Error Responses | `ErrorResponse` / `ErrorDetail` | Predictable machine-readable error format |
| **Auth** | `/api/v2/auth/login` | `LoginRequest` / `TokenResponse` | Operator authentication and API Key generation |
| **Assets** | `/api/v2/assets` | `AssetListResponse` / `AssetResponse` | Multi-tenant filtered device inventory |
| **Trust** | `/api/v2/assets/{id}/trust-profile` | `TrustProfileResponse` | 11-category Device Trust Profile |
| **Alerts** | `/api/v2/alerts` | `AlertListResponse` / `AlertResponse` | Deterministic security alerts feed |
| **Telemetry**| `/api/v2/telemetry/ingest` | `TelemetryIngestBatch` / `TelemetryIngestResponse` | Sensor observation ingestion |
| **Containment**| `/api/v2/containment/preview` | `ContainmentPreviewRequest` / `ContainmentPolicyResponse` | Micro-segmentation rule preview |
| **Collectors**| `/api/v2/collectors/register`| `CollectorEnrollRequest` / `CollectorEnrollResponse` | Sensor node provisioning |
| **Behavior** | `/api/v2/behavior/drift` | `DriftFeedResponse` / `BehavioralDriftResponse` | Telemetry baseline drift events |
| **Exposure** | `/api/v2/exposure/calculate-pri`| `PriCalculationRequest` / `PriCalculationResponse` | Explainable PRI-v2 risk scoring |

---

## 3. Server-Side Security Boundaries

### 3.1 Hard Multi-Tenant Isolation
Tenant isolation is enforced in FastAPI dependencies and database queries via `tenant_id`:
* Headers: `X-Tenant-ID` or `X-Tenant` (sanitized and scoped).
* Enforcement: Every asset, alert, collector, observation, baseline, and containment intent is queried strictly by `filter_by(tenant_id=tenant_id)`.
* Result: A request from `Tenant A` targeting an entity belonging to `Tenant B` deterministically returns HTTP 404 (zero information leakage).

### 3.2 Role-Based Access Control (RBAC)
Role hierarchy enforced server-side via `require_role(min_role)`:
$$\text{VIEWER (1)} < \text{ANALYST (2)} < \text{OPERATOR (3)} < \text{APPROVER (4)} < \text{ADMIN (5)}$$

* High-risk containment approvals require `APPROVER` or `ADMIN`.
* Gateway execution & sensor enrollment require `OPERATOR` or higher.
* Unauthorized actions return HTTP 403 Forbidden with role context.

### 3.3 Collector Pre-Shared Token Authentication
Sensor nodes authenticate via `X-Sensor-Token` using cryptographic SHA-256 hash lookups against the active collector registry with automatic heartbeat tracking.

---

## 4. Request Lifecycle & Standard Error Contract

### Request Flow
```
[ Incoming HTTP Request ]
          │
          ▼
[ Correlation Middleware ] ──► Injects / Propagates `X-Request-ID` & records latency
          │
          ▼
[ Auth & Tenant Dependency ] ──► Resolves User / Collector and verifies Tenant Scope
          │
          ▼
[ RBAC Permission Guard ] ──► Validates minimum role hierarchy
          │
          ▼
[ Domain Router & Service ] ──► Executes pure engine logic
          │
          ▼
[ Pydantic Serializer ] ──► Emits typed response with headers (`X-Request-ID`, `X-Response-Time-Ms`)
```

### Standard Error Contract
All API errors follow the standard format:
```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Asset with ID 999 not found in tenant scope.",
    "request_id": "req-777a8b9c",
    "details": {}
  }
}
```
