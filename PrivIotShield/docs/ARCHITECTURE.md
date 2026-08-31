# PRIVIOT SHIELD — DOMAIN ARCHITECTURE & PACKAGE SPECIFICATION
**Version:** 1.0.0-PHASE-A  
**Date:** August 31, 2026  
**Status:** IMPLEMENTED & VERIFIED (62/62 Tests Passing)

---

## 1. Modular Monolith Architecture & Domain Boundaries

PrivIoT Shield is organized into clean domain packages under `priviot/`:

```
priviot/
├── __init__.py               # Package metadata and versioning (v4.0.0)
│
├── api/                      # Presentation and API Gateways
│   ├── legacy/               # Legacy Flask route proxies
│   ├── routes/               # API route definitions
│   └── schemas/              # Input/Output data transfer contracts
│
├── data/                     # Persistence & Storage Domain
│   ├── models/               # SQLAlchemy Models (Canonical + Legacy)
│   └── database.py           # Session & Connection Lifecycle
│
├── engines/                  # Pure Domain Security & Analytics Engines
│   ├── exposure/             # Mathematical PRI-v2 Risk Scoring Engine
│   ├── behavior/             # 48h Synthetic MUD Baselines & Drift Detection
│   ├── dns/                  # Shannon Entropy DGA & C2 Threat Intel
│   ├── vuln_intel/           # Deterministic CVE / CISA KEV / EPSS Catalog
│   ├── fingerprint/          # Deterministic Multi-Priority Fingerprinting
│   ├── containment/          # 8-State Firewall Micro-Segmentation Lifecycle
│   ├── discovery/            # Safe Subnet Probe & Deep Discovery
│   └── telemetry/            # Batch Telemetry Ingestion & Correlation
│
├── security/                 # System Security & Policy Enforcement
│   ├── rbac/                 # Server-Side Role Hierarchy (Viewer -> Admin)
│   ├── pilot/                # Pilot Mode Isolation & Safety Flow Analyzer
│   └── validation/           # Scanning Boundary Guards (SSRF/Loopback/CIDR)
│
├── integrations/             # External Gateway & Commercial Connectors
│   ├── firewall/             # iptables, Pi-hole, pfSense, UniFi Adapters
│   └── billing/              # Idempotent Stripe Webhook Processor
│
└── services/                 # Operational Fleet & Management Subsystems
    ├── collectors/           # Sensor Fleet Token Auth & Health Sweeps
    ├── reporting/            # 7 Enterprise Database Aggregation Reports
    ├── scheduler/            # Continuous Discovery & Heartbeat Monitor
    ├── backup/               # Cryptographic Snapshots & Integrity Validator
    ├── entitlements/         # Quota Enforcement & Retention Purging
    └── mssp/                 # Cross-Tenant MSSP Posture Aggregator
```

---

## 2. Dependency Direction Principles

The architecture strictly enforces unidirectional dependency flow:

```
[ API Layer (Flask / FastAPI) ]
              │
              ▼
    [ Application Services ]
              │
              ▼
    [ Security & Domain Engines ]
              │
              ▼
   [ Data Models & Persistence ]
```

### Architectural Rules:
1. **Engines are Framework-Independent:** `priviot.engines.*` modules contain zero Flask or HTTP request dependencies.
2. **Zero Circular Imports:** Data models reside at the lowest dependency tier (`priviot.data.models`); engines import models, but models never import engines.
3. **Deterministic Formulas are Sacred:** Risk algorithms (PRI-v2), baseline thresholds (48-hour window), DGA entropy thresholds (3.8 bits), and containment state transitions are mathematically identical across all entry points.

---

## 3. Migration State Tracking

| Subsystem | State | Current Implementation | Target Transition |
| :--- | :--- | :--- | :--- |
| **Domain Packages** | **CURRENT** | Modular packages established under `priviot/` | Fully segregated |
| **Data Models** | **CURRENT** | Canonical models (`Asset`, `Observation`, `Alert`, `ContainmentIntent`, `Collector`) | Fully canonical |
| **Security Logic** | **CURRENT** | 100% pure domain Python logic | Unchanged / Preserved |
| **Control Plane** | **MIGRATING** | Flask 3.1 WSGI Monolith | FastAPI ASGI Router (Phase B) |
| **Background Jobs**| **MIGRATING** | In-process Python daemon threads | Celery 5 + Redis 7 (Phase C) |
| **Presentation** | **MIGRATING** | 25 Jinja2 Templates + Dark SOC CSS | Next.js 14+ TypeScript SPA (Phase D) |
