# PRIVIOT SHIELD — DATA RETENTION & LIFECYCLE POLICY
**Document Version:** 1.0.0-COMMERCIAL  
**Scope:** Telemetry, Observations, Audit Trails, and System State  

---

## 1. Storage Tiering & Durability Model

PrivIoT Shield maintains a strict distinction between **Transient Ingestion State** and **Durable Authoritative Records**:

```
┌─────────────────────────────────────────────────────────────┐
│ TRANSIENT TIER (Redis In-Memory)                           │
│ - Raw packet observation queue (TTL: 1 Hour)                │
│ - Real-time SSE Pub/Sub channel (Ephemeral)                 │
│ - Worker celery result backend (TTL: 24 Hours)              │
└──────────────────────────────┬──────────────────────────────┘
                               │ (Worker Batch Commit)
┌──────────────────────────────▼──────────────────────────────┐
│ DURABLE TIER (PostgreSQL 16 Storage)                        │
│ - Assets, Devices & MAC Identities (Indefinite / Permanent) │
│ - 48-Hour Baseline MUD Profiles (Permanent until retrained) │
│ - Security Alerts & Forensic Evidence (Default: 365 Days)   │
│ - Containment Actions & Policy Verifications (365 Days)     │
│ - Compliance Audit Logs & User Actions (Default: 7 Years)   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Retention Schedules & Governance

| Data Entity | Storage Location | Retention Period | Purge Mechanism | Compliance Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Telemetry Queue** | Redis Task Broker | 1 Hour | Automatic TTL eviction | Transient load buffer only |
| **Asset Metadata** | PostgreSQL (`assets`) | Permanent | Explicit admin purge | IT Asset Inventory compliance |
| **Behavioral Baselines** | PostgreSQL (`baselines`)| Permanent | Replaced on model retraining| MUD RFC 8520 auditability |
| **Security Alerts** | PostgreSQL (`alerts`) | 365 Days (Configurable) | Celery Beat nightly retention purge | Incident response compliance |
| **Audit Logs** | PostgreSQL (`audit_logs`)| 7 Years (Configurable) | Read-only append; never purged early | SOC 2 / HIPAA / ISO 27001 |
