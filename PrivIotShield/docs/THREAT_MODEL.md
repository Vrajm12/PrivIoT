# PRIVIOT SHIELD — SECURITY THREAT MODEL & STRIDE ANALYSIS
**Version:** 6.0.0-PRODUCTION  
**Date:** August 31, 2026  

---

## 1. Threat Actors & Capabilities

| Threat Actor | Motivation | Capability Level | Target Assets |
| :--- | :--- | :--- | :--- |
| **Malicious Tenant / MSSP Client** | Cross-tenant data exfiltration | High (API tampering, IDOR) | Foreign tenant assets, alerts, telemetry |
| **Compromised Edge Collector** | Telemetry poisoning, spoofing | Medium (Pre-shared key theft)| Observation pipeline, baseline profiles |
| **Internal Malicious Operator** | Unauthorized micro-segmentation| High (Legitimate credentials)| Gateway firewall rules, device availability|
| **External Network Adversary** | C2 communication, lateral move | High (Exploit staging, DGA) | IoT firmware, network gateways |

---

## 2. STRIDE Matrix & Production Countermeasures

| Threat Category | Attack Vector | Security Countermeasure | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Collector token forging | SHA-256 pre-shared tokens with revocation support | LOW (Token theft mitigated via rotation) |
| **Tampering** | Parameterized SQL injection | SQLAlchemy parameterized queries & Pydantic validation | NEGLIGIBLE |
| **Repudiation** | Unauthorized containment action | Immutable `AuditEvent` log with actor attribution & timestamps | NEGLIGIBLE |
| **Information Disclosure**| IDOR across tenant boundaries | Strict server-side `tenant_id` query filtering | NEGLIGIBLE |
| **Denial of Service** | Telemetry batch flood | Bounded batch sizes (max 500) & Celery queue quotas | LOW |
| **Elevation of Privilege**| Viewer executing containment | Strict 4-tier RBAC (`require_role("operator"/"approver")`)| NEGLIGIBLE |
