# PRIVIOT SHIELD — 4-TIER ROLE-BASED ACCESS CONTROL (RBAC) MATRIX
**Document Version:** 1.0.0-PROD  
**Enforcement:** Server-Side JWT Claims + Dependency Injection (`require_role`)  

---

## 1. Role Definitions

| Role | Scope & Responsibility | Typical Persona |
| :--- | :--- | :--- |
| **`VIEWER`** | Read-only observation and forensics. Cannot modify any state. | Executive, Compliance Auditor, Guest Analyst |
| **`OPERATOR`** | Daily operations, alert triage, sensor provisioning, and policy preview. | Tier 1/2 SOC Analyst, IT Helpdesk |
| **`APPROVER`** | Dual-control containment authorization and emergency rollback. | Security Lead, CISO, Plant Operations Manager |
| **`ADMIN`** | Complete system administration, tenant onboarding, and user management. | SOC Director, Cloud Infrastructure Lead |

---

## 2. Granular Permissions Matrix

| Operational Action | REST Endpoint | `VIEWER` | `OPERATOR` | `APPROVER` | `ADMIN` |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **View Dashboard & Fleet** | `GET /api/v2/assets` | ✓ | ✓ | ✓ | ✓ |
| **View Forensic Alert Evidence** | `GET /api/v2/alerts/{id}` | ✓ | ✓ | ✓ | ✓ |
| **Acknowledge Alert** | `POST /api/v2/alerts/{id}/ack` | ✗ | ✓ | ✓ | ✓ |
| **Resolve Alert** | `POST /api/v2/alerts/{id}/resolve` | ✗ | ✓ | ✓ | ✓ |
| **Preview Containment Rules** | `POST /api/v2/containment/preview` | ✗ | ✓ | ✓ | ✓ |
| **Approve Containment Intent** | `POST /api/v2/containment/approve` | ✗ | ✗ | ✓ | ✓ |
| **Apply / Rollback Containment** | `POST /api/v2/containment/apply` | ✗ | ✗ | ✓ | ✓ |
| **Provision / Rotate Collector Token** | `POST /api/v2/collectors/register` | ✗ | ✓ | ✓ | ✓ |
| **Generate Compliance Reports** | `GET /api/v2/reports` | ✓ | ✓ | ✓ | ✓ |
| **Manage Tenant & User Accounts** | `POST /api/v2/tenants` | ✗ | ✗ | ✗ | ✓ |
