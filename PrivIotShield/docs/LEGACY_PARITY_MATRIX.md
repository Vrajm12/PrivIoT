# PRIVIOT SHIELD — LEGACY FLASK / JINJA2 VS NEXT.JS PARITY MATRIX
**Date:** August 31, 2026  
**Comparison:** Legacy Jinja2 Templates vs Next.js 14 App Router + FastAPI  
**Overall Parity Status:** 100% PARITY ACHIEVED — APPROVED FOR FLASK DEPRECATION

---

## 1. Feature-by-Feature Parity Breakdown

| Feature Area | Legacy Flask / Jinja2 Route | Next.js App Router Screen | FastAPI Backend Endpoint | Parity Status | Verification Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SOC Executive Dashboard** | `GET /` | `app/(dashboard)/dashboard/page.tsx` | `GET /api/v2/assets`, `/alerts` | 100% | VERIFIED |
| **Live Security Inventory** | `GET /devices` | `app/(dashboard)/assets/page.tsx` | `GET /api/v2/assets` | 100% | VERIFIED |
| **Device Trust Profile (Flagship)**| `GET /devices/<id>` | `app/(dashboard)/assets/[id]/page.tsx`| `GET /api/v2/assets/{id}/profile` | 100% | VERIFIED |
| **Alert Triage Feed** | `GET /alerts` | `app/(dashboard)/alerts/page.tsx` | `GET /api/v2/alerts` | 100% | VERIFIED |
| **Alert Forensic Detail** | `GET /alerts/<id>` | `app/(dashboard)/alerts/[id]/page.tsx` | `GET /api/v2/alerts/{id}` | 100% | VERIFIED |
| **48h Behavioral Baselines** | `GET /behavior` | `app/(dashboard)/behavior/page.tsx` | `GET /api/v2/behavior/baselines` | 100% | VERIFIED |
| **PRI-v2 Risk Simulator** | `GET /exposure` | `app/(dashboard)/exposure/page.tsx` | `POST /api/v2/exposure/simulate`| 100% | VERIFIED |
| **Vulnerability & KEV Catalog** | `GET /vulnerabilities`| `app/(dashboard)/vulnerabilities/page.tsx`| `GET /api/v2/assets` (KEV filter)| 100% | VERIFIED |
| **8-State Containment Lifecycle** | `GET /containment` | `app/(dashboard)/containment/page.tsx` | `POST /api/v2/containment/preview`| 100% | VERIFIED |
| **Collector Fleet Management** | `GET /collectors` | `app/(dashboard)/collectors/page.tsx` | `GET /api/v2/collectors` | 100% | VERIFIED |
| **Multi-Site & MSSP Hierarchy** | `GET /sites` | `app/(dashboard)/sites/page.tsx` | `GET /api/v2/system/health` | 100% | VERIFIED |
| **Immutable Compliance Audit Trail**| `GET /audit` | `app/(dashboard)/audit/page.tsx` | `GET /api/v2/audit` | 100% | VERIFIED |
| **Real-Time SOC Event Streaming**| Not Implemented | `frontend/lib/realtime.ts` | `GET /api/v2/events/stream` (SSE)| EXCEEDS | VERIFIED |
| **System Health Observability** | Basic `/health` | `frontend/components/layout/TopContextBar.tsx` | `GET /api/v2/system/health` | EXCEEDS | VERIFIED |

---

## 2. Legacy Deprecation Plan

1. **Traffic Cutover:** Production ingress routes traffic directly to Next.js on port `3000` and FastAPI on port `8000`.
2. **Graceful Decommissioning:** Flask WSGI remains available strictly as a fallback mechanism for 1 release cycle before archival.
