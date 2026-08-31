# PRIVIOT SHIELD — SOC PRODUCTIZATION & OPERATOR INVESTIGATION WORKFLOW
**Version:** 6.0.0-SOC-PRODUCTIZED  
**Date:** August 31, 2026  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary & Operator Decision Hierarchy

PrivIoT Shield has transitioned from an engineering console into a specialized **IoT Security Operations Console (SOC)** tailored for non-developer security analysts, SecOps teams, and MSSP operators. The platform empowers operators to instantly transition from *"Something changed"* to *"I understand exactly what happened and what I should do."*

```
                    ┌────────────────────────────────────────┐
                    │          WHAT NEEDS ATTENTION?         │
                    │   (Severity Matrix, PRI Risk, Drifts)  │
                    └───────────────────┬────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────┐
                    │             WHAT CHANGED?              │
                    │   (Chronological Real Audit Stream)    │
                    └───────────────────┬────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────┐
                    │      WHY DID THIS ALERT FIRE?          │
                    │  (Baseline vs Observed vs PRI Delta)   │
                    └───────────────────┬────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────┐
                    │       RECOMMENDATION & IMPACT          │
                    │ (Preserved Safe Flows vs Isolated WAN) │
                    └───────────────────┬────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────┐
                    │      HUMAN APPROVAL & VERIFICATION     │
                    │   (State Machine: DRAFT → VERIFIED)    │
                    └────────────────────────────────────────┘
```

---

## 2. Screen Hierarchy & Information Architecture

| Screen Path | Operator Goal | Key Information & Evidence Displayed |
| :--- | :--- | :--- |
| **`/dashboard`** | Fast triage & operational decision-making | Severity matrix (Critical/High/Med/Low), 48h Baseline learning status, Collector sensor health, "What Changed?" chronological feed with direct evidence links. |
| **`/alerts/[id]`** | Forensic investigation & root-cause analysis | **"Why did this alert fire?"** 3-column forensic chain (Baseline Expected vs Observed Flow vs Difference & PRI Impact), Target device context, Recommended micro-segmentation rule syntax, Preserved safe flows preview. |
| **`/assets/[id]`** | Device Trust Profiling (Flagship View) | 11-category tabs (Overview, Identity & Evidence, Exposure & PRI Formula Breakdown, Vulnerabilities, 48h Behavior, Observed Services, Containment Policy). |
| **`/behavior`** | Baseline & anomaly inspection | Visual comparison matrix (Expected vs Observed for Destinations, Ports, DNS Domains, Protocols), Truthful 48-hour learning window timer. |
| **`/containment`** | Safe micro-segmentation & remediation | Operational impact preview (Preserved NTP/DNS/Gateway flows vs Isolated C2 WAN egress), 8-state lifecycle, 1-click emergency rollback. |

---

## 3. "Why Did This Alert Fire?" — Forensic Evidence Chain

PrivIoT Shield strictly avoids opaque alerts like *"Suspicious behavior detected."* Every alert renders a deterministic, evidence-backed chain:

1. **Normal Baseline:** Camera normally communicates exclusively on port `554/TCP` (RTSP) and `443/TCP` (HTTPS) with approved local NVR `10.10.1.5` and broker `hik-connect.com`.
2. **Observed Flow:** Outbound connection initiated to destination `203.0.113.99:6667/TCP` with DNS resolution for `dark-iot-c2.net`.
3. **Difference & PRI Impact:** Unapproved destination IP, unapproved IRC/C2 port, authoritative DarkIoT threat intel match. Deterministic behavioral penalty (+2.5) added to base exposure score ($1.9 \to 4.4$).
4. **Authoritative Evidence Payload:** Verifiable sensor capture metadata with hardware MAC attribution and timestamp.

---

## 4. Unknown Device UX & Uncertainty Governance

PrivIoT Shield treats uncertainty as an authentic product feature rather than a system defect:
* **Truthful Base Confidence:** Unclassified devices display exact heuristic confidence (e.g. `35%`) rather than fabricated vendor guesses.
* **Why Unknown?** Explains exact missing signals (no registered IEEE OUI match, proprietary UDP payload, no standard service banners).
* **What Would Improve Identification?** Checklist of potential passive and active telemetry sources (mDNS capture, DHCP Option 55 parameter list, active banner probe).

---

## 5. Containment Impact Analysis & Safe Flow Preservation

Autonomous firewall blocking is strictly disabled (`REQUIRE_APPROVAL`). Before operator approval, the system provides transparent impact analysis:
* **✓ PRESERVED SAFE FLOWS:** NTP (`123/UDP`), DNS (`53/UDP`), Local Subnet (`10.10.1.0/24`), Local Gateway (`10.10.1.1`), Camera Streaming (`554/TCP`).
* **✗ ISOLATED THREAT FLOWS:** Unapproved external egress to `203.0.113.99:6667/TCP` and malicious C2 endpoints.

---

## 6. Audit Finding: Asset #6 Discrepancy Resolution

* **Investigated Issue:** System reported `TOTAL ASSETS = 5` in pilot tenant while controlled test referenced `Asset #6`.
* **Root-Cause Analysis:** The PostgreSQL/SQLite database uses a global auto-incrementing integer sequence for table primary keys. The initial development seed (`default_tenant`) populated Asset IDs `1, 2, 3, 4, 5`. When the pilot tenant (`tenant_pilot_01`) dynamically discovered its first 5 devices, they received primary key IDs `6, 7, 8, 9, 10`.
* **Resolution:** `Asset #6` is the first discovered asset belonging to `tenant_pilot_01`. Tenant isolation guarantees that `tenant_pilot_01` accesses only its own 5 assets (`COUNT = 5`). Zero assets were lost, orphaned, or fabricated.

---

## 7. Quality & Verification Metrics

* **Backend Tests Passing:** `95 / 95` (100% test success across 15 test suites)
* **Frontend Routes Compiled:** `14 / 14` (Static and Dynamic Next.js App Router routes)
* **TypeScript Strict Typecheck:** `PASS` (`tsc --noEmit` with 0 errors)
* **Production Build:** `PASS` (`next build` clean)
* **Security & Tenant Isolation:** `PASS`
* **Mock Production Data:** `0`
* **Database Schema Changes:** `0`
* **Security Algorithm Changes:** `0`
* **Containment Policy:** `REQUIRE_APPROVAL` (Autonomous blocking locked)
