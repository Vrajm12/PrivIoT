# PRIVIOT SHIELD — PILOT FEEDBACK & PRODUCT IMPROVEMENT LOOP
**Document Version:** 1.0.0-COMMERCIAL  
**Purpose:** Provide structured customer feedback channels during live pilot deployments.  

---

## 1. Feedback Severity Classification

| Priority | Definition | Example Scenario | Response Target |
| :--- | :--- | :--- | :--- |
| **P0 — Critical Security Defect** | Threat detection failure or containment safety flaw. | Safe flow incorrectly included in isolation rule. | $< 2\text{ Hours}$ |
| **P1 — Pilot Blocker** | Inability to ingest traffic or sensor connection failure. | SPAN interface dropping mirror frames. | $< 8\text{ Hours}$ |
| **P2 — Workflow Friction** | False positive alert or UI confusion. | Harmless proprietary UDP protocol flagged as drift. | $< 24\text{ Hours}$ |
| **P3 — Enhancement** | Feature request or third-party integration suggestion. | Request for Fortinet FortiGate API driver. | Product Backlog |

---

## 2. In-App Feedback Attribution

When an operator submits feedback from the SOC UI, the following forensic context is automatically captured:
* Current Screen Route & Asset / Alert ID.
* Observed Flow Metadata & Rule Diff.
* Active RBAC Role & Organization Workspace ID.
* Telemetry timestamp and sensor node correlation.
