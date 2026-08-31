# PRIVIOT SHIELD — CUSTOMER COMPLIANCE & AUDIT REPORTING
**Document Version:** 1.0.0-PROD  
**Target Audience:** Compliance Officers, Security Executives, SOC Managers  

---

## 1. Reporting Philosophy

PrivIoT Shield reports are strictly evidence-backed. The platform prohibits synthetic extrapolation, artificial compliance scores, or unobserved asset counts.

Every metric in `/reports` adheres to three reporting classes:
* **OBSERVED:** Directly captured and verified in packet stream telemetry.
* **INFERRED:** Derived through algorithmic heuristics (e.g. DHCP fingerprinting, DNS naming heuristics).
* **UNKNOWN:** Transparently flagged when evidence is insufficient.

---

## 2. Available Report Formats

### 1. Executive Summary Posture Report
* **Target Audience:** CISO, VP of Infrastructure, Operations Director.
* **Contents:**
  - Total monitored assets & subnet coverage.
  - Known vs Inferred vs Unknown identity rates.
  - Active critical alerts & resolution velocity.
  - Containment policy status (`REQUIRE_APPROVAL`).

### 2. Device Trust Inventory Report
* **Target Audience:** IT Asset Managers, OT Engineers.
* **Contents:**
  - Complete IP / MAC inventory.
  - Vendor / Model / Category breakdown.
  - 48-Hour baseline maturity state.
  - Full PRI-v2 risk distribution matrix.

### 3. Containment & Remediation Audit Attestation
* **Target Audience:** External Auditors, SOC Compliance Teams.
* **Contents:**
  - Chronological containment intent lifecycle history.
  - Dual-control approver identity and timestamp attribution.
  - Verification of preserved operational safe flows (NTP, DNS, Gateway).
  - 1-click rollback availability and disaster recovery readiness.
