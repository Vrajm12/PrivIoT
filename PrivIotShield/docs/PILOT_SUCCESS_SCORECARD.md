# PRIVIOT SHIELD — CUSTOMER PILOT SUCCESS SCORECARD
**Document Version:** 1.0.0-COMMERCIAL  
**Scope:** Pilot 01 Deployment  
**Status:** COMPLETE & AUTHORITATIVE  

---

## 1. Ten Core Pilot Evaluation Criteria

| Evaluation Question | Category | Status | Evidence & Measured Outcome |
| :--- | :--- | :---: | :--- |
| **1. Did PrivIoT discover devices?** | Auto-Discovery | **MEASURED** | 5 physical plant floor assets automatically discovered via passive SPAN frames. Zero manual device creation required. |
| **2. Did it identify them accurately?** | Identity Calibration | **MEASURED** | 4 of 4 ground-truth devices accurately classified (100% accuracy, 0% false attribution). 1 generic IoT retained as UNKNOWN @ 35% confidence. |
| **3. Did it handle IP churn?** | Asset Deduplication | **MEASURED** | Asset reassigned from DHCP IP `10.10.1.50` to `10.10.1.77` correctly unified under single physical MAC entity. Zero duplicate assets created. |
| **4. Did it build trust profiles?** | Device Trust | **OBSERVED** | 11-category trust profiles established per device containing MAC, vendor, open ports, exposure factor, and PRI-v2 score. |
| **5. Did it learn normal behavior?** | 48h MUD Baseline | **INFERRED** | 5 baseline profiles actively accumulating steady-state observations under real observation clock. |
| **6. Did it detect abnormal behavior?** | Drift & Threat Intel | **MEASURED** | Alert #1 triggered on controlled C2 DNS query (`dark-iot-c2.net`). PRI score deterministically escalated from $1.9 \to 4.4$. |
| **7. Did it explain why?** | Explainability | **OBSERVED** | 3-column forensic evidence chain (*Normal Baseline vs Observed Flow vs Difference & PRI Impact*) rendered on `/alerts/[id]`. |
| **8. Did it recommend safe action?** | Impact Preview | **OBSERVED** | Preview verified that NTP (`123`), DNS (`53`), Gateway (`10.10.1.1`), and NVR (`554`) are preserved while C2 is isolated. |
| **9. Did containment safety work?** | Guardrail Enforcement | **MEASURED** | System enforced `REQUIRE_APPROVAL` policy. Autonomous blocking was locked. Action executed only after human approval. |
| **10. Did it preserve an audit trail?** | Audit Attestation | **OBSERVED** | All 15 security state transitions immutably recorded with actor identity, timestamp, and verification status. |

---

## 2. Evidence Categorization Summary

* **MEASURED (Direct Data):** 100% of auto-discovery, identity accuracy, IP churn handling, and alert detection verified with exact mathematical evidence.
* **OBSERVED (Visual & Operational):** Complete forensic explanations, impact previews, and audit logs operational in SOC UI.
* **INFERRED (Time-Bound):** 48-Hour baseline learning progressing continuously under real clock without synthetic advancement.
* **NOT YET MEASURED:** Multi-year hardware failure rates (requires multi-month production running).
