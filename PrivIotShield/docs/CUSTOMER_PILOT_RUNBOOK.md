# PRIVIOT SHIELD — CUSTOMER PILOT OPERATIONAL RUNBOOK
**Operational Journey & Triage Protocol for Controlled Customer Pilots**  
**Version:** 6.0.0-PILOT  

---

## 1. Day-by-Day Pilot Execution Plan

```
Day 0: Installation & SPAN Port Activation
  ↓
Day 1: Automatic Asset Discovery Audit
  ↓
Days 1–2: Identity Calibration (Known vs Inferred vs Unknown)
  ↓
Days 2–3: 48-Hour Baseline Convergence
  ↓
Ongoing: Real-Time Behavioral Drift & Threat Monitoring
  ↓
Incident: Triage → Containment Recommendation → Approval → Verification
  ↓
Pilot Review: Evidence-Based Executive Debrief
```

---

## 2. Operational Phases

### Day 0: Installation & Physical Sensor Placement
* Connect edge collector NIC to network SPAN / mirror port.
* Verify collector registration and token authentication against central FastAPI control plane.
* Confirm real-time SSE stream indicates `SOC LIVE`.

### Day 1: Discovery & Passive Inventory Audit
* Verify automatic asset discovery without manual IP entry.
* Inspect `/assets` to confirm newly discovered devices appear within seconds of first packet transmission.
* Verify MAC attribution, IP correlation, and first/last seen timestamps.

### Days 1–2: Device Trust Profile & Identity Calibration
* Open `/assets/[id]` for discovered devices.
* Audit classification accuracy:
  - **KNOWN:** Exact vendor/model match via mDNS, SSDP, or OUI (Confidence $> 85\%$).
  - **INFERRED:** Behavioral heuristic match (Confidence $50\% - 84\%$).
  - **UNKNOWN / GENERIC:** Unclassified device (Confidence $< 50\%$).
* **Golden Rule:** Never manufacture certainty. Unclassified devices remain labeled `Generic IoT Device` with explicit low confidence.

### Days 2–3: 48-Hour Baseline Learning Window
* Allow the behavioral engine to observe normal operational communication patterns (approved DNS domains, external endpoints, internal gateways, operational ports).
* Baseline status progresses: `LEARNING` $\to$ `ESTABLISHED`.

### Ongoing: Continuous Behavioral Drift & Incident Response
* When a device initiates anomalous communication (e.g. unknown external IP, anomalous port, or threat intel domain match):
  1. Instant alert created in `/alerts`.
  2. Live notification banner triggers in SOC UI via Server-Sent Events.
  3. PRI-v2 risk score recomputes with behavioral penalty.
  4. Operator opens `/assets/[id]` to review exact forensic difference: *Observed Behavior* vs *48h Baseline*.

### Containment Lifecycle (Enforcement Protocol)
1. **Safety First:** Unattended autonomous blocking is disabled by default (`REQUIRE_APPROVAL`).
2. **Preview:** Operator reviews generated firewall rule syntax and explicit safe-flow protections (NTP, DNS, Gateway preserved).
3. **Approval:** Approver or Admin authorizes execution.
4. **Application:** Worker applies rule to gateway or iptables.
5. **Verification:** System actively probes to verify isolation before declaring `VERIFIED`.
6. **Rollback:** Single-click instant rollback capability with verified state restoration.
