# PRIVIOT SHIELD — COMPETITIVE POSITIONING & DIFFERENTIATION MATRIX
**Document Version:** 1.0.0-COMMERCIAL  
**Date:** August 31, 2026  

---

## 1. Product Category Landscape

PrivIoT Shield occupies a specialized operational position at the intersection of **Agentless IoT Security Operations** and **Safe Micro-Segmentation**.

| Dimension | PrivIoT Shield | Traditional EDR (CrowdStrike, S1) | Network NDR (Vectra, ExtraHop) | Active Scanners (Tenable, Qualys) | IoT Asset DB (Claroty, Armis) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Agent Requirement** | **Agentless** (SPAN sniffer) | Mandatory Kernel Agent | Agentless (TAP/SPAN) | Agentless (Active Probe) | Agentless (Passive/Active) |
| **IoT/OT Compatibility** | **Native** (Zero overhead) | Incompatible on 95% IoT | Compatible | High crash risk on legacy PLCs | Compatible |
| **Identity Grounding** | Multi-signal passive + confidence score | Host OS introspection | IP-centric flows | Port banner probing | Heuristic fingerprint DB |
| **Behavioral Baseline** | **48-Hour MUD Synthesis** | Process baseline | Statistical anomaly | None (Static scan) | Statistical profile |
| **Actionable Risk** | **PRI-v2 (Threat, KEV, EPSS, Reachability)** | Host vulnerability score | Risk score based on volume | Raw CVSS count | Exposure scoring |
| **Containment Model** | **Safe Flow Preservation + 1-Click Rollback** | Process kill / Host isolate | SIEM webhook / NAC trigger | None (Reporting only) | NAC / VLAN change |
| **Safety Guardrail** | **`REQUIRE_APPROVAL`** | Autonomous agent kill | Often alert-only | Read-only | Manual approval |

---

## 2. Where PrivIoT Shield is Strong

1. **Deterministic Explainability:** Replaces opaque *"Machine Learning Anomaly"* flags with exact 3-column evidence comparisons: *Normal Baseline vs Observed Flow vs Difference & PRI Delta*.
2. **Safe Micro-Segmentation:** Synthesizes gateway firewall rules that block malicious egress while strictly preserving operational protocols (NTP, DNS, Gateway, NVR streams).
3. **Data Honesty & Uncertainty UX:** Explicitly treats unknown devices as an honest state with a constructive checklist to improve confidence rather than fabricating vendor matches.
4. **Lightweight Edge Deployment:** Sensor nodes run on commodity Linux, Raspberry Pi, or Docker containers with negligible CPU/memory footprints.

---

## 3. Where PrivIoT Shield is Complemented by Existing Tools

* **SIEM / Log Aggregators (Splunk, Microsoft Sentinel):** PrivIoT streams structured JSON security events and audit records via syslog or REST to centralize enterprise logging.
* **Firewalls & Network Access Control (Palo Alto, pfSense, Cisco ISE):** PrivIoT generates iptables/nftables and firewall API payloads, acting as the policy intelligence engine while the firewall acts as the enforcement plane.
* **Vulnerability Scanners:** PrivIoT ingests CVE lists and recalculates actionable PRI-v2 by factoring in active exploit weaponization (CISA KEV) and network reachability.
