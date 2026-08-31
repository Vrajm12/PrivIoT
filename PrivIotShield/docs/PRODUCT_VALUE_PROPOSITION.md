# PRIVIOT SHIELD — CORE PRODUCT VALUE PROPOSITION
**Document Version:** 1.0.0-COMMERCIAL  
**Product:** PrivIoT Shield Continuous IoT Security Operations Console  
**Date:** August 31, 2026  

---

## 1. Executive Product Summary

**PrivIoT Shield** is an agentless, continuous IoT/OT security operations platform that discovers unmanaged connected devices, continuously fingerprints device trust profiles, establishes autonomous 48-hour behavioral baselines (MUD profiles), detects threat indicators and anomalous communication drift, and provides human-authorized, safe micro-segmentation with 1-click rollback.

---

## 2. Who is PrivIoT Shield For?

1. **Industrial & Plant Floor Operations (OT/ICS):** Manufacturing plants, utilities, and logistics hubs with unmanaged sensors, PLCs, cameras, and IoT gateways where software agents cannot be installed.
2. **Healthcare & Hospital Networks:** Clinical environments with medical devices, infusion pumps, and imaging hardware that require 100% uptime and zero disruption to patient care.
3. **Enterprise Smart Facilities:** Corporate headquarters and branches with HVAC systems, smart lighting, badge readers, and physical security cameras.
4. **Managed Security Service Providers (MSSPs):** Multi-tenant security teams managing heterogeneous customer device fleets across multiple distributed sites.

---

## 3. What Problem Does PrivIoT Solve?

Traditional cybersecurity tooling is designed for user endpoints (laptops, mobile devices, servers) with modern operating systems and agent capabilities. IoT and OT devices break this paradigm:
* **Zero Agent Support:** IoT devices have proprietary firmware, stripped-down Linux, or RTOS, making agent installation impossible.
* **Ephemeral & Unmanaged Assets:** Devices connect via DHCP, undergo IP churn, or are installed by contractors without IT logging.
* **High Operational Risk from Automated Blocking:** Autonomous firewall disconnects can halt assembly lines, disable safety systems, or interrupt medical monitoring.
* **Static Vulnerability Noise:** Traditional vulnerability scanners generate thousands of theoretical CVE alerts without considering network exposure or weaponized exploitability (CISA KEV).

---

## 4. What Does PrivIoT Automate?

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ 1. AUTO-DISCOVER│ ──> │ 2. FINGERPRINT  │ ──> │ 3. 48h BASELINE │ ──> │ 4. DRIFT & PRI  │
│ (Passive SPAN)  │     │ (Multi-Signal)  │     │ (MUD Profiles)  │     │ (Threat + Drift)│
└─────────────────┘     └─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                                                 │
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐              │
│ 7. IMMUTABLE    │ <── │ 6. RULE VERIFY  │ <── │ 5. SAFE ISOLATE │ <────────────┘
│    AUDIT TRAIL  │     │ (Active Ping)   │     │ (Human Approved)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

1. **Passive Continuous Discovery:** Sniffs switch SPAN / mirror traffic to discover assets without active ping scanning or service degradation.
2. **Multi-Signal Identity Correlation:** Unifies MAC OUI, DHCP Option 55 parameter lists, mDNS/SSDP broadcasts, and TLS hostnames into a defensible identity confidence score.
3. **Autonomous MUD Baseline Synthesis:** Observes steady-state communication patterns for 48 hours to generate an authoritative Manufacturer Usage Description (allowed ports, destinations, DNS resolvers).
4. **Deterministic PRI-v2 Risk Scoring:** Calculates actionable risk using:
   $$\text{PRI} = \min(10.0, [(\text{Threat} + \text{KEV} + \text{EPSS}) \times E] + B + C)$$
5. **Safe Micro-Segmentation Policy Synthesis:** Generates exact firewall rules (iptables, pfSense, UniFi) that drop malicious C2 egress while strictly preserving essential operational safe flows (NTP, DNS, Gateway, Camera Streaming).

---

## 5. What Does PrivIoT NOT Claim to Do?

PrivIoT Shield maintains strict data and operational honesty:
* **NOT an EDR Replacement:** PrivIoT does not perform in-memory analysis, process execution inspection, or kernel-level telemetry on endpoints.
* **NOT a Generic SIEM:** PrivIoT does not ingest application logs or Windows Event Logs; it focuses strictly on device-level network behavior and exposure.
* **NOT an Autonomous Firewall:** PrivIoT strictly enforces `REQUIRE_APPROVAL` for containment actions to protect critical OT uptime.
* **NOT Guaranteed 100% Identity Classification:** When packet evidence is sparse, PrivIoT transparently outputs `UNKNOWN DEVICE` with honest base confidence (e.g. `35%`) rather than guessing.
