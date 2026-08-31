# PRIVIOT SHIELD — CUSTOMER ONBOARDING MANUAL
**Document Version:** 1.0.0-PROD  
**Target Audience:** Security Operations, Network Engineers, SOC Administrators  

---

## 1. Onboarding Philosophy

PrivIoT Shield deploys into industrial and enterprise environments via passive, non-intrusive network observation. No endpoint agents are installed on IoT/OT devices.

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐     ┌─────────────────────┐
│ 1. Organization │ ──> │   2. Site    │ ──> │  3. Collector  │ ──> │  4. Network Scope   │
└─────────────────┘     └──────────────┘     └────────────────┘     └─────────────────────┘
                                                                               │
┌─────────────────────────┐     ┌──────────────────────────┐     ┌─────────────▼─────────┐
│ 7. Start Real-Time SOC  │ <── │ 6. Pre-Flight Diagnostic │ <── │  5. Security Policy   │
└─────────────────────────┘     └──────────────────────────┘     └───────────────────────┘
```

---

## 2. Step-by-Step Deployment Procedure

### Step 1: Create Organization / Tenant
* **Action:** In `/onboarding` or via API `POST /api/v2/tenants`, initialize customer workspace.
* **Safety Invariant:** All cryptographic tokens, assets, baselines, and logs are partitioned by `tenant_id`.

### Step 2: Define Plant / Facility Site
* **Action:** Assign a physical or logical location (e.g. `Pune_Plant_Floor_VLAN10`).
* **Purpose:** Allows enterprise multi-facility management with localized alerting and containment routing.

### Step 3: Deploy & Provision Edge Collector
* **Action:** Generate sensor enrollment token in `/collectors`.
* **Hardware/VM Options:** Docker container, VMware OVA, or dedicated 1U Linux appliance.
* **Secret Handling:** Pre-shared SHA-256 enrollment token (`X-Sensor-Token`) is displayed once. Never stored in plaintext.

### Step 4: Configure Switch SPAN / Mirroring
* **Action:** Connect sensor eth1 interface to switch mirror port.
* **Protocol Support:** ARP, DHCP, DNS, mDNS, SSDP, RTSP, MQTT, Modbus TCP, TLS Client Hello.

### Step 5: Establish Security Policy Guardrails
* **Containment Policy:** Default set to `REQUIRE_APPROVAL` (Autonomous blocking strictly disabled).
* **Behavioral Learning:** 48-Hour continuous MUD convergence clock.
* **Safe Flows Exemption:** NTP (`123/UDP`), DNS (`53/UDP`), Gateway (`10.10.1.1`), Local NVR (`554/TCP`) are permanently whitelisted.

### Step 6: Pre-Flight Pipeline Verification
* **Diagnostic Route:** `/collectors` diagnostic surface verifies all 6 stages:
  1. *Collector Authentication:* Validated via SHA-256 HMAC.
  2. *Network Visibility:* Live SPAN frames arriving.
  3. *Batch Ingestion:* FastAPI accepting observation chunks.
  4. *Celery Processing:* Async worker queues healthy.
  5. *PostgreSQL Persistence:* Assets and telemetry committed.
  6. *Real-Time SOC:* SSE event bus emitting live transitions.

### Step 7: Continuous Autonomous Observation
* Transition system to live SOC mode. Assets are auto-discovered, fingerprinted, and baselined without manual operator tagging.
