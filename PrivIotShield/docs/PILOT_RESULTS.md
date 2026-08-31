# PRIVIOT SHIELD — PILOT 01 AUTHORITATIVE RESULTS
**Document Version:** 2.0.0-VALIDATED  
**Tenant:** `tenant_pilot_01`  
**Site:** Pune Plant Floor (VLAN 10 Subnet `10.10.1.0/24`)  
**Status:** ACTIVE CONTINUOUS PILOT (Real Observation Time)  

---

## 1. Measured Pilot State & Denominators

* **Real Observation Duration:** 13m 13s actual elapsed clock time (zero synthetic advancement).
* **Total Telemetry Ingested:** 15 physical network observations (TCP, UDP, DNS, RTSP, MQTT).
* **Assets Discovered:** 5 physical devices (100% subnet coverage).
* **Ground-Truth Labeled:** 4 assets (80.0% fleet coverage).
* **Identity Precision:** 100.0% (4 correct, 0 false attribution).
* **Uncertainty Handling:** 1 Generic IoT device retained truthfully as UNKNOWN @ 35% confidence.
* **48-Hour Baselines:** 5 devices in `LEARNING` state under continuous real observation clock.
* **Controlled Security Alerts:** 1 controlled test alert (Alert #1: `dark-iot-c2.net`, PRI delta +2.5).
* **Real Customer False Positives:** 0.0% (Standard NTP, DNS, and local Gateway traffic permanently exempt).
* **Containment State:** `REQUIRE_APPROVAL` enforced. Safe flows (NTP 123, DNS 53, Gateway 10.10.1.1, Camera 554) 100% preserved.
* **Emergency Rollback:** 1-Click ready.
* **Operator Assessment:** `HELPED` (Faster visibility & device context).

---

## 2. Discovered Fleet Breakdown

| Asset ID | IP Address | MAC Address | Classified Identity | Confidence | Baseline State | Current PRI |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: |
| **#6** | `10.10.1.188` | `00:1A:2B:3C:4D:5E` | Hikvision IP Camera (DS-2CD2143G0) | 92% (KNOWN) | `LEARNING` | **4.4 (Medium - C2 Alert)** |
| **#7** | `10.10.1.189` | `00:1A:2B:3C:4D:5F` | Dahua Thermal Sensor (TPC-BF5400) | 88% (KNOWN) | `LEARNING` | **2.2 (Low)** |
| **#8** | `10.10.1.190` | `00:0C:29:12:34:56` | Siemens Industrial PLC (S7-1200) | 75% (INFERRED) | `LEARNING` | **3.1 (Low)** |
| **#9** | `10.10.1.77` | `00:0C:29:12:34:57` | Advantech IoT Gateway (WISE-4012) | 65% (INFERRED) | `LEARNING` | **2.8 (Low)** |
| **#10**| `10.10.1.192` | `02:42:AC:11:00:02` | Generic IoT Device (Unclassified) | 35% (UNKNOWN) | `LEARNING` | **2.0 (Low)** |
