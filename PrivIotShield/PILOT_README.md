# PrivIoT Shield — Commercial Pilot Deployment Guide

## 1. Overview
PrivIoT Shield provides **Agentless Continuous IoT/OT Exposure Management + Automated Network Containment**. It deploys as a lightweight hybrid architecture consisting of:
- **PrivIoT Control Plane:** Multi-tenant intelligence engine, Device Trust Profile aggregator, PRI-v2 risk scoring, and containment orchestration.
- **PrivIoT Edge Sensor:** Lightweight, non-intrusive containerized packet/flow observation node deployed on local network segments.

---

## 2. Pilot Architecture & Network Requirements
```
[ IoT/OT Subnet: 192.168.1.0/24 ]
   ├── IP Cameras (RTSP/ONVIF)
   ├── Smart Lighting / Plugs (MQTT)
   ├── Printers (IPP/RAW)
   └── Building Management / Gateways
              │ (Mirror Port / SPAN / TAP / Promiscuous)
              ▼
    [ PrivIoT Edge Sensor ]
              │ (HTTPS REST API / X-Sensor-Token Authenticated)
              ▼
   [ PrivIoT Control Plane ]
              │ (XML-RPC / REST API / SSH / CLI)
              ▼
   [ Gateway / Firewall ] (pfSense / UniFi / Linux iptables / Pi-hole)
```

### Network Requirements:
- **Sensor Host:** 1x Linux/Docker host with 2 vCPUs, 2 GB RAM, 10 GB disk.
- **Port Mirroring:** SPAN or TAP port mirroring IoT VLAN traffic to the sensor network interface.
- **Outbound Connectivity:** HTTPS (TCP 443/5000) from Edge Sensor to PrivIoT Control Plane.

---

## 3. Collector Bootstrap & Enrollment (3 Steps)

### Step 1: Enroll Collector via Control Plane
```bash
curl -X POST http://<CONTROL_PLANE_IP>:5000/api/v2/collectors/register \
  -H "X-API-Key: <ADMIN_API_KEY>" \
  -H "X-Tenant-ID: pilot_enterprise" \
  -H "Content-Type: application/json" \
  -d '{"name": "HQ_Sensor_01", "site_id": "site_alpha", "network_scope": "192.168.1.0/24"}'
```
*Response returns a secure one-time provision token: `priviot_sensor_...`*

### Step 2: Configure Sensor Environment
```bash
cat <<EOF > .env
PRIVIOT_API_URL=http://<CONTROL_PLANE_IP>:5000/api/v2/telemetry/ingest
PRIVIOT_SENSOR_TOKEN=priviot_sensor_...
BATCH_SIZE=50
FLUSH_INTERVAL=5.0
EOF
```

### Step 3: Launch Sensor
```bash
docker run -d --name priviot_sensor --net=host --env-file .env priviot/sensor:latest
```

---

## 4. Supported Containment Providers

| Provider | Integration Method | Verification Semantics | Rollback Mechanism |
| :--- | :--- | :--- | :--- |
| **Linux iptables / nftables** | Direct CLI / Subprocess | Live packet filter inspection | 1-Click CLI inverse rule purge |
| **Pi-hole / AdGuard Home** | CLI gravity regex insertion | Query live domain blocklist | Regex deletion |
| **pfSense / OPNsense** | XML-RPC / REST easyrule API | Live pfctl state table inspection | XML-RPC filter reload |
| **Ubiquiti UniFi Controller** | Controller REST API | Controller firewall rule query | REST rule purge |

---

## 5. Security & Safety Model
- **No Unattended Containment:** All containment recommendations require explicit human approval via the web UI or authenticated API (`REQUIRE_APPROVAL`).
- **Safe Flow Preservation:** Containment generators explicitly preserve local default gateways, DNS (port 53), NTP (port 123), and local NVR stream ingress.
- **Tenant Isolation:** Enforced server-side at the database layer; cross-tenant access returns HTTP 404.

---

## 6. Pilot Success Criteria
1. **Device Discovery Rate:** $\ge 90\%$ of active network devices discovered automatically without manual entry.
2. **Detection Latency:** $< 60$ seconds from anomalous external egress observation to alert generation.
3. **Containment Verification Success Rate:** $100\%$ verified active provider filter state.
