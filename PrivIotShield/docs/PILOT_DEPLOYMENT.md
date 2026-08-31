# PRIVIOT SHIELD — CUSTOMER PILOT DEPLOYMENT PACKAGE
**Deployment Guide for Controlled Enterprise On-Premise / Edge Pilots**  
**Version:** 6.0.0-PILOT  
**Target Environment:** Customer On-Premise Appliance, Dedicated VM, or Edge Gateway  

---

## 1. Pilot Architecture & Hardware Requirements

PrivIoT Shield deploys as an isolated, containerized stack inside the customer network:

| Component | Minimum Spec | Recommended |
| :--- | :--- | :--- |
| **Central SOC Node (API, DB, UI, Workers)** | 4 vCPU, 8 GB RAM, 50 GB SSD | 8 vCPU, 16 GB RAM, 200 GB NVMe |
| **Edge Collector Node (Sensor)** | 2 vCPU, 2 GB RAM, 20 GB SSD | 4 vCPU, 4 GB RAM, 50 GB SSD |
| **OS / Runtime** | Ubuntu 22.04 LTS / Debian 12 / RHEL 9 | Docker Engine 24.0+ & Compose v2 |

---

## 2. Step-by-Step Pilot Deployment

### Step 1: Environment & Configuration Initialization
```bash
# Clone or unpack the PrivIoT Pilot distribution
cd /opt/priviot-shield

# Copy safe configuration template
cp .env.example .env

# Generate secure random secret keys
SECRET_KEY=$(openssl rand -hex 32)
sed -i "s/replace_with_cryptographically_secure_random_hex_key_64_bytes/$SECRET_KEY/g" .env
```

### Step 2: Launch Core Infrastructure & Services
```bash
# Start PostgreSQL, Redis, Celery workers, and web control plane
docker compose up -d postgres redis celery_worker celery_beat web frontend

# Verify service liveness
curl -f http://127.0.0.1:8000/health/live
curl -f http://127.0.0.1:8000/health/ready
```

### Step 3: Edge Collector Sensor Provisioning
1. Log into the SOC console at `https://<PILOT_IP>:3000` as `secops_admin`.
2. Navigate to **Collectors** (`/collectors`) $\to$ Click **Enroll Sensor Node**.
3. Select Network Interface (e.g. `eth0` / `span0`) and copy the generated `X-Sensor-Token`.
4. Deploy the collector agent on the sensor host or TAP/SPAN port:
```bash
python collector_agent.py \
  --server-url https://<PILOT_IP>:8000 \
  --token <PROVISIONED_SENSOR_TOKEN> \
  --interface eth1 \
  --site "Plant-Floor-VLAN-10"
```

---

## 3. Post-Deployment Pilot Verification Checklist

- [ ] Web console reachable at `https://<PILOT_IP>:3000`
- [ ] FastAPI OpenAPI schema live at `https://<PILOT_IP>:8000/docs`
- [ ] Redis Pub/Sub event transport operational
- [ ] Celery worker fleet active with 4 concurrent processing threads
- [ ] Edge collector transmitting telemetry heartbeats every 60s
- [ ] Default containment safety policy set to `REQUIRE_APPROVAL` (Zero autonomous blocking)
