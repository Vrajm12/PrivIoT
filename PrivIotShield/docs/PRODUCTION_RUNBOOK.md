# PRIVIOT SHIELD — PRODUCTION OPERATIONS & INCIDENT RUNBOOK
**Version:** 6.0.0-PRODUCTION  
**Date:** August 31, 2026  

---

## 1. System Startup & Service Orchestration

PrivIoT Shield runs as a set of containerized services orchestrated via `docker-compose.yml` or Kubernetes manifests:

```bash
# 1. Start all infrastructure and worker containers
docker compose up -d postgres redis celery_worker celery_beat

# 2. Verify Database Migration & Readiness
docker compose exec postgres pg_isready -U priviot_app_user

# 3. Start FastAPI Control Plane & Next.js SOC Console
docker compose up -d web frontend
```

---

## 2. Health Probes & Monitoring

* **Liveness Probe:** `GET /health/live` $\to$ Returns HTTP 200 `{status: "healthy"}`
* **Readiness Probe:** `GET /health/ready` $\to$ Checks PostgreSQL & Redis connectivity
* **System Health Endpoint:** `GET /api/v2/system/health` $\to$ Returns database latency, Redis latency, and telemetry pipeline state
* **Metrics Endpoint:** `GET /api/v2/system/metrics` $\to$ Returns queue depths, ingestion throughput, and active SSE streams

---

## 3. Database Backup & Disaster Recovery Procedure

### Automated Hot Backup (RPO < 1 minute)
```bash
# Run pg_dump snapshot
pg_dump -U priviot_app_user -h postgres -F c -b -v -f /backups/priviot_backup_$(date +%Y%m%d_%H%M%S).dump priviot_shield_db
```

### Complete Restoration (RTO < 5 minutes)
```bash
# 1. Stop web and worker traffic
docker compose stop web celery_worker frontend

# 2. Restore database from snapshot
pg_restore -U priviot_app_user -h postgres -d priviot_shield_db -v --clean /backups/priviot_backup_LATEST.dump

# 3. Restart services
docker compose start celery_worker web frontend
```

---

## 4. Emergency Incident Response & Containment Rollback

If a network containment rule inadvertently disrupts legitimate operational flows:

1. **Locate Asset Profile:** Navigate to `/assets/[id]` or `/containment`.
2. **Execute Rollback:**
   - **Via UI:** Click `Request Rollback` $\to$ `Confirm Rollback`.
   - **Via CLI / API:**
     ```bash
     curl -X POST https://soc.priviot.internal/api/v2/containment/rollback \
       -H "X-Tenant-ID: <tenant_id>" \
       -H "X-API-Key: <operator_api_key>" \
       -H "Content-Type: application/json" \
       -d '{"intent_id": 123, "reason": "Emergency operational override"}'
     ```
3. **Verify Gateway State:** Check `/audit` for durable `containment_rollback_verified` event.
