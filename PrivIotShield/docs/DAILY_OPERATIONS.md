# PRIVIOT SHIELD — DAILY SECURITY OPERATIONS RUNBOOK
**Document Version:** 1.0.0-PROD  
**Target Audience:** Tier 1 / Tier 2 SOC Analysts, Incident Responders  

---

## 1. Daily Operator Workflow

The daily operator workflow is structured around four primary questions:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. WHAT CHANGED SINCE LAST SHIFT?                          │
│    Inspect `/dashboard` "What Changed?" chronological feed. │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 2. ARE THERE UNRESOLVED CRITICAL ALERTS?                    │
│    Review open alerts in `/alerts` and triage by severity.  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 3. DID ANY DEVICE DRIFT FROM ITS BASELINE?                  │
│    Inspect Expected vs Observed differences in `/behavior`. │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 4. ARE ALL SENSORS HEALTHY AND INGESTING?                   │
│    Verify collector heartbeat timestamps in `/collectors`.  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Standard Shift Checklist

| Frequency | Check Item | Location | Expected Healthy State | Action if Degraded |
| :--- | :--- | :--- | :--- | :--- |
| **Shift Start** | Active Threat Alerts | `/alerts` | Zero unacknowledged Critical alerts. | Perform forensic investigation via `/alerts/[id]`. |
| **Shift Start** | Sensor Heartbeat Age | `/collectors` | Last heartbeat `< 60s`, rate `> 0 ev/s`. | Check switch SPAN port link & host network. |
| **Mid-Shift** | Behavioral Baseline State | `/behavior` | Devices in `LEARNING` or `STABLE`. | Investigate anomalous egress destinations. |
| **Mid-Shift** | Fleet Risk Distribution | `/fleet` | PRI scores bounded, zero unexplained jumps. | Drill down into PRI breakdown on `/assets/[id]`. |
| **Shift End** | Incident Containment Audit | `/audit` | All containment actions have verified approvals. | Ensure emergency rollback is tested and ready. |

---

## 3. Truthful Operational Failure Handling

* **NO DATA $\ne$ SYSTEM FAILURE:** If an asset shows zero observed DNS queries, the UI displays *"No observations recorded"* rather than reporting an engine error.
* **COLLECTOR OFFLINE:** If a sensor node disconnects, the Top Context Bar displays `COLLECTOR DEGRADED`. Historical telemetry remains fully queryable.
* **SYSTEM FAILURE:** If Redis or Celery encounters an issue, the UI explicitly flags `WORKER DEGRADED` while PostgreSQL and FastAPI maintain synchronous read operations.
