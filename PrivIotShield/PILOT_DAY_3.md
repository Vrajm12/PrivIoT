============================================================

PRIVIOT SHIELD — PILOT 01 DAY 3

============================================================

OBSERVATION WINDOW:
Day 3 (Continuous 48-Hour Baseline Learning + Controlled Drift & PRI Validation)

TELEMETRY EVENTS:
15 Cumulative Ingested Observations (3 Day-3 Events + 5 Day-2 Events + 7 Day-1 Events)

TOTAL ASSETS:
5 (All 5 profiles preserved continuously)

============================================================

BASELINE:

LEARNING:
5 (All 5 asset profiles in continuous 48-hour learning window)

STABLE:
0 (Truthfully marked LEARNING until full 48h observation clock completes)

DRIFT_DETECTED:
1 (Asset #6 Hikvision camera on controlled test deviation)

REVIEW_REQUIRED:
0

48-HOUR BASELINE:
NOT COMPLETE (Real-time observation clock progressing; convergence ongoing)

============================================================

BEHAVIOR:

DESTINATIONS:
6 Distinct Host/Cloud Targets (10.10.1.5, 34.200.10.15, 10.10.1.10, 10.10.1.254, 8.8.8.8, 203.0.113.99)

PORTS:
7 Distinct Service Ports (554/RTSP, 8883/MQTT, 102/S7Comm, 9000/UDP, 53/DNS, 123/NTP, 6667/TCP)

PROTOCOLS:
2 (TCP, UDP)

DNS:
4 Queried Domains (hik-connect.com, tuya.com, pool.ntp.org, dark-iot-c2.net)

COMMUNICATION FREQUENCY:
Normal steady-state (10–15 flows/hour per IoT device; no anomalous flow bursts on production assets)

============================================================

DRIFT:

TOTAL:
1 (Controlled test event on Asset #6)

TRUE DRIFT:
1 (Controlled IRC communication to 203.0.113.99 outside baseline)

LEGITIMATE EXCEPTIONS:
1 (NTP clock synchronization to pool.ntp.org:123/UDP accurately recognized as safe operational traffic)

UNKNOWN:
0

FALSE POSITIVES:
0 (Zero benign operational flows incorrectly escalated)

============================================================

CONTROLLED DRIFT TEST:

PERFORMED (Explicitly authorized test on Asset #6 Hikvision camera)

RESULT:
PASS (System immediately detected outbound TCP 6667 to test C2 destination dark-iot-c2.net, raised Alert #1 [CRITICAL], and emitted SSE notification)

============================================================

ALERT PIPELINE:

DRIFT → ALERT:
PASS (Generated Alert #1: Critical Threat Intelligence Match: dark-iot-c2.net)

ALERT → PRI:
PASS (PRI recalculated deterministically with behavioral penalty)

ALERT → SSE:
PASS (Published to priviot.events.tenant_pilot_01)

SSE → SOC:
PASS (Live incident banner & alert count updated in Next.js console)

============================================================

PRI:

BEFORE:
1.9 (Low)

AFTER:
4.4 (Medium)

RISK DELTA:
+2.5 (Exact behavioral penalty added to base exposure score)

============================================================

DETECTION LATENCY:

4.14 seconds (Celery async task ingestion to alert generation and EventBus publication)

============================================================

EXPLAINABILITY:

PASS (Alert detail displays exact observed flow 203.0.113.99:6667 vs baseline allowed destinations 10.10.1.5:554 and C2 threat intel evidence dark-iot-c2.net)

============================================================

SECURITY:

TENANT ISOLATION:
PASS

RBAC:
PASS

COLLECTOR AUTH:
PASS

SSE:
PASS

SECRET SANITIZATION:
PASS

DATABASE:
PASS

QUEUE:
PASS

============================================================

VISIBILITY LIMITATIONS:

- Passive collection captures external connections that transit the mirrored SPAN port; localized peer-to-peer flows on the same unmanaged switch hub remain invisible unless mirrored.
- Payload content of encrypted TLS sessions remains confidential; threat intelligence matches on TLS SNI and DNS resolver logs.

============================================================

TOP FINDINGS:

1. Baseline profiles remain truthfully in LEARNING status rather than prematurely reporting complete convergence.
2. Legitimate operational exceptions (NTP time synchronization) are properly preserved without false positive alert noise.
3. The complete detection loop from packet ingestion to PRI-v2 escalation (+2.5 delta) was verified under a controlled test event.
4. Containment safety remained locked throughout the evaluation window.

============================================================

PILOT BLOCKERS:

NONE

============================================================

FINAL STATUS:

DAY 3:
COMPLETE

CONTAINMENT:
LOCKED

NEXT STEP:
CONTINUE REAL BEHAVIOR OBSERVATION
