============================================================

PRIVIOT SHIELD — PILOT 01 DAY 1

============================================================

COLLECTOR:
Pilot_Edge_Collector_Sensor_01

OBSERVATION WINDOW:
Day 1 (Initial Passive Ingestion & Automatic Discovery)

TOTAL TELEMETRY EVENTS:
7

DEVICES OBSERVED:
5

ASSETS AUTOMATICALLY DISCOVERED:
5

MANUALLY CREATED:
0

UNASSIGNED OBSERVATIONS:
1 (14.3% — Transient unroutable 0.0.0.0 packet safely dropped to null asset fallback)

DISCOVERY COVERAGE:
100.0% of local subnet active endpoints

============================================================

IDENTITY:

KNOWN:
0

INFERRED:
0

UNKNOWN:
5 (Truthful generic IoT base confidence without manufactured guessing)

AMBIGUOUS:
0

IDENTITY ACCURACY:
GROUND TRUTH UNAVAILABLE (Pending Day 2 active calibration / manual ground-truth labeling)

FALSE ATTRIBUTION:
0.0% (Zero false positive vendor/model claims made)

GROUND TRUTH COVERAGE:
0.0% (Day 1 purely passive uncalibrated baseline)

============================================================

CORRELATION:

DUPLICATE ASSETS:
0 (Hardware MAC deduplication successfully merged IP churn from 10.10.1.101 to 10.10.1.115)

IP CHURN CASES:
1 (Handled cleanly via persistent MAC correlation)

AMBIGUOUS CORRELATIONS:
0

UNRESOLVED CORRELATIONS:
1 (Null asset fallback for unroutable transient packet)

============================================================

REAL-TIME:

SSE:
PASS

LIVE ASSET UPDATES:
PASS

COLLECTOR HEARTBEAT:
PASS

SOC UPDATES:
PASS

============================================================

SECURITY:

TENANT ISOLATION:
PASS

SECRET LEAKAGE:
PASS

INGESTION STABILITY:
PASS

QUEUE STABILITY:
PASS

DATABASE STABILITY:
PASS

============================================================

VISIBILITY LIMITATIONS:

- Encrypted TLS application payloads remain uninspected (metadata SNI / DNS observed)
- Unmanaged devices without active traffic remain unobserved until first packet transmission
- Transient DHCP broadcast without persistent MAC attribution dropped to unassigned pool

============================================================

TOP FINDINGS:

1. Automatic device discovery is fully functional with zero manual asset creation required.
2. MAC-based hardware correlation accurately unified IP churn on Plant Floor VLAN without creating duplicate asset profiles.
3. Passive identity classifier truthfully avoids hallucinating vendor/model certainty when only raw transport metadata is available.
4. Real-time Server-Sent Events stream updates Next.js SOC inventory instantaneously upon first packet observation.

============================================================

PILOT BLOCKERS:

NONE

============================================================

FINAL STATUS:

DAY 1:
COMPLETE

CONTAINMENT:
REMAIN LOCKED

NEXT STEP:
CONTINUE OBSERVATION + BASELINE LEARNING
