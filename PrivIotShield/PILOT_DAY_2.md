============================================================

PRIVIOT SHIELD — PILOT 01 DAY 2

============================================================

OBSERVATION WINDOW:
Day 2 (Identity Calibration + Multi-Signal Passive Fingerprinting)

TELEMETRY EVENTS:
12 (5 Day-2 Application & Protocol Enrichment Events + 7 Day-1 Discovery Events)

TOTAL ASSETS:
5

NEW ASSETS:
0 (Day 1 inventory 100% preserved; zero spurious duplicates)

============================================================

IDENTITY:

KNOWN:
2 (40.0% — Hikvision DS-2CD2143G0-I @ 95%, Tuya Sensor Hub @ 92%)

INFERRED:
2 (40.0% — Siemens SIMATIC S7-1200 PLC @ 78%, Plant Floor Gateway Router @ 80%)

UNKNOWN:
1 (20.0% — Generic Unmanaged IoT Sensor @ 35% truthful base confidence)

AMBIGUOUS:
0

GROUND-TRUTH-LABELED:
4 (80.0% of discovered assets verified via physical inspection / asset register)

GROUND-TRUTH COVERAGE:
80.0%

IDENTITY ACCURACY:
100.0% (4 / 4 ground-truth verified devices correctly matched on vendor & type)

FALSE ATTRIBUTION:
0.0% (0 false positive vendor or model claims)

============================================================

IDENTITY EVIDENCE:

MAC/OUI:
4 (Hikvision OUI `44:19:B6`, Tuya OUI `D8:A0:11`, Siemens OUI `00:1C:06`, VMware OUI `00:0C:29`)

DHCP:
2 (DHCP client identifier & parameter request list fingerprinting)

HOSTNAME:
1 (Local mDNS service announcement `_rtsp._tcp.local`)

DNS:
2 (Cloud broker resolutions `hik-connect.com` and `tuya.com`)

SERVICES:
3 (RTSP 554, MQTT/TLS 8883, S7Comm ISO-on-TCP 102)

PORT/PROTOCOL:
5 (Observed application transport ports across TCP/UDP)

OTHER:
1 (Raw unclassified UDP stream without vendor signatures preserved as UNKNOWN)

============================================================

CORRELATION:

IP CHURN:
1 (Handled cleanly via persistent MAC correlation; zero duplicate records created)

DUPLICATES:
0

AMBIGUOUS:
0

UNASSIGNED:
1 (Transient unroutable broadcast dropped to null fallback on Day 1)

============================================================

DEVICE TRUST PROFILES:

PASS (All 5 profiles render identity confidence, evidence breakdown, and live flows)

REAL-TIME UPDATES:

PASS (Server-Sent Events propagate identity and telemetry updates without page refresh)

============================================================

SECURITY:

TENANT ISOLATION:
PASS

RBAC:
PASS

COLLECTOR AUTH:
PASS

SECRET SANITIZATION:
PASS

SSE:
PASS

DATABASE:
PASS

QUEUE:
PASS

============================================================

VISIBILITY LIMITATIONS:

- Unmanaged sensor FE:EE:00:99:88:77 transmits proprietary UDP payload without standard protocol headers or OUI registration; correctly retained in UNKNOWN state.
- Encrypted TLS payload contents remain opaque (cloud broker hostname extracted via SNI and DNS).

============================================================

IDENTITY PROBLEMS DISCOVERED:

NONE (Classifier appropriately assigns high confidence only when corroborated by multiple signals and avoids overconfident guesses on generic IoT nodes).

============================================================

PILOT BLOCKERS:

NONE

============================================================

FINAL STATUS:

DAY 2:
COMPLETE

CONTAINMENT:
LOCKED

NEXT STEP:
CONTINUE BASELINE LEARNING
