# PRIVIOT SHIELD — ESP32 PHYSICAL SENSOR INTEGRATION GUIDE

This document provides complete instructions for connecting, flashing, and operating a physical **ESP32 Dev Module** as a continuous 2.4 GHz Wi-Fi & BLE telemetry scanner feeding real-time airspace observations into PrivIoT Shield.

---

## 1. HARDWARE REQUIREMENTS
* **Microcontroller:** ESP32 Dev Module (e.g. ESP32-WROOM-32 / NodeMCU-32S / DOIT ESP32 DevKit v1)
* **Connection:** Micro-USB to USB-A data cable (connecting to PC Port `COM5` or similar)
* **Network:** Local 2.4 GHz Wi-Fi network (802.11 b/g/n) reachable by both PC and ESP32

---

## 2. ARDUINO IDE SETUP
* **Arduino IDE Version:** 2.3.x (e.g., 2.3.10)
* **ESP32 Board Core:**
  1. Open Arduino IDE: `File` → `Preferences`.
  2. In **Additional Board Manager URLs**, add:
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
  3. Open `Tools` → `Board` → `Boards Manager...`, search for `esp32` by **Espressif Systems**, and click **Install**.

---

## 3. ESP32 BOARD SELECTION
* In Arduino IDE:
  * **Board:** `Tools` → `Board` → `esp32` → **ESP32 Dev Module**
  * **Port:** `Tools` → `Port` → **COM5** (or the COM port assigned to your ESP32)
  * **Upload Speed:** `921600` (or `115200`)
  * **CPU Frequency:** `240MHz (WiFi/BT)`
  * **Flash Frequency:** `80MHz`
  * **Partition Scheme:** `Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)`

---

## 4. REQUIRED ARDUINO LIBRARIES
1. **ArduinoJson (v6 or v7):**
   * Go to `Sketch` → `Include Library` → `Manage Libraries...`.
   * Search for `ArduinoJson` by Benoit Blanchon and click **Install**.
2. **WiFi & HTTPClient:**
   * Built directly into the ESP32 Arduino core (no manual install needed).

---

## 5. BACKEND STARTUP COMMANDS

To receive telemetry from physical hardware on your local network, start both the FastAPI Control Plane and the Next.js Frontend:

### Terminal 1: FastAPI Control Plane (Bound to 0.0.0.0 for LAN access)
```powershell
# From repo root (N:\PROJECTS\PrivIoT\PrivIotShield)
.\venv\Scripts\uvicorn priviot.api.fastapi_app:app --host 0.0.0.0 --port 8000
```

### Terminal 2: Next.js SOC Dashboard
```powershell
# From frontend folder (N:\PROJECTS\PrivIoT\PrivIotShield\frontend)
npm run dev
```

---

## 6. HOW TO FIND YOUR PC LAN IP

Your ESP32 needs your PC's local IP address on your Wi-Fi network (not `localhost`):

1. Open PowerShell on Windows and run:
   ```powershell
   ipconfig
   ```
2. Look under **Wireless LAN adapter Wi-Fi** for **IPv4 Address**:
   ```
   IPv4 Address. . . . . . . . . . . : 192.168.1.105
   ```
   *(Note this IP for Step 10).*

---

## 7. HOW TO REGISTER / ENROLL THE COLLECTOR

Your ESP32 needs a pre-shared Sensor Token (`X-Sensor-Token`) registered in the database.

Run the automatic provisioning script:
```powershell
.\venv\Scripts\python scripts/register_esp32_collector.py
```

**Output:**
```
Collector Name: ESP32_Hardware_Scanner
Collector Type: wifi_scanner
Tenant ID:      default_tenant
YOUR SENSOR TOKEN:
   priviot_sensor_F5pFf66Cr84xDMlrOTGGEzZbMtKSDsz_w8s9MA5hIh8
```

---

## 8. WHERE TO PUT WI-FI CREDENTIALS IN FIRMWARE

Open the Arduino sketch located at:
[`firmware/esp32_wifi_scanner/esp32_wifi_scanner.ino`](file:///N:/PROJECTS/PrivIoT/PrivIotShield/firmware/esp32_wifi_scanner/esp32_wifi_scanner.ino)

Update lines 30–31:
```cpp
const char* WIFI_SSID     = "MyHomeWiFi";      // <-- Your 2.4 GHz Wi-Fi Name
const char* WIFI_PASSWORD = "MySecretPassword";  // <-- Your Wi-Fi Password
```

---

## 9. WHERE TO PUT SENSOR TOKEN IN FIRMWARE

In [`esp32_wifi_scanner.ino`](file:///N:/PROJECTS/PrivIoT/PrivIotShield/firmware/esp32_wifi_scanner/esp32_wifi_scanner.ino) line 41:
```cpp
const char* SENSOR_TOKEN  = "priviot_sensor_5qn7WP9XBu87zBg6SU9aRVRBXsqVrpaVEbDHEyvCets";
const char* TENANT_ID     = "default_tenant";
```

---

## 10. WHERE TO PUT BACKEND URL IN FIRMWARE

In [`esp32_wifi_scanner.ino`](file:///N:/PROJECTS/PrivIoT/PrivIotShield/firmware/esp32_wifi_scanner/esp32_wifi_scanner.ino) lines 35–37:
```cpp
const char* BACKEND_HOST  = "192.168.1.105";  // <-- REPLACE WITH YOUR PC's IP FROM STEP 6
const int   BACKEND_PORT  = 8000;
const char* BACKEND_PATH  = "/api/v2/telemetry/ingest";
```

---

## 11. HOW TO FLASH THE ESP32
1. Connect the ESP32 to your PC via USB cable.
2. Open [`firmware/esp32_wifi_scanner/esp32_wifi_scanner.ino`](file:///N:/PROJECTS/PrivIoT/PrivIotShield/firmware/esp32_wifi_scanner/esp32_wifi_scanner.ino) in Arduino IDE.
3. Select `Tools` → `Port` → `COM5`.
4. Click the **Upload** arrow button (or press `Ctrl + U`).
   *(If prompted "Connecting...", hold down the `BOOT` button on your ESP32 board for 2 seconds).*

---

## 12. SERIAL MONITOR BAUD RATE
* In Arduino IDE: `Tools` → `Serial Monitor` (or `Ctrl + Shift + M`).
* In the bottom-right dropdown, select **115200 baud**.

---

## 13. EXPECTED SERIAL OUTPUT

```
==================================================
       PRIVIOT SHIELD — ESP32 SENSOR NODE         
       Firmware: v4.0.0-PROD | Airspace Scanner   
==================================================

[WIFI] Connecting to SSID: MyHomeWiFi
.....
[WIFI] Connected successfully!
[WIFI] ESP32 Assigned IP: 192.168.1.182
[WIFI] ESP32 Hardware MAC: A0:B7:65:DD:EE:11
[WIFI] RSSI to Gateway:  -54 dBm

==================================================
[SCAN CYCLE #1] Scanning 2.4 GHz Airspace...
[SCAN] Discovery completed: 8 nearby networks found.
   #01 | BSSID: 00:14:22:1A:3B:5C | RSSI:  -48 dBm | CH:  1 | SSID: Office_Main_AP
   #02 | BSSID: 50:C7:BF:33:44:55 | RSSI:  -62 dBm | CH:  6 | SSID: TP-Link_Kasa_Plug
   #03 | BSSID: 74:83:C2:88:99:AA | RSSI:  -71 dBm | CH:  6 | SSID: Guest_WiFi
   ...
[HTTP] Dispatching batch to: http://192.168.1.105:8000/api/v2/telemetry/ingest
[HTTP] Response Status: 200
[SUCCESS] Telemetry ingested & correlated by PrivIoT backend!
[METRICS] Processed: 8 | New Discovered Assets: 5 | Anomalies: 0
==================================================
```

---

## 14. HOW TO VERIFY BACKEND RECEIVED TELEMETRY

In your FastAPI terminal, you will see real-time HTTP 200 log lines:
```
INFO:priviot.api:FastAPI [POST] /api/v2/telemetry/ingest -> 200 (12.4ms) [req_id=req-...]
```

Or run a manual test query:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health/live"
```

---

## 15. HOW TO VERIFY DATABASE RECORDS

Run this PowerShell command to see newly discovered physical devices in the database:
```powershell
.\venv\Scripts\python -c "from app import app; from models import Asset, Collector, Observation;
with app.app_context():
    print('\n=== SENSOR HEARTBEAT ===')
    for c in Collector.query.all():
        print(f'Collector: {c.name} | Status: {c.status} | Last Seen: {c.last_heartbeat}')
    print('\n=== DISCOVERED ASSETS ===')
    for a in Asset.query.filter_by(discovery_source='esp32_wifi_scan').all():
        print(f'Asset ID: {a.id} | BSSID/MAC: {a.mac_address} | SSID: {a.hostname} | Vendor: {a.vendor} | Source: {a.discovery_source}')
"
```

---

## 16. HOW TO VERIFY IN THE DASHBOARD

1. Open your browser: `http://localhost:3000/assets`.
2. Notice the green **REAL SENSOR** badge next to all devices discovered by the ESP32.
3. Click any discovered Wi-Fi device to view its **Device Trust Profile**:
   * **Discovery Source:** Wi-Fi Beacon Scan (ESP32)
   * **Reconciliation Mode:** Hardware BSSID / Radio (ESP32)
   * **Confidence:** Derived honestly from MAC OUI & SSID signals without claiming false 100% certainty.

---

## 17. TROUBLESHOOTING

| Symptom | Cause | Resolution |
|---|---|---|
| `[ERROR] HTTP POST failed: connection refused` | `BACKEND_HOST` is set to `localhost` or wrong LAN IP | Set `BACKEND_HOST` to your PC's Wi-Fi IPv4 from `ipconfig`. Ensure Uvicorn is bound to `0.0.0.0:8000`. |
| `[HTTP] Response Status: 401 Unauthorized` | Invalid `X-Sensor-Token` | Re-run `.\venv\Scripts\python scripts/register_esp32_collector.py` and copy the exact token to `SENSOR_TOKEN`. |
| `[WIFI] Connection failed` | 5 GHz only or typo in Wi-Fi credentials | Ensure the Wi-Fi router broadcasts 2.4 GHz (ESP32 does not support 5 GHz). |
| Arduino IDE compilation error: `ArduinoJson.h: No such file` | Library not installed | In Arduino IDE: `Sketch` → `Include Library` → `Manage Libraries` → Install `ArduinoJson`. |
| Windows Firewall blocks port 8000 | Inbound rules blocking local LAN connections | Allow Python/Uvicorn on Private Networks in Windows Defender Firewall, or run: `netsh advfirewall firewall add rule name="PrivIoT Port 8000" dir=in action=allow protocol=TCP localport=8000` |
