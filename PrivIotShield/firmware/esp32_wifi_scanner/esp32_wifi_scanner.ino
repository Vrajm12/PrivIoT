/*
 ==============================================================================
  PRIVIOT SHIELD — ESP32 PHYSICAL TELEMETRY SENSOR FIRMWARE
  Continuous 2.4 GHz Wi-Fi & BLE Airspace Scanner Node
 ==============================================================================
  Target Board:       ESP32 Dev Module (NodeMCU-32S / WROOM-32)
  Serial Baud Rate:   115200 baud
  Required Libraries: ArduinoJson (v6 or v7)
                      WiFi (built-in ESP32 core)
                      HTTPClient (built-in ESP32 core)
                      BLEDevice (optional, built-in ESP32 core)
 ==============================================================================
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// Optional: Enable BLE Scanning alongside Wi-Fi
#define ENABLE_BLE_SCAN false

#if ENABLE_BLE_SCAN
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#endif

// ==============================================================================
// 1. NETWORK & BACKEND CONFIGURATION
// ==============================================================================
// Set your 2.4 GHz Wi-Fi credentials:
const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// Set your PC/Server LAN IP address (Run 'ipconfig' on Windows to find it):
// IMPORTANT: Do NOT use "localhost" or "127.0.0.1" here!
const char* BACKEND_HOST  = "172.16.133.1";  // <--- YOUR LAPTOP HOTSPOT IP
const int   BACKEND_PORT  = 8000;
const char* BACKEND_PATH  = "/api/v2/telemetry/ingest";

// Pre-Shared Sensor Provisioning Token & Tenant Scope:
const char* SENSOR_TOKEN  = "priviot_sensor_F5pFf66Cr84xDMlrOTGGEzZbMtKSDsz_w8s9MA5hIh8";
const char* TENANT_ID     = "default_tenant";

// Telemetry Scan Cadence (in milliseconds):
const unsigned long SCAN_INTERVAL_MS = 20000; // 20 seconds between scans

// ==============================================================================
// GLOBAL STATE & TIMERS
// ==============================================================================
unsigned long lastScanTime = 0;
unsigned long scanCycleCount = 0;

// Helper: Format BSSID uint8_t* to uppercase colon-separated string "AA:BB:CC:DD:EE:FF"
String formatBSSID(uint8_t* bssid) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  return String(buf);
}

// Connect or reconnect to Wi-Fi
void ensureWiFiConnected() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  Serial.println();
  Serial.print("[WIFI] Connecting to SSID: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 25) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println();
    Serial.println("[WIFI] Connected successfully!");
    Serial.print("[WIFI] ESP32 Assigned IP: ");
    Serial.println(WiFi.localIP());
    Serial.print("[WIFI] ESP32 Hardware MAC: ");
    Serial.println(WiFi.macAddress());
    Serial.print("[WIFI] RSSI to Gateway:  ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");
  } else {
    Serial.println();
    Serial.println("[WIFI] Connection failed. Will retry in next cycle...");
  }
}

// Perform scan and dispatch telemetry batch to PrivIoTShield backend
void performScanAndSendTelemetry() {
  scanCycleCount++;
  Serial.println();
  Serial.println("==================================================");
  Serial.print("[SCAN CYCLE #");
  Serial.print(scanCycleCount);
  Serial.println("] Scanning 2.4 GHz Airspace...");

  // 1. Perform Asynchronous/Synchronous 802.11 Wi-Fi Scan
  int numNetworks = WiFi.scanNetworks(false, true); // (async=false, show_hidden=true)

  if (numNetworks < 0) {
    Serial.println("[ERROR] Wi-Fi scan failed with error code.");
    return;
  }

  Serial.print("[SCAN] Discovery completed: ");
  Serial.print(numNetworks);
  Serial.println(" nearby networks found.");

  if (numNetworks == 0) {
    Serial.println("[SCAN] No active networks detected in range.");
    return;
  }

  // 2. Build Telemetry JSON Batch using ArduinoJson
  // Calculate dynamic capacity based on number of networks
  DynamicJsonDocument doc(12288); // 12 KB buffer handles up to 30 networks safely
  doc["collector_id"] = "ESP32_Hardware_Scanner";

  JsonArray observations = doc.createNestedArray("observations");

  for (int i = 0; i < numNetworks; ++i) {
    String ssid = WiFi.SSID(i);
    if (ssid.length() == 0) {
      ssid = "<hidden>";
    }
    String bssidStr = formatBSSID(WiFi.BSSID(i));
    int32_t rssi = WiFi.RSSI(i);
    int32_t channel = WiFi.channel(i);
    wifi_auth_mode_t authMode = WiFi.encryptionType(i);

    // Print summary to Serial
    Serial.printf("   #%02d | BSSID: %s | RSSI: %4d dBm | CH: %2d | SSID: %s\n",
                  i + 1, bssidStr.c_str(), rssi, channel, ssid.c_str());

    JsonObject obs = observations.createNestedObject();
    obs["observation_type"] = "wifi_scan";
    obs["src_mac"] = bssidStr;
    obs["src_ip"] = "0.0.0.0";

    JsonObject payload = obs.createNestedObject("payload");
    payload["ssid"] = ssid;
    payload["bssid"] = bssidStr;
    payload["rssi"] = rssi;
    payload["channel"] = channel;
    payload["encryption_type"] = (int)authMode;
    payload["auto_discover"] = true;
  }

  // Free scan results from memory
  WiFi.scanDelete();

  // 3. Serialize JSON to String
  String jsonString;
  serializeJson(doc, jsonString);

  // 4. Send HTTP POST Request to FastAPI Control Plane
  if (WiFi.status() != WL_CONNECTED) {
    ensureWiFiConnected();
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("[ERROR] Cannot send telemetry: Wi-Fi offline.");
      return;
    }
  }

  HTTPClient http;
  String targetUrl = "http://" + String(BACKEND_HOST) + ":" + String(BACKEND_PORT) + String(BACKEND_PATH);

  Serial.print("[HTTP] Dispatching batch to: ");
  Serial.println(targetUrl);

  http.begin(targetUrl);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Sensor-Token", SENSOR_TOKEN);
  http.addHeader("X-Tenant-ID", TENANT_ID);
  http.setTimeout(8000); // 8 second timeout

  int httpResponseCode = http.POST(jsonString);

  if (httpResponseCode > 0) {
    String responseBody = http.getString();
    Serial.print("[HTTP] Response Status: ");
    Serial.println(httpResponseCode);

    if (httpResponseCode == 200) {
      Serial.println("[SUCCESS] Telemetry ingested & correlated by PrivIoT backend!");
      // Parse backend response metrics
      DynamicJsonDocument resDoc(512);
      DeserializationError err = deserializeJson(resDoc, responseBody);
      if (!err) {
        int processed = resDoc["processed_count"] | 0;
        int newAssets = resDoc["new_assets_discovered"] | 0;
        int anomalies = resDoc["anomalies_detected"] | 0;
        Serial.printf("[METRICS] Processed: %d | New Discovered Assets: %d | Anomalies: %d\n",
                      processed, newAssets, anomalies);
      }
    } else {
      Serial.print("[WARN] Ingestion rejected with body: ");
      Serial.println(responseBody);
    }
  } else {
    Serial.print("[ERROR] HTTP POST failed: ");
    Serial.println(http.errorToString(httpResponseCode).c_str());
    Serial.println("       Tip: Check if backend is running on 0.0.0.0:8000 and PC firewall allows port 8000.");
  }

  http.end();
  Serial.println("==================================================");
}

// ==============================================================================
// ARDUINO SETUP & MAIN LOOP
// ==============================================================================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("==================================================");
  Serial.println("       PRIVIOT SHIELD — ESP32 SENSOR NODE         ");
  Serial.println("       Firmware: v4.0.0-PROD | Airspace Scanner   ");
  Serial.println("==================================================");

  ensureWiFiConnected();

  // Perform initial immediate scan
  performScanAndSendTelemetry();
  lastScanTime = millis();
}

void loop() {
  // Check and maintain Wi-Fi connection
  if (WiFi.status() != WL_CONNECTED) {
    ensureWiFiConnected();
  }

  // Periodic Telemetry Ingestion Timer
  if (millis() - lastScanTime >= SCAN_INTERVAL_MS) {
    lastScanTime = millis();
    performScanAndSendTelemetry();
  }

  delay(100);
}
