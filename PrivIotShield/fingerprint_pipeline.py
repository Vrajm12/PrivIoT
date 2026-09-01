"""
PrivIoT - Hardened Device Fingerprinting & Identity Reconciliation Engine (Phase 1.5)
Implements independent IdentityEvidence calculations (damping correlated features)
and multi-priority asset reconciliation with DHCP address change and IP conflict detection.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class IdentityEvidenceClaim:
    """
    Structured evidence claim for an identity decision.
    """
    def __init__(self, source: str, observation: str, weight: float, confidence_contrib: float, parser_version: str = "v1.5"):
        self.source = source
        self.observation = observation
        self.weight = weight
        self.confidence_contrib = confidence_contrib
        self.timestamp = datetime.utcnow().isoformat()
        self.parser_version = parser_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "observation": self.observation,
            "weight": round(self.weight, 2),
            "confidence_contribution": round(self.confidence_contrib, 2),
            "timestamp": self.timestamp,
            "parser_version": self.parser_version
        }


class FingerprintPipeline:
    """
    Evaluates evidence-weighted identity matching without false 100% certainty claims
    and performs DHCP-aware asset reconciliation.
    """

    def process_observation(self, obs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process raw host observations into an evidence-backed probabilistic device fingerprint.
        """
        ip = obs.get("ip_address")
        mac = obs.get("mac_address")
        open_ports = obs.get("open_ports", [])
        banners = obs.get("banners", {})
        tls_cert = obs.get("tls_cert")
        upnp = obs.get("upnp_info")

        inferred_vendor = "Unknown"
        inferred_model = "Unknown Model"
        inferred_type = "Generic IoT Device"
        base_confidence = 0.25
        claims: List[IdentityEvidenceClaim] = []

        seen_sources = set()

        # 0. Hardware MAC OUI Resolution (Weight 0.35)
        if mac and len(mac) >= 8:
            prefix = mac[:8].upper()
            oui_map = {
                # Surveillance & Smart Cameras
                "00:12:17": ("Hikvision", "IP Camera"),
                "00:40:8C": ("Axis Communications", "Access Controller"),
                "E0:50:8B": ("Dahua", "IP Camera"),
                # IoT & Smart Home
                "50:C7:BF": ("TP-Link", "Smart Plug / IoT"),
                "14:EB:B6": ("TP-Link", "Wi-Fi Router / AP"),
                "E8:48:B8": ("TP-Link", "Smart Device"),
                "B0:4E:26": ("TP-Link", "Wireless Device"),
                "EC:B5:FA": ("Philips Hue", "IoT Gateway"),
                "50:02:91": ("Tuya Smart", "Smart IoT Device"),
                "70:89:76": ("Tuya Smart", "Smart Home Sensor"),
                "D4:A6:51": ("Tuya Smart", "Smart Controller"),
                # Espressif Modules (ESP32 / ESP8266)
                "24:0A:C4": ("Espressif", "ESP32 IoT Node"),
                "30:AE:A4": ("Espressif", "ESP32 IoT Node"),
                "84:CC:A8": ("Espressif", "ESP8266 IoT Node"),
                "94:E6:86": ("Espressif", "ESP32 IoT Node"),
                "A0:B7:65": ("Espressif", "ESP32 Dev Module"),
                "AC:67:B2": ("Espressif", "ESP32 Device"),
                "C4:4F:33": ("Espressif", "ESP8266 Device"),
                "DC:4F:22": ("Espressif", "ESP32 Device"),
                "EC:62:60": ("Espressif", "ESP8266 Device"),
                "30:C6:F7": ("Espressif", "ESP32 Device"),
                # Networking & Infrastructure
                "00:14:22": ("Cisco", "Network Infrastructure"),
                "00:1A:A1": ("Cisco", "Wireless Controller"),
                "00:22:6B": ("Cisco-Linksys", "Wi-Fi Router"),
                "00:14:6C": ("Netgear", "Wi-Fi Router"),
                "00:1E:2A": ("Netgear", "Wireless Gateway"),
                "20:4E:7F": ("Netgear", "Wireless AP"),
                "74:83:C2": ("Ubiquiti", "UniFi Wireless AP"),
                "00:18:0A": ("Ubiquiti", "UniFi AP / Switch"),
                "FC:EC:DA": ("Ubiquiti", "UniFi Gateway"),
                "00:05:5D": ("D-Link", "Wireless Router"),
                "18:62:2C": ("D-Link", "Access Point"),
                "00:11:32": ("Synology", "Network Storage"),
                # Consumer & Mobile Ecosystems
                "F0:18:98": ("Apple", "Apple Host / Device"),
                "3C:06:30": ("Apple", "Apple Device"),
                "60:F8:1D": ("Apple", "Apple Device"),
                "3C:28:6D": ("Google", "Nest / Android Device"),
                "54:60:09": ("Google", "Google Home / Chromecast"),
                "CC:6E:A4": ("Samsung", "Smart Appliance"),
                "00:07:AB": ("Samsung", "Smart TV"),
                "00:1E:0B": ("HP", "Network Printer"),
                "00:26:86": ("Amazon", "Echo / Alexa Device"),
                "84:D6:D0": ("Amazon", "FireTV / Echo Device"),
                "00:1A:79": ("Intel", "Wi-Fi Interface"),
                "70:4F:57": ("Intel", "Wireless Controller")
            }
            if prefix in oui_map:
                v, t = oui_map[prefix]
                inferred_vendor = v
                inferred_type = t
                claims.append(IdentityEvidenceClaim(
                    source="mac_oui_database",
                    observation=f"MAC OUI '{prefix}' registered to {v} ({t})",
                    weight=0.35,
                    confidence_contrib=0.35
                ))
                seen_sources.add("mac_oui")

        # 0.1 Wi-Fi Beacon & Scan Signal
        ssid = obs.get("ssid")
        bssid = obs.get("bssid")
        rssi = obs.get("rssi")
        channel = obs.get("channel")
        if ssid or bssid:
            if inferred_type == "Generic IoT Device":
                inferred_type = "Wi-Fi Access Point / Router"
            if ssid and ssid != "<hidden>":
                inferred_model = f"SSID: {ssid}"
            claims.append(IdentityEvidenceClaim(
                source="esp32_wifi_beacon",
                observation=f"Wi-Fi SSID: '{ssid or 'Hidden'}', BSSID: {bssid or mac}, RSSI: {rssi or 'N/A'} dBm, Channel: {channel or 'N/A'}",
                weight=0.30,
                confidence_contrib=0.25
            ))
            seen_sources.add("wifi_scan")

        # 0.2 BLE Advertisement Signal
        ble_name = obs.get("name") or obs.get("ble_name")
        ble_addr = obs.get("address") or obs.get("ble_address")
        if ble_name or (obs.get("observation_type") == "ble_scan"):
            if inferred_type == "Generic IoT Device":
                inferred_type = "BLE Peripheral / Beacon"
            if ble_name:
                inferred_model = f"BLE: {ble_name}"
            claims.append(IdentityEvidenceClaim(
                source="esp32_ble_advertisement",
                observation=f"BLE Name: '{ble_name or 'Unnamed'}', Address: {ble_addr or mac}, RSSI: {rssi or 'N/A'} dBm",
                weight=0.30,
                confidence_contrib=0.25
            ))
            seen_sources.add("ble_scan")

        # 1. UPnP Device Descriptor (Independent Structured Protocol: Weight 0.35)
        if upnp:
            mfg = upnp.get("manufacturer")
            model = upnp.get("model")
            dev_type = upnp.get("device_type")
            if mfg:
                inferred_vendor = mfg
                claims.append(IdentityEvidenceClaim(
                    source="upnp_descriptor",
                    observation=f"Manufacturer: {mfg}, Model: {model or 'N/A'}",
                    weight=0.35,
                    confidence_contrib=0.30
                ))
                seen_sources.add("upnp")
            if model:
                inferred_model = model
            if dev_type:
                inferred_type = dev_type

        # 2. TLS Certificate SAN / Subject CN (Independent Cryptographic Layer: Weight 0.25)
        if tls_cert:
            cn = tls_cert.get("subject_cn") or ""
            issuer = tls_cert.get("issuer_cn") or ""
            
            # Dampen TLS contribution if UPnP already asserted same vendor (correlated signal)
            tls_contrib = 0.20 if "upnp" not in seen_sources else 0.15
            
            if "hikvision" in cn.lower() or "hikvision" in issuer.lower():
                if inferred_vendor == "Unknown":
                    inferred_vendor = "Hikvision"
                    inferred_type = "IP Camera / NVR"
                claims.append(IdentityEvidenceClaim(
                    source="tls_certificate",
                    observation=f"Subject CN: {cn}, Issuer: {issuer}",
                    weight=0.25,
                    confidence_contrib=tls_contrib
                ))
                seen_sources.add("tls")
            elif "dahua" in cn.lower() or "dahua" in issuer.lower():
                if inferred_vendor == "Unknown":
                    inferred_vendor = "Dahua"
                    inferred_type = "Smart Camera / DVR"
                claims.append(IdentityEvidenceClaim(
                    source="tls_certificate",
                    observation=f"Subject CN: {cn}",
                    weight=0.25,
                    confidence_contrib=tls_contrib
                ))
                seen_sources.add("tls")
            elif cn:
                claims.append(IdentityEvidenceClaim(
                    source="tls_certificate",
                    observation=f"Subject CN: {cn}",
                    weight=0.15,
                    confidence_contrib=0.10
                ))

        # 3. Protocol Banners & Proprietary Ports
        banners_str = json.dumps(banners).lower()
        banner_contrib = 0.15 if ("upnp" not in seen_sources and "tls" not in seen_sources) else 0.10

        if 8000 in open_ports or "hikvision" in banners_str or "dvrdvs-web" in banners_str:
            if inferred_vendor == "Unknown":
                inferred_vendor = "Hikvision"
            if inferred_type == "Generic IoT Device":
                inferred_type = "IP Camera / Surveillance NVR"
            claims.append(IdentityEvidenceClaim(
                source="service_banner_8000",
                observation="Port 8000 Hikvision Web/SDK banner observed",
                weight=0.20,
                confidence_contrib=banner_contrib
            ))

        if 37777 in open_ports or "dahua" in banners_str:
            if inferred_vendor == "Unknown":
                inferred_vendor = "Dahua"
            if inferred_type == "Generic IoT Device":
                inferred_type = "Smart Camera / DVR"
            claims.append(IdentityEvidenceClaim(
                source="service_port_37777",
                observation="Port 37777 Dahua DVR/Camera service active",
                weight=0.20,
                confidence_contrib=banner_contrib
            ))

        if 9999 in open_ports or "tapo" in banners_str or "kasa" in banners_str:
            if inferred_vendor == "Unknown":
                inferred_vendor = "TP-Link"
            if inferred_type == "Generic IoT Device":
                inferred_type = "Smart Plug / Switch"
            claims.append(IdentityEvidenceClaim(
                source="service_port_9999",
                observation="Port 9999 TP-Link Smart Home autokey protocol observed",
                weight=0.20,
                confidence_contrib=banner_contrib
            ))

        if 554 in open_ports:
            if inferred_type == "Generic IoT Device":
                inferred_type = "Smart Camera (RTSP Stream)"
            claims.append(IdentityEvidenceClaim(
                source="service_port_554",
                observation="Port 554 RTSP live streaming endpoint available",
                weight=0.15,
                confidence_contrib=0.08
            ))

        if 1883 in open_ports or 8883 in open_ports:
            if inferred_type == "Generic IoT Device":
                inferred_type = "Smart Sensor / MQTT Gateway"
            claims.append(IdentityEvidenceClaim(
                source="service_port_mqtt",
                observation=f"MQTT Broker active on port {1883 if 1883 in open_ports else 8883}",
                weight=0.15,
                confidence_contrib=0.08
            ))

        # Sum contributions with strict asymptotic capping (max 0.95 to never claim 100% certainty)
        total_confidence = min(0.95, round(base_confidence + sum(c.confidence_contrib for c in claims), 2))

        evidence_dict = {
            "identity_confidence": total_confidence,
            "claims_count": len(claims),
            "claims": [c.to_dict() for c in claims],
            "open_ports": open_ports,
            "reconciliation_notes": "Evidence evaluated with correlated signal damping."
        }

        return {
            "ip_address": ip,
            "mac_address": mac,
            "vendor": inferred_vendor,
            "manufacturer": inferred_vendor,
            "model": inferred_model,
            "device_type": inferred_type,
            "confidence": total_confidence,
            "evidence": evidence_dict
        }

    def reconcile_asset(self, db_session, user_id: int, obs: Dict[str, Any], network_scope: str = "192.168.1.0/24", tenant_id: str = "default_tenant") -> Tuple[Any, bool]:
        """
        Hardened multi-priority asset reconciliation:
        1. MAC address lookup (most stable).
        2. IP address lookup with fingerprint conflict check (DHCP reassignment detection).
        3. History tracking (ip_history, mac_history, identity_history).
        """
        from models import Asset, AssetService, AuditEvent

        fp = self.process_observation(obs)
        ip = fp["ip_address"]
        mac = fp["mac_address"]
        now_iso = datetime.utcnow().isoformat()
        now = datetime.utcnow()

        existing_asset = None
        reconciliation_method = "new_asset"

        # 1. Primary Priority: Stable Hardware MAC Address
        if mac and len(mac) == 17:
            existing_asset = Asset.query.filter_by(mac_address=mac, tenant_id=tenant_id).first()
            if existing_asset:
                reconciliation_method = "mac_address_match"

        # 2. Secondary Priority: IP Address with Fingerprint Conflict Check
        if not existing_asset and ip:
            candidate = Asset.query.filter_by(ip_address=ip, tenant_id=tenant_id).first()
            if candidate:
                # Check if new fingerprint is compatible with existing asset or completely conflicting (DHCP lease reuse)
                is_conflicting = (
                    candidate.vendor != "Unknown" and fp["vendor"] != "Unknown" and 
                    candidate.vendor.lower() != fp["vendor"].lower()
                )
                if is_conflicting:
                    # DHCP address was reassigned to a different physical device!
                    # Do NOT merge! Move old asset IP to stale and create new asset.
                    logger.info(f"DHCP Reassignment detected at {ip}: previous {candidate.vendor}, new {fp['vendor']}")
                    candidate.reconciliation_method = "stale_ip_reassigned"
                    existing_asset = None
                else:
                    existing_asset = candidate
                    reconciliation_method = "corroborated_ip_fingerprint"

        is_new = False

        if existing_asset:
            # Reconcile existing asset
            existing_asset.last_seen = now
            
            # Check for IP change on same MAC
            if existing_asset.ip_address != ip:
                ip_hist = existing_asset.get_ip_history()
                ip_hist.append({"ip": existing_asset.ip_address, "reassigned_at": now_iso})
                existing_asset.ip_history = json.dumps(ip_hist)
                existing_asset.ip_address = ip

            if mac and not existing_asset.mac_address:
                existing_asset.mac_address = mac

            existing_asset.reconciliation_method = reconciliation_method

            # Update identity if confidence is higher or equal
            if fp["confidence"] >= (existing_asset.identity_confidence or 0.0):
                if fp["vendor"] != "Unknown":
                    existing_asset.vendor = fp["vendor"]
                    existing_asset.manufacturer = fp["vendor"]
                if fp["model"] != "Unknown Model":
                    existing_asset.model = fp["model"]
                if fp["device_type"] != "Generic IoT Device":
                    existing_asset.device_type = fp["device_type"]
                existing_asset.identity_confidence = fp["confidence"]
                existing_asset.set_evidence(fp["evidence"])

            asset = existing_asset
        else:
            # Create new canonical Asset
            is_new = True
            asset = Asset(
                tenant_id=tenant_id,
                ip_address=ip,
                mac_address=mac,
                hostname=obs.get("hostname") or f"iot-{ip.replace('.', '-')}",
                vendor=fp["vendor"],
                manufacturer=fp["vendor"],
                model=fp["model"],
                device_type=fp["device_type"],
                identity_confidence=fp["confidence"],
                identity_evidence=json.dumps(fp["evidence"]),
                reconciliation_method=reconciliation_method,
                ip_history=json.dumps([{"ip": ip, "first_seen": now_iso}]),
                network_scope=network_scope,
                user_id=user_id,
                first_seen=now,
                last_seen=now
            )
            db_session.add(asset)
            db_session.flush()

            audit = AuditEvent(
                tenant_id=tenant_id,
                actor_id=user_id,
                action='asset_created',
                target_type='asset',
                target_id=str(asset.id),
                details_json=json.dumps({
                    "ip": ip, "vendor": fp["vendor"], "confidence": fp["confidence"], "reconciliation": reconciliation_method
                }),
                result='success'
            )
            db_session.add(audit)

        # 3. Hardened Service Inventory with explicit authentication & encryption semantics
        existing_services = {s.port: s for s in asset.services.all()}
        open_ports = obs.get("open_ports", [])
        banners = obs.get("banners", {})

        for port in open_ports:
            service_name = "http" if port in [80, 8080] else ("https" if port in [443, 8443] else ("rtsp" if port == 554 else ("mqtt" if port == 1883 else ("mqtts" if port == 8883 else ("telnet" if port == 23 else ("ssh" if port == 22 else "custom"))))))
            banner_val = banners.get(f"{port}/{service_name}") or banners.get(str(port)) or ""
            
            # Explicit evidence-backed security semantics
            if port in [443, 8443, 8883]:
                enc_status = "TLS"
                is_enc = True
            elif port in [80, 8080, 23, 1883]:
                enc_status = "PLAINTEXT"
                is_enc = False
            else:
                enc_status = "NOT_ASSESSED"
                is_enc = False

            auth_status = "NOT_ASSESSED"

            if port in existing_services:
                svc = existing_services[port]
                svc.last_seen = now
                if banner_val:
                    svc.version_banner = str(banner_val)[:255]
            else:
                new_svc = AssetService(
                    asset_id=asset.id,
                    port=port,
                    protocol='tcp',
                    service_name=service_name,
                    version_banner=str(banner_val)[:255],
                    is_encrypted=is_enc,
                    encryption_status=enc_status,
                    auth_indication=auth_status,
                    first_seen=now,
                    last_seen=now
                )
                db_session.add(new_svc)

        db_session.commit()
        return asset, is_new


# Singleton instance
fingerprint_pipeline = FingerprintPipeline()
