"""
PrivIoT - Evidence-Backed DNS Intelligence & Domain Classification Engine (Phase 2)
Categorizes DNS telemetry into KNOWN_GOOD, KNOWN_VENDOR, INTERNAL, UNKNOWN, SUSPICIOUS, and THREAT_INTEL_MATCH.
Enforces strict evidence standards (never flagging domains malicious purely because they are foreign/cloud-hosted).
"""

import math
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from extensions import db
from models import Alert

logger = logging.getLogger(__name__)

# Authoritative Whitelist & Vendor Catalog
KNOWN_GOOD_DOMAINS = {
    "pool.ntp.org", "time.google.com", "time.windows.com", "time.cloudflare.com",
    "dns.google", "one.one.one.one", "cloudflare-dns.com", "schema.org", "w3.org"
}

KNOWN_VENDOR_DOMAINS = {
    "hik-connect.com": "Hikvision Cloud P2P",
    "ezvizlife.com": "Ezviz / Hikvision IoT Platform",
    "dahuacloud.com": "Dahua Cloud Service",
    "lechange.com": "Imou / Dahua Consumer Cloud",
    "tplinkcloud.com": "TP-Link Kasa & Tapo Cloud",
    "tplinkra.com": "TP-Link Remote Access",
    "tuya.com": "Tuya Smart IoT Platform",
    "tuyaus.com": "Tuya North America Broker",
    "smartlife.me": "Tuya SmartLife Services",
    "amazon.com": "Amazon AWS / Alexa Infrastructure",
    "amazonaws.com": "Amazon Web Services",
    "googleapis.com": "Google Cloud Infrastructure",
    "apple.com": "Apple HomeKit / iCloud",
    "nest.com": "Google Nest Services"
}

KNOWN_THREAT_C2_DOMAINS = {
    "mirai-botnet.cc": "Mirai Variant C2 Command Broker",
    "dark-iot-c2.net": "DarkIoT Weaponized Exploitation Node",
    "iot-exploit-hub.ru": "Active CVE Weaponization & Payload Staging",
    "mozi-dht-seed.org": "Mozi P2P Botnet Master Node"
}

DYNAMIC_DNS_SUFFIXES = {
    ".duckdns.org", ".no-ip.org", ".no-ip.biz", ".ngrok.io", ".hopto.org", ".zapto.org"
}


def calculate_domain_entropy(domain: str) -> float:
    """Calculate Shannon entropy to identify algorithmic DGA domain patterns."""
    subdomain = domain.split('.')[0] if '.' in domain else domain
    if not subdomain:
        return 0.0
    prob = [float(subdomain.count(c)) / len(subdomain) for c in dict.fromkeys(list(subdomain))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return round(entropy, 2)


class DNSIntelligenceEngine:
    """
    Evaluates and classifies DNS queries from IoT assets.
    """

    def classify_domain(self, domain: str) -> Tuple[str, str, float]:
        """
        Returns (category, evidence_description, confidence)
        Categories: KNOWN_GOOD, KNOWN_VENDOR, INTERNAL, UNKNOWN, SUSPICIOUS, THREAT_INTEL_MATCH
        """
        if not domain:
            return "UNKNOWN", "Empty domain string", 0.1

        dom_clean = domain.lower().strip().rstrip('.')

        # 1. Internal & Multicast/Reverse DNS
        if dom_clean.endswith(".local") or dom_clean.endswith(".lan") or dom_clean.endswith(".internal") or dom_clean.endswith(".in-addr.arpa"):
            return "INTERNAL", "Local network mDNS/mDNS or subnet PTR reverse lookup", 0.99

        # 2. Known Good Infrastructure
        for good in KNOWN_GOOD_DOMAINS:
            if dom_clean == good or dom_clean.endswith("." + good):
                return "KNOWN_GOOD", f"Authoritative global infrastructure service ({good})", 0.95

        # 3. Known Vendor Cloud Platform
        for vendor_dom, desc in KNOWN_VENDOR_DOMAINS.items():
            if dom_clean == vendor_dom or dom_clean.endswith("." + vendor_dom):
                return "KNOWN_VENDOR", f"Legitimate vendor cloud endpoint: {desc}", 0.90

        # 4. Confirmed Threat Intelligence C2 Match
        for c2_dom, desc in KNOWN_THREAT_C2_DOMAINS.items():
            if dom_clean == c2_dom or dom_clean.endswith("." + c2_dom):
                return "THREAT_INTEL_MATCH", f"Authoritative C2 indicator: {desc}", 0.98

        # 5. Dynamic DNS & High-Entropy DGA Check
        is_ddns = any(dom_clean.endswith(suffix) for suffix in DYNAMIC_DNS_SUFFIXES)
        entropy = calculate_domain_entropy(dom_clean)

        if is_ddns:
            return "SUSPICIOUS", f"Dynamic DNS endpoint ({dom_clean}) commonly leveraged for unmanaged egress", 0.75

        if entropy > 3.8 and len(dom_clean.split('.')[0]) > 12:
            return "SUSPICIOUS", f"High Shannon entropy ({entropy}) suggesting potential Domain Generation Algorithm (DGA)", 0.70

        # 6. Default: Unclassified Cloud/Web Service
        return "UNKNOWN", "Unclassified external domain without established threat or vendor signature", 0.50

    def evaluate_dns_query(self, tenant_id: str, asset: Any, domain: str, 
                           resolved_ip: Optional[str] = None, timestamp: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Evaluate live DNS query, log findings, and trigger security alerts if malicious/suspicious.
        """
        category, evidence, confidence = self.classify_domain(domain)
        now = timestamp or datetime.utcnow()

        # Trigger high-priority alert for C2 Threat Intel match
        if category == "THREAT_INTEL_MATCH":
            alert_exists = Alert.query.filter_by(
                tenant_id=tenant_id,
                asset_id=asset.id,
                alert_type="threat_intel_dns_match",
                status="OPEN"
            ).first()

            if not alert_exists:
                alert = Alert(
                    tenant_id=tenant_id,
                    asset_id=asset.id,
                    alert_type="threat_intel_dns_match",
                    severity="critical",
                    title=f"Critical Threat Intelligence Match: {domain}",
                    description=f"Device {asset.vendor} {asset.device_type} ({asset.ip_address}) resolved malicious C2 domain '{domain}'. {evidence}",
                    evidence_json=json.dumps({
                        "domain": domain,
                        "resolved_ip": resolved_ip,
                        "category": category,
                        "evidence": evidence,
                        "confidence": confidence,
                        "timestamp": now.isoformat()
                    }),
                    status="OPEN",
                    created_at=now
                )
                db.session.add(alert)
                logger.warning(f"CRITICAL DNS ALERT: Asset {asset.id} resolved {domain} ({evidence})")

                # Emit real-time alert event
                try:
                    from priviot.services.event_bus import event_bus
                    event_bus.emit_alert_created(
                        tenant_id=tenant_id,
                        site_id=getattr(asset, "network_scope", "default_site") or "default_site",
                        alert_id=alert.id or 0,
                        asset_id=asset.id,
                        alert_type="threat_intel_dns_match",
                        severity="critical",
                        title=f"Critical Threat Intelligence Match: {domain}"
                    )
                except Exception:
                    pass

        return {
            "domain": domain,
            "resolved_ip": resolved_ip,
            "category": category,
            "evidence": evidence,
            "confidence": confidence
        }


# Singleton instance
dns_intel_engine = DNSIntelligenceEngine()
