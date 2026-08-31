"""
PrivIoT Shield — Real-Time Security Event Bus (Redis Pub/Sub Transport)
Provides canonical typed security event serialization and tenant-isolated routing.
"""
import os
import json
import logging
import secrets
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger("priviot.events")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Secret blacklist to strictly prevent credential leakage into SSE streams
SENSITIVE_KEYS = {
    "password", "password_hash", "auth_token_hash", "token_hash",
    "raw_token", "api_key", "secret", "private_key", "gateway_credentials",
    "authorization", "session_secret", "cookie"
}

def sanitize_payload(obj: Any) -> Any:
    """Recursively filter sensitive keys from event payloads."""
    if isinstance(obj, dict):
        return {
            k: sanitize_payload(v) for k, v in obj.items()
            if k.lower() not in SENSITIVE_KEYS
        }
    elif isinstance(obj, list):
        return [sanitize_payload(item) for item in obj]
    return obj


@dataclass
class SecurityEvent:
    event_id: str
    event_type: str
    timestamp: str
    tenant_id: str
    site_id: str
    asset_id: Optional[int]
    correlation_id: Optional[str]
    severity: str
    payload: Dict[str, Any]

    def to_json(self) -> str:
        d = asdict(self)
        d["payload"] = sanitize_payload(d["payload"])
        return json.dumps(d)


class EventBus:
    """
    Publisher for real-time security events over tenant-scoped Redis Pub/Sub channels.
    """
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or REDIS_URL
        self._redis_client = None

    def _get_redis(self):
        if self._redis_client is None:
            try:
                import redis
                self._redis_client = redis.Redis.from_url(self.redis_url, socket_timeout=1.0)
            except Exception as e:
                logger.warning(f"Redis Pub/Sub unavailable: {e}")
                return None
        return self._redis_client

    def publish_event(self, event: SecurityEvent) -> bool:
        """
        Publish a typed security event to tenant-scoped channel: priviot.events.{tenant_id}
        """
        channel = f"priviot.events.{event.tenant_id}"
        r = self._get_redis()
        if not r:
            logger.debug(f"EventBus fallback (Redis inactive): Dropped live event {event.event_type}")
            return False

        try:
            raw_data = event.to_json()
            r.publish(channel, raw_data)
            logger.info(f"EventBus: Published [{event.event_type}] on channel '{channel}' (id={event.event_id})")
            return True
        except Exception as exc:
            logger.warning(f"EventBus publication failed: {exc}")
            return False

    # Canonical Helper Constructors
    def emit_asset_discovered(self, tenant_id: str, site_id: str, asset_id: int, ip_address: str, vendor: str, model: str, correlation_id: Optional[str] = None):
        event = SecurityEvent(
            event_id=f"evt_{secrets.token_hex(6)}",
            event_type="ASSET_DISCOVERED",
            timestamp=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            site_id=site_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            severity="info",
            payload={
                "asset_id": asset_id,
                "ip_address": ip_address,
                "vendor": vendor,
                "model": model,
                "status": "NEW"
            }
        )
        return self.publish_event(event)

    def emit_behavior_drift(self, tenant_id: str, site_id: str, asset_id: int, drift_type: str, severity: str, difference: str, confidence: float, correlation_id: Optional[str] = None):
        event = SecurityEvent(
            event_id=f"evt_{secrets.token_hex(6)}",
            event_type="BEHAVIOR_DRIFT_DETECTED",
            timestamp=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            site_id=site_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            severity=severity,
            payload={
                "asset_id": asset_id,
                "drift_type": drift_type,
                "difference": difference,
                "confidence": confidence
            }
        )
        return self.publish_event(event)

    def emit_alert_created(self, tenant_id: str, site_id: str, alert_id: int, asset_id: Optional[int], alert_type: str, severity: str, title: str, correlation_id: Optional[str] = None):
        event = SecurityEvent(
            event_id=f"evt_{secrets.token_hex(6)}",
            event_type="ALERT_CREATED",
            timestamp=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            site_id=site_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            severity=severity,
            payload={
                "alert_id": alert_id,
                "alert_type": alert_type,
                "title": title
            }
        )
        return self.publish_event(event)

    def emit_pri_changed(self, tenant_id: str, site_id: str, asset_id: int, old_pri: float, new_pri: float, pri_level: str, correlation_id: Optional[str] = None):
        event = SecurityEvent(
            event_id=f"evt_{secrets.token_hex(6)}",
            event_type="PRI_CHANGED",
            timestamp=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            site_id=site_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            severity="high" if new_pri >= 6.0 else "info",
            payload={
                "asset_id": asset_id,
                "old_pri": old_pri,
                "new_pri": new_pri,
                "pri_level": pri_level
            }
        )
        return self.publish_event(event)

    def emit_containment_state_changed(self, tenant_id: str, site_id: str, intent_id: int, asset_id: int, target_provider: str, new_state: str, correlation_id: Optional[str] = None):
        event = SecurityEvent(
            event_id=f"evt_{secrets.token_hex(6)}",
            event_type="CONTAINMENT_STATE_CHANGED",
            timestamp=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            site_id=site_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            severity="verified" if new_state == "VERIFIED" else "info",
            payload={
                "intent_id": intent_id,
                "asset_id": asset_id,
                "provider": target_provider,
                "state": new_state
            }
        )
        return self.publish_event(event)

    def emit_collector_status_changed(self, tenant_id: str, site_id: str, collector_id: int, collector_name: str, new_status: str):
        event = SecurityEvent(
            event_id=f"evt_{secrets.token_hex(6)}",
            event_type="COLLECTOR_STATUS_CHANGED",
            timestamp=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            site_id=site_id,
            asset_id=None,
            correlation_id=None,
            severity="critical" if new_status in ("offline", "revoked") else "info",
            payload={
                "collector_id": collector_id,
                "collector_name": collector_name,
                "status": new_status
            }
        )
        return self.publish_event(event)


# Singleton
event_bus = EventBus()
