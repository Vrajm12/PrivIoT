"""
Celery Asynchronous Containment Tasks
"""
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from priviot.workers.celery_app import celery_app
from app import app as flask_app
from extensions import db
from priviot.data.models import ContainmentIntent, Asset, AuditEvent
from priviot.engines.containment import containment_engine

logger = logging.getLogger("priviot.workers.containment")

@celery_app.task(bind=True, max_retries=2, default_retry_delay=5)
def async_apply_containment_task(self, intent_id: int, tenant_id: str, actor_id: int) -> Dict[str, Any]:
    """
    Asynchronously push verified containment rules to network gateway appliance.
    """
    with flask_app.app_context():
        intent = ContainmentIntent.query.filter_by(id=intent_id, tenant_id=tenant_id).first()
        if not intent:
            logger.error(f"Worker: Containment intent {intent_id} not found in tenant '{tenant_id}'")
            return {"status": "error", "error": "Intent not found"}

        asset = Asset.query.filter_by(id=intent.asset_id, tenant_id=tenant_id).first()
        if not asset:
            return {"status": "error", "error": "Asset not found"}

        try:
            intent.status = containment_engine.transition_state(intent.status, "APPLYING")
            
            res = containment_engine.execute_apply(
                intent_dict=intent.to_dict(),
                ip_address=asset.ip_address,
                provider_name=intent.applied_provider or "iptables"
            )

            if res.get("success"):
                intent.status = containment_engine.transition_state("APPLYING", "VERIFIED")
                intent.executed_at = datetime.utcnow()
            else:
                intent.status = "FAILED"

            audit = AuditEvent(
                tenant_id=tenant_id,
                actor_id=actor_id,
                action="async_containment_applied",
                target_type="containment",
                target_id=str(intent.id),
                details_json=json.dumps({"intent_id": intent.id, "status": intent.status}),
                result="success" if res.get("success") else "failure"
            )
            db.session.add(audit)
            db.session.commit()

            # Emit real-time containment state update
            try:
                from priviot.services.event_bus import event_bus
                event_bus.emit_containment_state_changed(
                    tenant_id=tenant_id,
                    site_id=getattr(asset, "network_scope", "default_site") or "default_site",
                    intent_id=intent.id,
                    asset_id=asset.id,
                    target_provider=intent.applied_provider or "iptables",
                    new_state=intent.status
                )
            except Exception:
                pass

            return {"status": intent.status, "message": "Async containment execution completed"}

        except Exception as exc:
            logger.exception(f"Worker failure applying containment {intent_id}: {exc}")
            intent.status = "FAILED"
            db.session.commit()
            raise self.retry(exc=exc)
