"""
FastAPI Server-Sent Events (SSE) Real-Time Streaming Router
Provides live tenant-scoped security event feeds for SOC dashboards.
"""
import os
import json
import asyncio
import logging
from datetime import datetime
from typing import Optional, AsyncGenerator
from fastapi import APIRouter, Depends, Query, Request, HTTPException, status
from fastapi.responses import StreamingResponse
from priviot.api.dependencies import get_current_user, get_current_tenant
from priviot.data.models import User

logger = logging.getLogger("priviot.api.events")

router = APIRouter(prefix="/api/v2/events", tags=["Real-Time Event Streams"])

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# In-memory queue registry for testing/fallback environments without live Redis
LOCAL_EVENT_SUBSCRIBERS = {}

def register_local_subscriber(tenant_id: str, queue: asyncio.Queue):
    if tenant_id not in LOCAL_EVENT_SUBSCRIBERS:
        LOCAL_EVENT_SUBSCRIBERS[tenant_id] = set()
    LOCAL_EVENT_SUBSCRIBERS[tenant_id].add(queue)

def unregister_local_subscriber(tenant_id: str, queue: asyncio.Queue):
    if tenant_id in LOCAL_EVENT_SUBSCRIBERS:
        LOCAL_EVENT_SUBSCRIBERS[tenant_id].discard(queue)


async def sse_event_generator(request: Request, tenant_id: str, site_id: Optional[str] = None) -> AsyncGenerator[str, None]:
    """
    Asynchronously yields Server-Sent Events for the authenticated tenant scope.
    """
    # 1. Yield Initial Handshake Event
    handshake = {
        "event_id": "evt_init",
        "event_type": "SYSTEM_CONNECTED",
        "timestamp": datetime.utcnow().isoformat(),
        "tenant_id": tenant_id,
        "payload": {"message": "Real-time SOC stream established.", "site_scope": site_id or "all"}
    }
    yield f"id: evt_init\nevent: SYSTEM_CONNECTED\ndata: {json.dumps(handshake)}\n\n"

    # 2. Setup Local Queue for Fallback & Test Determinism
    local_queue = asyncio.Queue(maxsize=100)
    register_local_subscriber(tenant_id, local_queue)

    # 3. Setup Redis Pub/Sub if available
    channel_name = f"priviot.events.{tenant_id}"
    pubsub = None
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(REDIS_URL, socket_timeout=2.0)
        pubsub = r.pubsub()
        await pubsub.subscribe(channel_name)
        logger.info(f"SSE: Client connected to Redis channel '{channel_name}'")
    except Exception as e:
        logger.warning(f"SSE: Redis Pub/Sub unavailable ({e}), operating in local event mode.")
        pubsub = None

    try:
        while True:
            # Check client disconnect
            if await request.is_disconnected():
                logger.info(f"SSE: Client disconnected from stream (tenant={tenant_id})")
                break

            msg_handled = False

            # Check Redis PubSub
            if pubsub:
                try:
                    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if msg and msg.get("data"):
                        raw_data = msg["data"].decode("utf-8") if isinstance(msg["data"], bytes) else str(msg["data"])
                        event_dict = json.loads(raw_data)
                        
                        # Filter by site if requested
                        if not site_id or event_dict.get("site_id") == site_id:
                            evt_id = event_dict.get("event_id", "evt_live")
                            evt_type = event_dict.get("event_type", "SECURITY_EVENT")
                            yield f"id: {evt_id}\nevent: {evt_type}\ndata: {raw_data}\n\n"
                            msg_handled = True
                except Exception as ex:
                    logger.debug(f"Redis poll exception: {ex}")

            # Check Local Queue fallback
            if not msg_handled and not local_queue.empty():
                raw_data = await local_queue.get()
                event_dict = json.loads(raw_data)
                evt_id = event_dict.get("event_id", "evt_live")
                evt_type = event_dict.get("event_type", "SECURITY_EVENT")
                yield f"id: {evt_id}\nevent: {evt_type}\ndata: {raw_data}\n\n"
                msg_handled = True

            if not msg_handled:
                # Periodic keepalive ping to prevent proxy/browser timeout
                yield ": keepalive\n\n"
                await asyncio.sleep(2.0)

    except asyncio.CancelledError:
        logger.info(f"SSE: Stream cancelled by client (tenant={tenant_id})")
    finally:
        unregister_local_subscriber(tenant_id, local_queue)
        if pubsub:
            try:
                await pubsub.unsubscribe(channel_name)
                await pubsub.close()
            except Exception:
                pass


@router.get("/stream", summary="Real-Time Security Operations Event Stream (SSE)")
async def stream_security_events(
    request: Request,
    site_id: Optional[str] = Query(None, description="Optional site filter"),
    tenant_id: str = Depends(get_current_tenant)
):
    """
    Subscribes the SOC console to live server-sent security events.
    """
    return StreamingResponse(
        sse_event_generator(request, tenant_id, site_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
