# PRIVIOT SHIELD — PRODUCTION CONFIGURATION AUDIT & DEPLOYMENT GUIDE
**Document Version:** 1.0.0-PROD  
**Status:** PRODUCTION HARDENED  

---

## 1. Environment Variable Specification

| Variable | Recommended Production Value | Security Invariant |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `production` | Disables debug mode and Swagger playground in untrusted networks. |
| `SECRET_KEY` | `64-character random hex` | Cryptographic root for JWT and HMAC tokens. |
| `DATABASE_URL` | `postgresql+asyncpg://...` | Enforces TLS connection pooling to PostgreSQL 16. |
| `REDIS_URL` | `rediss://...` | Encrypted TLS connection to Redis Broker. |
| `CORS_ORIGINS` | `https://soc.company.com` | Strict origin matching. Wildcards prohibited. |
| `CONTAINMENT_MODE` | `REQUIRE_APPROVAL` | Prevents autonomous firewall rule modifications. |
| `CELERY_WORKER_CONCURRENCY`| `4` (or CPU count) | Bounded worker memory consumption. |

---

## 2. Production Fail-Fast Validation Checklist

The application startup sequence validates that:
1. `DEBUG=False` in production environments.
2. `SECRET_KEY` is not the default development passphrase.
3. Database connection pool responds within 50ms.
4. Redis event bus and task queues are live.
5. All sensitive environment values are sanitized from console logs.
