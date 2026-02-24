# api/app/routers/system.py

import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
import redis.asyncio as redis

from app.schemas import UserInDB
from app.core.security import get_current_admin_user
from app.core.dependencies import get_redis_connection
from app.services.audit_logger import get_audit_failure_count

router = APIRouter(prefix="/system", tags=["System"])

# ── Phase 9A.2-E: Control-plane helper URLs ─────────────────────────
_NGINX_CONTROL_URL = os.getenv(
    "NGINX_CONTROL_BASE_URL", "http://nginx-control:8081"
).rstrip("/")
_FP_CONTROL_URL = os.getenv(
    "FORWARD_PROXY_CONTROL_BASE_URL", "http://forward-proxy-control:8082"
).rstrip("/")
_WAF_ENGINE_URL = os.getenv(
    "WAF_ENGINE_BASE_URL", "http://waf:8000"
).rstrip("/")


async def _probe(url: str, timeout: float = 2.0) -> dict[str, Any]:
    """Fire a GET to the given health URL; return status dict."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
        return {"reachable": True, "status_code": resp.status_code}
    except httpx.TimeoutException:
        return {"reachable": False, "error": "timeout"}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)[:120]}


@router.get("/health")
async def health_check():
    """Return enriched health status including helper reachability."""
    audit_failures = get_audit_failure_count()

    # Probe control-plane helpers and WAF engine in parallel
    import asyncio
    nginx_probe, fp_probe, waf_probe = await asyncio.gather(
        _probe(f"{_NGINX_CONTROL_URL}/health"),
        _probe(f"{_FP_CONTROL_URL}/health"),
        _probe(f"{_WAF_ENGINE_URL}/health"),
    )

    # Parse WAF engine TTL info if available
    waf_ttl_days = None
    if waf_probe.get("reachable"):
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{_WAF_ENGINE_URL}/health")
                if resp.status_code == 200:
                    data = resp.json()
                    waf_ttl_days = data.get("inspection_ttl_days")
        except Exception:
            pass

    overall = "healthy"
    if audit_failures > 0:
        overall = "degraded"

    return {
        "status": overall,
        "timestamp": datetime.now(timezone.utc),
        "audit_persistence_failures": audit_failures,
        "helpers": {
            "nginx_control": nginx_probe,
            "forward_proxy_control": fp_probe,
            "waf_engine": waf_probe,
        },
        "inspection_ttl_days": waf_ttl_days,
    }

@router.get("/vt-cache/stats", response_model=dict)
async def get_vt_cache_stats(
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get statistics about the VirusTotal IP cache in Redis."""
    stats = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_entries": 0, "malicious_count": 0, "clean_count": 0, "error_count": 0
    }
    try:
        async for key in redis_client.scan_iter('ip_info:*'):
            try:
                entry = await redis_client.get(key)
                if entry:
                    data = json.loads(entry)
                    if 'vt' in data:
                        stats['total_entries'] += 1
                        if data['vt'].get('is_malicious'):
                            stats['malicious_count'] += 1
                        else:
                            stats['clean_count'] += 1
            except (json.JSONDecodeError, TypeError):
                stats['error_count'] += 1
                continue
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting cache stats: {str(e)}"
        )

@router.post("/vt-cache/cleanup", response_model=dict)
async def cleanup_vt_cache(
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Manually clear all VirusTotal data from the IP cache in Redis."""
    cleaned_count = 0
    try:
        async for key in redis_client.scan_iter('ip_info:*'):
            entry = await redis_client.get(key)
            if entry:
                try:
                    data = json.loads(entry)
                    if 'vt' in data:
                        del data['vt']
                        await redis_client.set(key, json.dumps(data))
                        cleaned_count += 1
                except (json.JSONDecodeError, TypeError):
                    continue
        return {
            "message": "Cache cleanup completed successfully.",
            "cleaned_entries": cleaned_count
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error cleaning cache: {str(e)}"
        )