"""Decoupled WAF authorization engine for Nginx auth_request."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlsplit

import httpx
import redis.asyncio as redis
import uvicorn
from fastapi import FastAPI, Request, Response
from pymongo import AsyncMongoClient

from waf.checks.patterns.advanced_analyzer import get_analyzer
from waf.checks.security_engine import DEFAULT_POLICY, analyze_forwarded_request
from waf.ip.banlist import BAN_KEY_PREFIX, CLEAN_KEY_PREFIX
from waf.ip.local import is_local_ip

DEBUG = os.getenv("DEBUG", "false").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://mongodb:27017/waf_logs")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
BAN_TTL_SECONDS = int(os.getenv("BAN_TTL_SECONDS", "3600"))
INSPECTION_QUEUE_SIZE = int(os.getenv("INSPECTION_QUEUE_SIZE", "5000"))
INSPECTION_WORKERS = int(os.getenv("INSPECTION_WORKERS", "8"))
VT_TIMEOUT_SECONDS = float(os.getenv("VT_TIMEOUT_SECONDS", "8"))
MAX_LOG_BODY_BYTES = int(os.getenv("MAX_LOG_BODY_BYTES", "16384"))

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass(slots=True)
class InspectionJob:
    client_ip: str
    metadata: dict[str, Any]
    body: bytes
    queued_at: datetime


def _resolve_mongo_db_name() -> str:
    if MONGODB_DB_NAME:
        return MONGODB_DB_NAME

    parsed = urlparse(MONGODB_URL)
    path = parsed.path.lstrip("/")
    return path or "waf_logs"


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip:
        return real_ip

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def _extract_metadata(request: Request) -> dict[str, Any]:
    original_uri = request.headers.get("X-Original-URI") or request.url.path
    parsed = urlsplit(original_uri)

    return {
        "method": request.headers.get("X-Original-Method", request.method),
        "uri": original_uri,
        "path": parsed.path or request.url.path,
        "query": parsed.query or request.headers.get("X-Original-Query", ""),
        "host": request.headers.get("X-Original-Host", request.headers.get("Host", "")),
        "scheme": request.headers.get("X-Original-Proto", request.url.scheme),
        "request_id": request.headers.get("X-Request-ID", ""),
        "content_type": request.headers.get("Content-Type", ""),
        "content_length": request.headers.get("Content-Length", ""),
        "headers": dict(request.headers),
        "received_at": datetime.now(timezone.utc),
    }


def _serialize_request_body(body: bytes, content_type: str) -> dict[str, Any]:
    content_type_lc = (content_type or "").lower()
    body_hash = hashlib.sha256(body).hexdigest() if body else ""

    if not body:
        return {"content": "", "content_type": content_type, "size": 0, "sha256": body_hash}

    binary_types = (
        "image/",
        "video/",
        "audio/",
        "application/pdf",
        "application/zip",
        "application/octet-stream",
    )
    if any(marker in content_type_lc for marker in binary_types):
        return {
            "content": f"[BINARY_CONTENT:{len(body)} bytes]",
            "content_type": content_type,
            "size": len(body),
            "sha256": body_hash,
        }

    decoded = body.decode("utf-8", errors="ignore")
    truncated = len(decoded) > MAX_LOG_BODY_BYTES
    if truncated:
        decoded = decoded[:MAX_LOG_BODY_BYTES]

    return {
        "content": decoded,
        "truncated": truncated,
        "content_type": content_type,
        "size": len(body),
        "sha256": body_hash,
    }


def _is_vt_report_malicious(report: dict[str, Any]) -> bool:
    attributes = report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    try:
        malicious_count = int(stats.get("malicious", 0) or 0)
        suspicious_count = int(stats.get("suspicious", 0) or 0)
    except Exception:
        malicious_count = 0
        suspicious_count = 0

    total = 0
    for value in stats.values():
        if isinstance(value, int):
            total += value

    if total > 0:
        if malicious_count / total > 0.10:
            return True
        if suspicious_count / total > 0.20:
            return True

    try:
        reputation = int(attributes.get("reputation", 0) or 0)
    except Exception:
        reputation = 0

    return reputation < -50


async def _query_virustotal(app: FastAPI, ip: str) -> dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "skipped",
            "reason": "missing_api_key",
            "http_status": None,
            "is_malicious": False,
            "response": None,
        }

    if not ip or ip == "unknown" or is_local_ip(ip):
        return {
            "status": "skipped",
            "reason": "local_or_unknown_ip",
            "http_status": None,
            "is_malicious": False,
            "response": None,
        }

    try:
        response = await app.state.vt_http_client.get(
            f"/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
        )
    except httpx.TimeoutException:
        logger.warning("VirusTotal timeout for ip=%s", ip)
        return {
            "status": "timeout",
            "http_status": None,
            "is_malicious": False,
            "response": None,
        }
    except httpx.HTTPError as exc:
        logger.warning("VirusTotal request error for ip=%s error=%s", ip, exc)
        return {
            "status": "request_error",
            "http_status": None,
            "is_malicious": False,
            "response": {"error": str(exc)},
        }

    if response.status_code == 429:
        logger.warning("VirusTotal rate limit (429) for ip=%s", ip)
        return {
            "status": "rate_limited",
            "http_status": 429,
            "is_malicious": False,
            "response": None,
        }

    if response.status_code != 200:
        body_preview = response.text[:1024]
        logger.warning("VirusTotal non-200 status=%s for ip=%s", response.status_code, ip)
        return {
            "status": "error",
            "http_status": response.status_code,
            "is_malicious": False,
            "response": {"body_preview": body_preview},
        }

    payload = response.json()
    return {
        "status": "ok",
        "http_status": 200,
        "is_malicious": _is_vt_report_malicious(payload),
        "response": payload,
    }


async def _ban_ip(redis_client: redis.Redis | None, ip: str, reason: str) -> None:
    if not redis_client or not ip or ip == "unknown":
        return

    try:
        await redis_client.setex(f"{BAN_KEY_PREFIX}{ip}", BAN_TTL_SECONDS, reason)
    except Exception:
        logger.exception("Failed to ban ip=%s", ip)


async def _log_inspection(app: FastAPI, document: dict[str, Any]) -> None:
    collection = app.state.mongo_collection
    if collection is None:
        return

    try:
        await collection.insert_one(document)
    except Exception:
        logger.exception("Failed to write inspection document to MongoDB")


async def _process_job(app: FastAPI, worker_id: int, job: InspectionJob) -> None:
    processing_errors: list[str] = []

    pattern_malicious = False
    pattern_reason = ""
    try:
        pattern_malicious, pattern_reason = await analyze_forwarded_request(
            metadata=job.metadata,
            body_bytes=job.body,
            policy=DEFAULT_POLICY,
        )
    except Exception as exc:
        processing_errors.append(f"pattern_analysis_error:{exc}")
        logger.exception("Pattern analysis failed for ip=%s", job.client_ip)

    try:
        vt_result = await _query_virustotal(app, job.client_ip)
    except Exception as exc:
        vt_result = {
            "status": "internal_error",
            "http_status": None,
            "is_malicious": False,
            "response": {"error": str(exc)},
        }
        processing_errors.append(f"virustotal_error:{exc}")
        logger.exception("VirusTotal query failed for ip=%s", job.client_ip)
    vt_malicious = bool(vt_result.get("is_malicious", False))

    is_malicious = pattern_malicious or vt_malicious
    decision = "ban" if is_malicious else "allow"

    ban_reason = ""
    if pattern_malicious:
        ban_reason = pattern_reason or "PATTERN_MATCH"
    elif vt_malicious:
        ban_reason = "MALICIOUS_IP_VT"

    if decision == "ban":
        await _ban_ip(app.state.redis_client, job.client_ip, ban_reason)

    request_payload = {
        **job.metadata,
        "body": _serialize_request_body(job.body, str(job.metadata.get("content_type", ""))),
        "client_ip": job.client_ip,
    }

    document = {
        "timestamp": datetime.now(timezone.utc),
        "worker_id": worker_id,
        "queued_at": job.queued_at,
        "decision": decision,
        "ban_reason": ban_reason,
        "pattern_analysis": {
            "is_malicious": pattern_malicious,
            "reason": pattern_reason,
        },
        "virustotal": vt_result,
        "processing_errors": processing_errors,
        "request": request_payload,
    }

    await _log_inspection(app, document)


async def _inspection_worker(app: FastAPI, worker_id: int) -> None:
    queue: asyncio.Queue[InspectionJob] = app.state.inspection_queue

    while True:
        job = await queue.get()
        try:
            await _process_job(app, worker_id, job)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Inspection worker %s crashed while processing a job", worker_id)
        finally:
            queue.task_done()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis_client = None
    app.state.mongo_client = None
    app.state.mongo_collection = None
    app.state.vt_http_client = httpx.AsyncClient(
        base_url="https://www.virustotal.com/api/v3",
        timeout=httpx.Timeout(VT_TIMEOUT_SECONDS),
    )
    app.state.inspection_queue = asyncio.Queue(maxsize=INSPECTION_QUEUE_SIZE)
    app.state.worker_tasks = []

    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        app.state.redis_client = redis_client
        logger.info("Redis connected")
    except Exception:
        logger.exception("Redis initialization failed. Running fail-open.")

    try:
        mongo_client = AsyncMongoClient(MONGODB_URL)
        mongo_db = mongo_client[_resolve_mongo_db_name()]
        collection = mongo_db.inspections
        await collection.create_index("timestamp")
        await collection.create_index("request.client_ip")
        await collection.create_index("decision")

        app.state.mongo_client = mongo_client
        app.state.mongo_collection = collection
        logger.info("MongoDB async client initialized")
    except Exception:
        logger.exception("MongoDB initialization failed. Inspection logs disabled.")

    try:
        await get_analyzer()
        logger.info("Pattern analyzer warmed up")
    except Exception:
        logger.exception("Pattern analyzer warmup failed")

    workers = max(1, INSPECTION_WORKERS)
    for idx in range(workers):
        task = asyncio.create_task(_inspection_worker(app, idx), name=f"inspection-worker-{idx}")
        app.state.worker_tasks.append(task)

    logger.info(
        "WAF authorization engine started with queue_size=%s workers=%s",
        INSPECTION_QUEUE_SIZE,
        workers,
    )

    try:
        yield
    finally:
        try:
            await asyncio.wait_for(app.state.inspection_queue.join(), timeout=3)
        except Exception:
            logger.warning("Queue drain timed out during shutdown")

        for task in app.state.worker_tasks:
            task.cancel()
        await asyncio.gather(*app.state.worker_tasks, return_exceptions=True)

        await app.state.vt_http_client.aclose()

        redis_client = app.state.redis_client
        if redis_client is not None:
            try:
                await redis_client.aclose()
            except Exception:
                pass

        mongo_client = app.state.mongo_client
        if mongo_client is not None:
            mongo_client.close()


app = FastAPI(title="WAF Auth Engine", version="3.0.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    """Lightweight health check for container orchestration."""
    return {"status": "ok"}


@app.api_route("/inspect", methods=["GET", "POST"])
async def inspect(request: Request) -> Response:
    """Fail-open authorization endpoint called by Nginx auth_request."""

    client_ip = _extract_client_ip(request)

    try:
        body = await request.body()
        metadata = _extract_metadata(request)

        redis_client: redis.Redis | None = request.app.state.redis_client
        if redis_client is not None and client_ip and client_ip != "unknown":
            try:
                if await redis_client.exists(f"{BAN_KEY_PREFIX}{client_ip}"):
                    return Response(status_code=403)

                if await redis_client.exists(f"{CLEAN_KEY_PREFIX}{client_ip}"):
                    return Response(status_code=200)
            except Exception:
                logger.exception("Redis lookup failed for ip=%s. Falling open.", client_ip)

        job = InspectionJob(
            client_ip=client_ip,
            metadata=metadata,
            body=body,
            queued_at=datetime.now(timezone.utc),
        )

        try:
            request.app.state.inspection_queue.put_nowait(job)
        except asyncio.QueueFull:
            logger.warning(
                "Inspection queue full (size=%s). Dropping job for ip=%s uri=%s",
                INSPECTION_QUEUE_SIZE,
                client_ip,
                metadata.get("uri", ""),
            )

        return Response(status_code=200)
    except Exception:
        logger.exception("Unhandled error in /inspect. Falling open for ip=%s", client_ip)
        return Response(status_code=200)


if __name__ == "__main__":
    uvicorn.run("waf.app.server:app", host="0.0.0.0", port=8000, workers=1)
