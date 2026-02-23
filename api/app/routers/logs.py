# api/app/routers/logs.py

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient
import os
from datetime import datetime, timedelta
from bson import ObjectId

from app.core.security import get_current_admin_user
from app.schemas import UserInDB

router = APIRouter(prefix="/logs", tags=["logs"])

# MongoDB connection
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017/waf_logs")

_motor_client: AsyncIOMotorClient | None = None


async def get_mongodb():
    """Async dependency that returns a motor database handle."""
    global _motor_client
    try:
        if _motor_client is None:
            _motor_client = AsyncIOMotorClient(MONGODB_URL)
        db = _motor_client.waf_logs
        return db
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MongoDB connection failed: {e}")


def safe_isoformat(timestamp):
    """Safely convert timestamp to ISO format with +3 hours timezone adjustment."""
    if isinstance(timestamp, datetime):
        adjusted_timestamp = timestamp + timedelta(hours=3)
        return adjusted_timestamp.isoformat()
    elif isinstance(timestamp, (int, float)):
        try:
            if isinstance(timestamp, float):
                if timestamp != timestamp:  # NaN check
                    return "1970-01-01T03:00:00"
                if timestamp == float('inf') or timestamp == float('-inf'):
                    return "1970-01-01T03:00:00"
                if timestamp > 1e12:
                    timestamp = timestamp / 1000
                elif timestamp < 0:
                    return "1970-01-01T03:00:00"

            dt = datetime.fromtimestamp(timestamp)
            adjusted_dt = dt + timedelta(hours=3)
            return adjusted_dt.isoformat()
        except (ValueError, OSError, OverflowError):
            return "1970-01-01T03:00:00"
    else:
        return str(timestamp)


@router.get("/requests")
async def get_recent_requests(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, le=1000),
    site_name: Optional[str] = None,
    client_ip: Optional[str] = None,
    method: Optional[str] = None,
    status_code: Optional[int] = None,
    blocked_only: bool = False,
    db=Depends(get_mongodb),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get recent inspection logs with optional filtering - ADMIN ONLY"""
    try:
        filter_query = {}

        if site_name:
            filter_query["request.host"] = site_name
        if client_ip:
            filter_query["request.client_ip"] = client_ip
        if method:
            filter_query["request.method"] = method.upper()
        if blocked_only:
            filter_query["decision"] = "ban"

        skip = (page - 1) * limit

        total_count = await db.inspections.count_documents(filter_query)

        cursor = db.inspections.find(filter_query).sort("timestamp", -1).skip(skip).limit(limit)
        inspections = await cursor.to_list(length=limit)

        logs = []
        for doc in inspections:
            req = doc.get("request", {})
            is_blocked = doc.get("decision") == "ban"
            headers = req.get("headers", {})
            body_info = req.get("body", {})

            # Build a human-readable request string
            header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
            request_str = f"{req.get('method', '')} {req.get('path', '')} HTTP/1.1\nHost: {req.get('host', '')}\n{header_lines}"

            log_entry = {
                "id": str(doc.get("_id", "")),
                "ip": req.get("client_ip", ""),
                "method": req.get("method", ""),
                "status": 403 if is_blocked else 200,
                "url": req.get("path", ""),
                "host": req.get("host", ""),
                "timestamp": safe_isoformat(doc.get("timestamp")),
                "request": request_str,
                "response": f"HTTP/1.1 {'403 Forbidden' if is_blocked else '200 OK'}",
                "site_name": req.get("host", ""),
                "is_blocked": is_blocked,
                "block_reason": doc.get("ban_reason", ""),
            }
            logs.append(log_entry)

        return {
            "logs": logs,
            "total": total_count,
            "page": page,
            "hasMore": skip + limit < total_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get requests: {e}")


@router.get("/requests/{request_id}")
async def get_request_details(
    request_id: str,
    db=Depends(get_mongodb),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get detailed inspection information - ADMIN ONLY"""
    try:
        doc = await db.inspections.find_one({"_id": ObjectId(request_id)})

        if not doc:
            raise HTTPException(status_code=404, detail="Request not found")

        doc["_id"] = str(doc["_id"])
        if "timestamp" in doc:
            doc["timestamp"] = safe_isoformat(doc["timestamp"])
        if "queued_at" in doc:
            doc["queued_at"] = safe_isoformat(doc["queued_at"])

        req = doc.get("request", {})
        if isinstance(req.get("received_at"), datetime):
            req["received_at"] = safe_isoformat(req["received_at"])

        return {
            "request": req,
            "response": {
                "decision": doc.get("decision", ""),
                "ban_reason": doc.get("ban_reason", ""),
            },
            "pattern_analysis": doc.get("pattern_analysis"),
            "virustotal": doc.get("virustotal"),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get request details: {e}")


@router.get("/statistics")
async def get_log_statistics(
    hours: int = Query(default=24, le=168),
    db=Depends(get_mongodb),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get logging statistics - ADMIN ONLY"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        pipeline = [
            {
                "$match": {
                    "timestamp": {"$gte": start_time, "$lte": end_time}
                }
            },
            {
                "$group": {
                    "_id": {
                        "host": "$request.host",
                        "decision": "$decision"
                    },
                    "count": {"$sum": 1},
                    "unique_ips": {"$addToSet": "$request.client_ip"}
                }
            },
            {
                "$group": {
                    "_id": "$_id.host",
                    "total_requests": {
                        "$sum": "$count"
                    },
                    "blocked_requests": {
                        "$sum": {
                            "$cond": [{"$eq": ["$_id.decision", "ban"]}, "$count", 0]
                        }
                    },
                    "unique_ips": {
                        "$addToSet": "$unique_ips"
                    }
                }
            }
        ]

        cursor = db.inspections.aggregate(pipeline)
        stats = await cursor.to_list(length=1000)

        for stat in stats:
            all_ips = []
            for ip_list in stat["unique_ips"]:
                all_ips.extend(ip_list)
            stat["unique_ips"] = list(set(all_ips))
            stat["unique_ip_count"] = len(stat["unique_ips"])
            del stat["unique_ips"]

        return {
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "hours": hours
            },
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {e}")


@router.get("/blocked")
async def get_blocked_requests(
    limit: int = Query(default=50, le=500),
    site_name: Optional[str] = None,
    db=Depends(get_mongodb),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get blocked requests with reasons - ADMIN ONLY"""
    try:
        filter_query = {"decision": "ban"}
        if site_name:
            filter_query["request.host"] = site_name

        cursor = db.inspections.find(filter_query).sort("timestamp", -1).limit(limit)
        blocked = await cursor.to_list(length=limit)

        for doc in blocked:
            doc["_id"] = str(doc["_id"])
            doc["timestamp"] = safe_isoformat(doc.get("timestamp"))

        return {
            "blocked_requests": blocked,
            "total": len(blocked)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get blocked requests: {e}")


@router.delete("/requests/{request_id}")
async def delete_request(
    request_id: str,
    db=Depends(get_mongodb),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Delete a specific inspection log - ADMIN ONLY"""
    try:
        result = await db.inspections.delete_one({"_id": ObjectId(request_id)})

        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Request not found")

        return {
            "message": "Inspection log deleted successfully",
            "deleted": result.deleted_count > 0
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete request: {e}")