from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Any

from fastapi import Request

from app.database import AsyncSessionLocal
from app.models import AuditLog
from app.schemas import UserInDB


logger = logging.getLogger(__name__)


def get_client_ip(request: Request | None) -> str | None:
    if not request:
        return None

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        first_ip = forwarded_for.split(",")[0].strip()
        if first_ip:
            return first_ip

    if request.client:
        return request.client.host
    return None


def _to_json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _to_json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_json_safe(item) for item in value]
    return value


async def write_audit_log(
    *,
    action: str,
    target_type: str,
    target_id: str | int | None,
    actor: UserInDB | None,
    request: Request | None,
    success: bool,
    before_json: dict[str, Any] | None = None,
    after_json: dict[str, Any] | None = None,
    error_message: str | None = None,
) -> None:
    try:
        async with AsyncSessionLocal() as session:
            log_entry = AuditLog(
                actor_user_id=actor.id if actor else None,
                actor_username=actor.username if actor else None,
                action=action,
                target_type=target_type,
                target_id=str(target_id) if target_id is not None else None,
                before_json=_to_json_safe(before_json),
                after_json=_to_json_safe(after_json),
                success=success,
                error_message=error_message,
                ip_address=get_client_ip(request),
            )
            session.add(log_entry)
            await session.commit()
    except Exception:
        logger.exception("Failed to persist audit log", extra={"action": action, "target_type": target_type})
