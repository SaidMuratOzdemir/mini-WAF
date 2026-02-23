from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_super_admin_user
from app.database import get_session
from app.models import AuditLog as AuditLogModel
from app.schemas import AuditLogOut, UserInDB


router = APIRouter(prefix="/audits", tags=["Audit"])


@router.get("", response_model=list[AuditLogOut])
async def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    result = await session.execute(
        select(AuditLogModel)
        .order_by(AuditLogModel.created_at.desc(), AuditLogModel.id.desc())
        .limit(limit)
    )
    return result.scalars().all()
