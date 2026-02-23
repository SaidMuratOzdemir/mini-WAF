from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_admin_user, get_current_super_admin_user
from app.database import get_session
from app.models import Site as SiteModel
from app.models import UpstreamPolicy as UpstreamPolicyModel
from app.schemas import UpstreamPolicyOut, UpstreamPolicyUpdate, UserInDB
from app.services.audit_logger import write_audit_log
from app.services.upstream_policy_service import get_effective_upstream_policy, policy_from_model
from app.utils.upstream_validation import UpstreamValidationError, validate_upstream_url


router = APIRouter(prefix="/policies", tags=["Policies"])


def _serialize_policy(model: UpstreamPolicyModel) -> dict[str, object]:
    return {
        "id": model.id,
        "allow_private_upstreams": model.allow_private_upstreams,
        "allowed_private_cidrs": model.allowed_private_cidrs,
        "denied_cidrs": model.denied_cidrs,
        "allowed_upstream_ports": model.allowed_upstream_ports,
        "denied_hostnames": model.denied_hostnames,
        "allowed_hostname_suffixes": model.allowed_hostname_suffixes,
        "updated_by_user_id": model.updated_by_user_id,
    }


@router.get("/upstream", response_model=UpstreamPolicyOut)
async def get_upstream_policy(
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_admin_user),
):
    result = await session.execute(select(UpstreamPolicyModel).order_by(UpstreamPolicyModel.id.asc()))
    policy_model = result.scalars().first()
    if not policy_model:
        policy_model = UpstreamPolicyModel()
        session.add(policy_model)
        await session.commit()
        await session.refresh(policy_model)
    return policy_model


@router.put("/upstream", response_model=UpstreamPolicyOut)
async def update_upstream_policy(
    payload: UpstreamPolicyUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    result = await session.execute(select(UpstreamPolicyModel).order_by(UpstreamPolicyModel.id.asc()))
    policy_model = result.scalars().first()

    if not policy_model:
        policy_model = UpstreamPolicyModel()
        session.add(policy_model)
        await session.flush()

    before = _serialize_policy(policy_model)

    try:
        data = payload.model_dump()
        for key, value in data.items():
            setattr(policy_model, key, value)
        policy_model.updated_by_user_id = current_user.id

        # Validate parsed policy eagerly to return a clean client error.
        policy_from_model(policy_model)

        await session.commit()
        await session.refresh(policy_model)
        await write_audit_log(
            action="policy.update",
            target_type="policy",
            target_id=policy_model.id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
            after_json=_serialize_policy(policy_model),
        )
        return policy_model
    except ValueError as exc:
        await session.rollback()
        await write_audit_log(
            action="policy.update",
            target_type="policy",
            target_id=policy_model.id if policy_model else None,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            after_json=payload.model_dump(),
            error_message=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="policy.update",
            target_type="policy",
            target_id=policy_model.id if policy_model else None,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            after_json=payload.model_dump(),
            error_message=str(exc),
        )
        raise


@router.post("/upstream/revalidate-sites", response_model=dict)
async def revalidate_active_sites(
    request: Request,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    policy = await get_effective_upstream_policy(session)
    result = await session.execute(
        select(SiteModel).where(SiteModel.is_active.is_(True)).order_by(SiteModel.id.asc())
    )
    active_sites = result.scalars().all()

    revalidated = 0
    disabled = 0
    failures: list[dict[str, object]] = []

    for site in active_sites:
        try:
            validation = await run_in_threadpool(validate_upstream_url, site.upstream_url, policy)
            site.resolved_upstream_ips = validation.resolved_ips
            site.last_resolved_at = datetime.utcnow()
            revalidated += 1
        except UpstreamValidationError as exc:
            site.is_active = False
            disabled += 1
            failures.append({"site_id": site.id, "host": site.host, "reason": str(exc)})
            await write_audit_log(
                action="site.disable_by_policy_revalidation",
                target_type="site",
                target_id=site.id,
                actor=current_user,
                request=request,
                success=True,
                before_json={"is_active": True, "upstream_url": site.upstream_url},
                after_json={"is_active": False},
                error_message=str(exc),
            )

    await session.commit()
    await write_audit_log(
        action="policy.revalidate_sites",
        target_type="policy",
        target_id=None,
        actor=current_user,
        request=request,
        success=True,
        after_json={"revalidated": revalidated, "disabled": disabled, "failures": failures},
    )
    return {"revalidated": revalidated, "disabled": disabled, "failures": failures}
