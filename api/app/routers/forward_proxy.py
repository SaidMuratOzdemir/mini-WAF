from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_super_admin_user, get_password_hash
from app.database import get_session
from app.models import OutboundDestinationRule, OutboundProxyProfile, OutboundProxyUser
from app.schemas import (
    ForwardProxyStatusOut,
    OutboundDestinationRuleCreate,
    OutboundDestinationRuleOut,
    OutboundDestinationRuleUpdate,
    OutboundProxyProfileCreate,
    OutboundProxyProfileOut,
    OutboundProxyProfileUpdate,
    OutboundProxyUserCreate,
    OutboundProxyUserOut,
    OutboundProxyUserUpdate,
    UserInDB,
)
from app.services.audit_logger import write_audit_log
from app.services.forward_proxy_config_manager import (
    ForwardProxyConfigApplyError,
    ForwardProxyConfigManager,
)


router = APIRouter(prefix="/forward-proxy", tags=["Forward Proxy"])
forward_proxy_config_manager = ForwardProxyConfigManager()


def _profile_state(profile: OutboundProxyProfile) -> dict[str, object]:
    return {
        "id": profile.id,
        "name": profile.name,
        "listen_port": profile.listen_port,
        "is_enabled": profile.is_enabled,
        "require_auth": profile.require_auth,
        "auth_realm": profile.auth_realm,
        "allow_connect_ports": profile.allow_connect_ports,
        "allowed_client_cidrs": profile.allowed_client_cidrs,
        "default_action": profile.default_action,
        "block_private_destinations": profile.block_private_destinations,
    }


def _rule_state(rule: OutboundDestinationRule) -> dict[str, object]:
    return {
        "id": rule.id,
        "profile_id": rule.profile_id,
        "action": rule.action,
        "rule_type": rule.rule_type,
        "value": rule.value,
        "priority": rule.priority,
        "is_enabled": rule.is_enabled,
    }


async def _get_enabled_profile_and_rules(
    session: AsyncSession,
) -> tuple[OutboundProxyProfile | None, list[OutboundDestinationRule], list[OutboundProxyUser]]:
    enabled_result = await session.execute(
        select(OutboundProxyProfile)
        .where(OutboundProxyProfile.is_enabled.is_(True))
        .order_by(OutboundProxyProfile.id)
    )
    enabled_profiles = enabled_result.scalars().all()
    if len(enabled_profiles) > 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only one enabled outbound proxy profile is supported in phase-9a.",
        )

    enabled_profile = enabled_profiles[0] if enabled_profiles else None
    if not enabled_profile:
        return None, [], []

    rules_result = await session.execute(
        select(OutboundDestinationRule)
        .where(OutboundDestinationRule.profile_id == enabled_profile.id)
        .where(OutboundDestinationRule.is_enabled.is_(True))
        .order_by(OutboundDestinationRule.priority.asc(), OutboundDestinationRule.id.asc())
    )
    rules = rules_result.scalars().all()

    # Fetch active auth users when auth is required
    auth_users: list[OutboundProxyUser] = []
    if enabled_profile.require_auth:
        users_result = await session.execute(
            select(OutboundProxyUser)
            .where(OutboundProxyUser.is_active.is_(True))
            .order_by(OutboundProxyUser.username.asc())
        )
        auth_users = list(users_result.scalars().all())

    return enabled_profile, rules, auth_users


async def _ensure_no_other_enabled_profile(session: AsyncSession, profile_id: int | None = None) -> None:
    query = select(OutboundProxyProfile.id).where(OutboundProxyProfile.is_enabled.is_(True))
    if profile_id is not None:
        query = query.where(OutboundProxyProfile.id != profile_id)
    existing_enabled = await session.execute(query.limit(1))
    if existing_enabled.first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another outbound proxy profile is already enabled.",
        )


async def _apply_forward_proxy_config(
    *,
    session: AsyncSession,
    request: Request,
    current_user: UserInDB,
) -> dict[str, object]:
    profile, rules, auth_users = await _get_enabled_profile_and_rules(session)

    # Guard: require_auth=true but no active users → reject apply
    if profile and profile.require_auth and not auth_users:
        active_count_result = await session.execute(
            select(sa_func.count(OutboundProxyUser.id)).where(OutboundProxyUser.is_active.is_(True))
        )
        active_count = active_count_result.scalar() or 0
        if active_count == 0:
            await write_audit_log(
                action="forward_proxy.apply",
                target_type="outbound_proxy_profile",
                target_id=profile.id,
                actor=current_user,
                request=request,
                success=False,
                error_message="require_auth is enabled but no active proxy users exist. Add at least one active user before applying.",
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="require_auth is enabled but no active proxy users exist. Create at least one active user before applying.",
            )

    try:
        result = await run_in_threadpool(
            forward_proxy_config_manager.apply_with_rollback,
            profile,
            rules,
            auth_users,
        )
        await write_audit_log(
            action="forward_proxy.apply",
            target_type="outbound_proxy_profile",
            target_id=profile.id if profile else None,
            actor=current_user,
            request=request,
            success=True,
            after_json={
                "active_profile_id": profile.id if profile else None,
                "active_profile_name": profile.name if profile else None,
                "active_rule_count": len(rules),
                "auth_user_count": len(auth_users),
                "result": result,
            },
        )
        return result
    except ForwardProxyConfigApplyError as exc:
        await write_audit_log(
            action="forward_proxy.apply",
            target_type="outbound_proxy_profile",
            target_id=profile.id if profile else None,
            actor=current_user,
            request=request,
            success=False,
            after_json={
                "active_profile_id": profile.id if profile else None,
                "active_profile_name": profile.name if profile else None,
                "active_rule_count": len(rules),
            },
            error_message=exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{exc.detail} (stage: {exc.diagnostics.get('stage', 'unknown')})",
        )


@router.get("/profiles", response_model=List[OutboundProxyProfileOut])
async def list_outbound_profiles(
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    result = await session.execute(select(OutboundProxyProfile).order_by(OutboundProxyProfile.id.asc()))
    return result.scalars().all()


@router.post("/profiles", response_model=OutboundProxyProfileOut, status_code=status.HTTP_201_CREATED)
async def create_outbound_profile(
    request: Request,
    payload: OutboundProxyProfileCreate,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    profile = OutboundProxyProfile(**payload.model_dump())

    if payload.is_enabled:
        await _ensure_no_other_enabled_profile(session)

    existing = await session.execute(
        select(OutboundProxyProfile.id).where(OutboundProxyProfile.name == payload.name).limit(1)
    )
    if existing.first():
        await write_audit_log(
            action="forward_proxy.profile.create",
            target_type="outbound_proxy_profile",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            after_json=payload.model_dump(),
            error_message=f"Outbound profile '{payload.name}' already exists.",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Outbound profile '{payload.name}' already exists.",
        )

    session.add(profile)
    try:
        await session.flush()
        if profile.is_enabled:
            await _apply_forward_proxy_config(session=session, request=request, current_user=current_user)
        await session.commit()
        await session.refresh(profile)
        await write_audit_log(
            action="forward_proxy.profile.create",
            target_type="outbound_proxy_profile",
            target_id=profile.id,
            actor=current_user,
            request=request,
            success=True,
            after_json=_profile_state(profile),
        )
        return profile
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.profile.create",
            target_type="outbound_proxy_profile",
            target_id=getattr(profile, "id", None),
            actor=current_user,
            request=request,
            success=False,
            after_json=payload.model_dump(),
            error_message=str(exc),
        )
        raise


@router.put("/profiles/{profile_id}", response_model=OutboundProxyProfileOut)
async def update_outbound_profile(
    request: Request,
    profile_id: int,
    payload: OutboundProxyProfileUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    profile = await session.get(OutboundProxyProfile, profile_id)
    if not profile:
        await write_audit_log(
            action="forward_proxy.profile.update",
            target_type="outbound_proxy_profile",
            target_id=profile_id,
            actor=current_user,
            request=request,
            success=False,
            error_message="Outbound proxy profile not found.",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Outbound proxy profile not found.")

    if payload.is_enabled:
        await _ensure_no_other_enabled_profile(session, profile_id=profile_id)

    before = _profile_state(profile)
    for key, value in payload.model_dump().items():
        setattr(profile, key, value)

    try:
        await session.flush()
        await _apply_forward_proxy_config(session=session, request=request, current_user=current_user)
        await session.commit()
        await session.refresh(profile)
        await write_audit_log(
            action="forward_proxy.profile.update",
            target_type="outbound_proxy_profile",
            target_id=profile.id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
            after_json=_profile_state(profile),
        )
        return profile
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.profile.update",
            target_type="outbound_proxy_profile",
            target_id=profile_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            after_json=payload.model_dump(),
            error_message=str(exc),
        )
        raise


@router.delete("/profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_outbound_profile(
    request: Request,
    profile_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    profile = await session.get(OutboundProxyProfile, profile_id)
    if not profile:
        await write_audit_log(
            action="forward_proxy.profile.delete",
            target_type="outbound_proxy_profile",
            target_id=profile_id,
            actor=current_user,
            request=request,
            success=False,
            error_message="Outbound proxy profile not found.",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Outbound proxy profile not found.")

    before = _profile_state(profile)

    try:
        await session.delete(profile)
        await session.flush()
        await _apply_forward_proxy_config(session=session, request=request, current_user=current_user)
        await session.commit()
        await write_audit_log(
            action="forward_proxy.profile.delete",
            target_type="outbound_proxy_profile",
            target_id=profile_id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
        )
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.profile.delete",
            target_type="outbound_proxy_profile",
            target_id=profile_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            error_message=str(exc),
        )
        raise


@router.get("/profiles/{profile_id}/rules", response_model=List[OutboundDestinationRuleOut])
async def list_outbound_rules(
    profile_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    profile = await session.get(OutboundProxyProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Outbound proxy profile not found.")

    result = await session.execute(
        select(OutboundDestinationRule)
        .where(OutboundDestinationRule.profile_id == profile_id)
        .order_by(OutboundDestinationRule.priority.asc(), OutboundDestinationRule.id.asc())
    )
    return result.scalars().all()


@router.post("/profiles/{profile_id}/rules", response_model=OutboundDestinationRuleOut, status_code=status.HTTP_201_CREATED)
async def create_outbound_rule(
    request: Request,
    profile_id: int,
    payload: OutboundDestinationRuleCreate,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    profile = await session.get(OutboundProxyProfile, profile_id)
    if not profile:
        await write_audit_log(
            action="forward_proxy.rule.create",
            target_type="outbound_destination_rule",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            after_json=payload.model_dump(),
            error_message="Outbound proxy profile not found.",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Outbound proxy profile not found.")

    rule = OutboundDestinationRule(profile_id=profile_id, **payload.model_dump())
    session.add(rule)
    try:
        await session.flush()
        if profile.is_enabled:
            await _apply_forward_proxy_config(session=session, request=request, current_user=current_user)
        await session.commit()
        await session.refresh(rule)
        await write_audit_log(
            action="forward_proxy.rule.create",
            target_type="outbound_destination_rule",
            target_id=rule.id,
            actor=current_user,
            request=request,
            success=True,
            after_json=_rule_state(rule),
        )
        return rule
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.rule.create",
            target_type="outbound_destination_rule",
            target_id=getattr(rule, "id", None),
            actor=current_user,
            request=request,
            success=False,
            after_json=payload.model_dump(),
            error_message=str(exc),
        )
        raise


@router.put("/rules/{rule_id}", response_model=OutboundDestinationRuleOut)
async def update_outbound_rule(
    request: Request,
    rule_id: int,
    payload: OutboundDestinationRuleUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    rule = await session.get(OutboundDestinationRule, rule_id)
    if not rule:
        await write_audit_log(
            action="forward_proxy.rule.update",
            target_type="outbound_destination_rule",
            target_id=rule_id,
            actor=current_user,
            request=request,
            success=False,
            error_message="Outbound destination rule not found.",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Outbound destination rule not found.")

    profile = await session.get(OutboundProxyProfile, rule.profile_id)
    before = _rule_state(rule)
    for key, value in payload.model_dump().items():
        setattr(rule, key, value)

    try:
        await session.flush()
        if profile and profile.is_enabled:
            await _apply_forward_proxy_config(session=session, request=request, current_user=current_user)
        await session.commit()
        await session.refresh(rule)
        await write_audit_log(
            action="forward_proxy.rule.update",
            target_type="outbound_destination_rule",
            target_id=rule.id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
            after_json=_rule_state(rule),
        )
        return rule
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.rule.update",
            target_type="outbound_destination_rule",
            target_id=rule_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            after_json=payload.model_dump(),
            error_message=str(exc),
        )
        raise


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_outbound_rule(
    request: Request,
    rule_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    rule = await session.get(OutboundDestinationRule, rule_id)
    if not rule:
        await write_audit_log(
            action="forward_proxy.rule.delete",
            target_type="outbound_destination_rule",
            target_id=rule_id,
            actor=current_user,
            request=request,
            success=False,
            error_message="Outbound destination rule not found.",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Outbound destination rule not found.")

    profile = await session.get(OutboundProxyProfile, rule.profile_id)
    before = _rule_state(rule)
    try:
        await session.delete(rule)
        await session.flush()
        if profile and profile.is_enabled:
            await _apply_forward_proxy_config(session=session, request=request, current_user=current_user)
        await session.commit()
        await write_audit_log(
            action="forward_proxy.rule.delete",
            target_type="outbound_destination_rule",
            target_id=rule_id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
        )
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.rule.delete",
            target_type="outbound_destination_rule",
            target_id=rule_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            error_message=str(exc),
        )
        raise


@router.post("/apply", status_code=status.HTTP_200_OK)
async def apply_forward_proxy_config(
    request: Request,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    result = await _apply_forward_proxy_config(session=session, request=request, current_user=current_user)
    return result


@router.get("/status", response_model=ForwardProxyStatusOut)
async def get_forward_proxy_status(
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    profile, rules, auth_users = await _get_enabled_profile_and_rules(session)
    validate_result = await run_in_threadpool(forward_proxy_config_manager.validate_proxy_config)
    return ForwardProxyStatusOut(
        active_profile_id=profile.id if profile else None,
        active_profile_name=profile.name if profile else None,
        active_rule_count=len(rules),
        require_auth=profile.require_auth if profile else False,
        active_auth_user_count=len(auth_users),
        config_path=str(forward_proxy_config_manager.generated_config_path),
        validation=validate_result.as_dict(),
    )


# ── Phase 9A.2-A: Forward Proxy User CRUD ───────────────────────────


def _user_safe_state(user: OutboundProxyUser) -> dict[str, object]:
    """Return user state without password_hash for audit logging."""
    return {
        "id": user.id,
        "username": user.username,
        "is_active": user.is_active,
    }


@router.get("/users", response_model=List[OutboundProxyUserOut])
async def list_outbound_proxy_users(
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    result = await session.execute(
        select(OutboundProxyUser).order_by(OutboundProxyUser.username.asc())
    )
    return result.scalars().all()


@router.post("/users", response_model=OutboundProxyUserOut, status_code=status.HTTP_201_CREATED)
async def create_outbound_proxy_user(
    request: Request,
    payload: OutboundProxyUserCreate,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    # Check for duplicate username
    existing = await session.execute(
        select(OutboundProxyUser.id).where(OutboundProxyUser.username == payload.username).limit(1)
    )
    if existing.first():
        await write_audit_log(
            action="forward_proxy.user.create",
            target_type="outbound_proxy_user",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            after_json={"username": payload.username},
            error_message=f"Proxy user '{payload.username}' already exists.",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proxy user '{payload.username}' already exists.",
        )

    proxy_user = OutboundProxyUser(
        username=payload.username,
        password_hash=get_password_hash(payload.password),
        is_active=True,
    )
    session.add(proxy_user)
    try:
        await session.flush()
        await session.commit()
        await session.refresh(proxy_user)
        await write_audit_log(
            action="forward_proxy.user.create",
            target_type="outbound_proxy_user",
            target_id=proxy_user.id,
            actor=current_user,
            request=request,
            success=True,
            after_json=_user_safe_state(proxy_user),
        )
        return proxy_user
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.user.create",
            target_type="outbound_proxy_user",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            after_json={"username": payload.username},
            error_message=str(exc),
        )
        raise


@router.put("/users/{user_id}", response_model=OutboundProxyUserOut)
async def update_outbound_proxy_user(
    request: Request,
    user_id: int,
    payload: OutboundProxyUserUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    proxy_user = await session.get(OutboundProxyUser, user_id)
    if not proxy_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proxy user not found.")

    before = _user_safe_state(proxy_user)

    if payload.password is not None:
        proxy_user.password_hash = get_password_hash(payload.password)
    if payload.is_active is not None:
        proxy_user.is_active = payload.is_active

    try:
        await session.flush()
        await session.commit()
        await session.refresh(proxy_user)
        await write_audit_log(
            action="forward_proxy.user.update",
            target_type="outbound_proxy_user",
            target_id=proxy_user.id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
            after_json=_user_safe_state(proxy_user),
        )
        return proxy_user
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.user.update",
            target_type="outbound_proxy_user",
            target_id=user_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            error_message=str(exc),
        )
        raise


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_outbound_proxy_user(
    request: Request,
    user_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    proxy_user = await session.get(OutboundProxyUser, user_id)
    if not proxy_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proxy user not found.")

    before = _user_safe_state(proxy_user)
    try:
        await session.delete(proxy_user)
        await session.commit()
        await write_audit_log(
            action="forward_proxy.user.delete",
            target_type="outbound_proxy_user",
            target_id=user_id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
        )
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="forward_proxy.user.delete",
            target_type="outbound_proxy_user",
            target_id=user_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            error_message=str(exc),
        )
        raise
