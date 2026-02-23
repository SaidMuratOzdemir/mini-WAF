# api/app/routers/sites.py
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import httpx
import logging

logger = logging.getLogger(__name__)

from app.database import get_session
from app.models import Site as SiteModel, Certificate as CertificateModel
from app.schemas import SiteCreate, Site as SiteSchema, UserInDB
from app.core.security import ROLE_SUPER_ADMIN, get_current_admin_user
from app.services.audit_logger import write_audit_log
from app.services.nginx_config_manager import NginxConfigManager, NginxConfigApplyError
from app.services.upstream_policy_service import (
    UpstreamPolicySnapshot,
    get_effective_upstream_policy,
)
from app.utils.upstream_validation import (
    UpstreamValidationError,
    UpstreamValidationResult,
    validate_server_name,
    validate_upstream_url,
)

router = APIRouter(prefix="/sites", tags=["Sites"])
nginx_config_manager = NginxConfigManager()


def _normalize_tls_sni_override(override: str | None) -> str | None:
    if not override:
        return None
    normalized = validate_server_name(override)
    if normalized.startswith("[") and normalized.endswith("]"):
        return normalized[1:-1]
    return normalized


async def get_default_certificate(session: AsyncSession) -> CertificateModel | None:
    result = await session.execute(
        select(CertificateModel)
        .where(CertificateModel.is_default.is_(True))
        .order_by(CertificateModel.id.desc())
    )
    return result.scalars().first()


async def resolve_site_tls_certificate(
    session: AsyncSession,
    site_payload: SiteCreate | SiteModel,
) -> CertificateModel | None:
    if not getattr(site_payload, "tls_enabled", False):
        return None

    certificate_id = getattr(site_payload, "tls_certificate_id", None)
    if certificate_id:
        certificate = await session.get(CertificateModel, certificate_id)
        if not certificate:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="TLS enabled site requires a valid certificate selection.",
            )
        return certificate

    default_certificate = await get_default_certificate(session)
    if not default_certificate:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="TLS enabled site requires a certificate; no default certificate is configured.",
        )
    return default_certificate


def _site_state(site: SiteModel) -> dict[str, object]:
    return {
        "id": site.id,
        "host": site.host,
        "name": site.name,
        "upstream_url": site.upstream_url,
        "is_active": site.is_active,
        "preserve_host_header": site.preserve_host_header,
        "enable_sni": site.enable_sni,
        "websocket_enabled": site.websocket_enabled,
        "body_inspection_profile": site.body_inspection_profile,
        "tls_enabled": site.tls_enabled,
        "http_redirect_to_https": site.http_redirect_to_https,
        "tls_certificate_id": site.tls_certificate_id,
        "upstream_tls_verify": site.upstream_tls_verify,
        "upstream_tls_server_name_override": site.upstream_tls_server_name_override,
        "hsts_enabled": site.hsts_enabled,
        "xss_enabled": site.xss_enabled,
        "sql_enabled": site.sql_enabled,
        "vt_enabled": site.vt_enabled,
        "resolved_upstream_ips": site.resolved_upstream_ips,
        "last_resolved_at": site.last_resolved_at.isoformat() if site.last_resolved_at else None,
    }


def _validation_policy_for_user(
    policy: UpstreamPolicySnapshot,
    current_user: UserInDB,
) -> UpstreamPolicySnapshot:
    # Always allow private evaluation at validation layer, then enforce role gate separately.
    # This ensures admin users receive explicit RBAC denial instead of generic private-IP validation errors.
    return policy.with_private_access(True)


def _assert_private_upstream_permission(
    result: UpstreamValidationResult,
    current_user: UserInDB,
) -> None:
    if result.is_private_target and current_user.role != ROLE_SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Private/LAN upstream tanımı yalnızca super_admin rolü tarafından yapılabilir.",
        )


async def _validate_upstream_for_site(
    site_payload: SiteCreate | SiteModel,
    current_user: UserInDB,
    session: AsyncSession,
) -> tuple[UpstreamValidationResult, UpstreamPolicySnapshot]:
    try:
        base_policy = await get_effective_upstream_policy(session)
    except ValueError as exc:
        raise UpstreamValidationError(f"Upstream policy misconfigured: {exc}") from exc
    effective_policy = _validation_policy_for_user(base_policy, current_user)

    upstream_result = await run_in_threadpool(
        validate_upstream_url,
        site_payload.upstream_url,
        effective_policy,
    )
    _assert_private_upstream_permission(upstream_result, current_user)
    return upstream_result, effective_policy


async def sync_site_proxy_config_hook(
    site: SiteModel,
    operation: str,
    current_user: UserInDB,
    request: Request,
    session: AsyncSession,
    policy: UpstreamPolicySnapshot | None = None,
    certificate: CertificateModel | None = None,
) -> None:
    """
    Sync rendered site configs to generated Nginx snippets directory.
    """
    try:
        if operation in {"create", "update"}:
            validation_policy = policy or await get_effective_upstream_policy(session)
            revalidated = await run_in_threadpool(validate_upstream_url, site.upstream_url, validation_policy)
            _assert_private_upstream_permission(revalidated, current_user)
            site.resolved_upstream_ips = revalidated.resolved_ips
            site.last_resolved_at = datetime.utcnow()

        result = await run_in_threadpool(
            nginx_config_manager.apply_with_rollback,
            site,
            operation,
            certificate,
        )
        logger.info("Synced Nginx config for site change", extra={
            "site_id": getattr(site, "id", None),
            "host": getattr(site, "host", None),
            "operation": operation,
            "certificate_id": getattr(certificate, "id", None) if certificate else None,
            "sync_result": result,
        })
    except NginxConfigApplyError as exc:
        logger.error(
            "Failed to apply Nginx config pipeline for site",
            extra={
                "site_id": getattr(site, "id", None),
                "host": getattr(site, "host", None),
                "operation": operation,
                "diagnostics": exc.diagnostics,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{exc.detail} (stage: {exc.diagnostics.get('stage', 'unknown')})",
        )
    except UpstreamValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


async def check_external_site_health(host: str) -> str:
    """Check if a site is healthy by making HTTP request through Nginx edge."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            url = "http://nginx:80/"
            headers = {"Host": host}
            response = await client.get(url, headers=headers)
            if 200 <= response.status_code < 400:
                return 'healthy'
            else:
                return 'unhealthy'
    except Exception:
        return 'unhealthy'


async def check_site_health(site) -> str:
    """Check if a site is healthy by making HTTP request to the host."""
    try:
        result = await check_external_site_health(site.host)
        return result
    except Exception:
        return 'unhealthy'


@router.get("", response_model=List[SiteSchema])
async def list_sites(
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """List all protected sites with health status."""
    result = await session.execute(select(SiteModel).order_by(SiteModel.id))
    sites = result.scalars().all()

    health_tasks = []
    for site in sites:
        task = check_site_health(site)
        health_tasks.append((site, task))

    for site, task in health_tasks:
        site.health_status = await task

    return sites


@router.post("", response_model=SiteSchema, status_code=status.HTTP_201_CREATED)
async def create_site(
        request: Request,
        site: SiteCreate,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Add a new protected site."""
    upstream_result = None
    effective_policy = None
    try:
        validated_host = validate_server_name(site.host)
        upstream_result, effective_policy = await _validate_upstream_for_site(site, current_user, session)
        validated_sni_override = _normalize_tls_sni_override(site.upstream_tls_server_name_override)
    except HTTPException as exc:
        await write_audit_log(
            action="site.create",
            target_type="site",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            after_json=site.model_dump(),
            error_message=str(exc.detail),
        )
        raise
    except UpstreamValidationError as exc:
        await write_audit_log(
            action="site.create",
            target_type="site",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            after_json=site.model_dump(),
            error_message=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    tls_certificate = await resolve_site_tls_certificate(session, site)

    existing = await session.execute(
        select(SiteModel).filter_by(host=validated_host)
    )
    if existing.scalars().first():
        await write_audit_log(
            action="site.create",
            target_type="site",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            after_json=site.model_dump(),
            error_message=f"Site with host '{validated_host}' already exists.",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with host '{validated_host}' already exists."
        )

    site_data = site.model_dump()
    site_data["host"] = validated_host
    site_data["upstream_url"] = upstream_result.normalized_url
    site_data["upstream_tls_server_name_override"] = validated_sni_override
    site_data["resolved_upstream_ips"] = upstream_result.resolved_ips
    site_data["last_resolved_at"] = datetime.utcnow()
    new_site = SiteModel(**site_data)
    session.add(new_site)
    try:
        await session.flush()
        await session.refresh(new_site)
        await sync_site_proxy_config_hook(
            new_site,
            "create",
            current_user=current_user,
            request=request,
            session=session,
            policy=effective_policy,
            certificate=tls_certificate,
        )
        await session.commit()
        await write_audit_log(
            action="site.create",
            target_type="site",
            target_id=new_site.id,
            actor=current_user,
            request=request,
            success=True,
            after_json=_site_state(new_site),
        )
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="site.create",
            target_type="site",
            target_id=getattr(new_site, "id", None),
            actor=current_user,
            request=request,
            success=False,
            after_json=site_data,
            error_message=str(exc),
        )
        raise

    await session.refresh(new_site)

    return new_site


@router.put("/{site_id}", response_model=SiteSchema)
async def update_site(
        request: Request,
        site_id: int,
        site_update: SiteCreate,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Update an existing protected site."""
    upstream_result = None
    effective_policy = None
    try:
        validated_host = validate_server_name(site_update.host)
        upstream_result, effective_policy = await _validate_upstream_for_site(site_update, current_user, session)
        validated_sni_override = _normalize_tls_sni_override(site_update.upstream_tls_server_name_override)
    except HTTPException as exc:
        await write_audit_log(
            action="site.update",
            target_type="site",
            target_id=site_id,
            actor=current_user,
            request=request,
            success=False,
            after_json=site_update.model_dump(),
            error_message=str(exc.detail),
        )
        raise
    except UpstreamValidationError as exc:
        await write_audit_log(
            action="site.update",
            target_type="site",
            target_id=site_id,
            actor=current_user,
            request=request,
            success=False,
            after_json=site_update.model_dump(),
            error_message=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    tls_certificate = await resolve_site_tls_certificate(session, site_update)

    db_site = await session.get(SiteModel, site_id)
    if not db_site:
        await write_audit_log(
            action="site.update",
            target_type="site",
            target_id=site_id,
            actor=current_user,
            request=request,
            success=False,
            error_message=f"Site with ID {site_id} not found.",
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Site with ID {site_id} not found.")

    before = _site_state(db_site)
    if db_site.host != validated_host:
        conflict = await session.execute(
            select(SiteModel).filter_by(host=validated_host)
        )
        if conflict.scalars().first():
            await write_audit_log(
                action="site.update",
                target_type="site",
                target_id=site_id,
                actor=current_user,
                request=request,
                success=False,
                before_json=before,
                after_json=site_update.model_dump(),
                error_message=f"Site with host '{validated_host}' already exists.",
            )
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Site with host '{validated_host}' already exists."
            )

    update_data = site_update.model_dump()
    update_data["host"] = validated_host
    update_data["upstream_url"] = upstream_result.normalized_url
    update_data["upstream_tls_server_name_override"] = validated_sni_override
    update_data["resolved_upstream_ips"] = upstream_result.resolved_ips
    update_data["last_resolved_at"] = datetime.utcnow()
    for key, value in update_data.items():
        setattr(db_site, key, value)

    try:
        await session.flush()
        await sync_site_proxy_config_hook(
            db_site,
            "update",
            current_user=current_user,
            request=request,
            session=session,
            policy=effective_policy,
            certificate=tls_certificate,
        )
        await session.commit()
        await write_audit_log(
            action="site.update",
            target_type="site",
            target_id=db_site.id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
            after_json=_site_state(db_site),
        )
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="site.update",
            target_type="site",
            target_id=site_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            after_json=update_data,
            error_message=str(exc),
        )
        raise

    await session.refresh(db_site)

    return db_site


@router.delete("/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
        request: Request,
        site_id: int,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Delete a protected site."""
    db_site = await session.get(SiteModel, site_id)
    if not db_site:
        await write_audit_log(
            action="site.delete",
            target_type="site",
            target_id=site_id,
            actor=current_user,
            request=request,
            success=False,
            error_message=f"Site with ID {site_id} not found.",
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Site with ID {site_id} not found.")

    deleted_site = db_site
    before = _site_state(db_site)
    try:
        await session.delete(db_site)
        await session.flush()
        await sync_site_proxy_config_hook(
            deleted_site,
            "delete",
            current_user=current_user,
            request=request,
            session=session,
        )
        await session.commit()
        await write_audit_log(
            action="site.delete",
            target_type="site",
            target_id=site_id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
        )
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="site.delete",
            target_type="site",
            target_id=site_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            error_message=str(exc),
        )
        raise
