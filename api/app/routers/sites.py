# api/app/routers/sites.py
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import httpx
import logging

logger = logging.getLogger(__name__)

from app.database import get_session
from app.models import Site as SiteModel, Certificate as CertificateModel
from app.schemas import SiteCreate, Site as SiteSchema, UserInDB
from app.core.security import get_current_admin_user
from app.services.nginx_config_manager import NginxConfigManager, NginxConfigApplyError
from app.utils.upstream_validation import (
    UpstreamValidationError,
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


async def sync_site_proxy_config_hook(
    site: SiteModel,
    operation: str,
    certificate: CertificateModel | None = None,
) -> None:
    """
    Sync rendered site configs to generated Nginx snippets directory.
    """
    try:
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
        site: SiteCreate,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Add a new protected site."""
    try:
        validated_host = validate_server_name(site.host)
        upstream_result = await run_in_threadpool(validate_upstream_url, site.upstream_url)
        validated_sni_override = _normalize_tls_sni_override(site.upstream_tls_server_name_override)
    except UpstreamValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    tls_certificate = await resolve_site_tls_certificate(session, site)

    existing = await session.execute(
        select(SiteModel).filter_by(host=validated_host)
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with host '{validated_host}' already exists."
        )

    site_data = site.model_dump()
    site_data["host"] = validated_host
    site_data["upstream_url"] = upstream_result.normalized_url
    site_data["upstream_tls_server_name_override"] = validated_sni_override
    new_site = SiteModel(**site_data)
    session.add(new_site)
    try:
        await session.flush()
        await session.refresh(new_site)
        await sync_site_proxy_config_hook(new_site, "create", tls_certificate)
        await session.commit()
    except Exception:
        await session.rollback()
        raise

    await session.refresh(new_site)

    return new_site


@router.put("/{site_id}", response_model=SiteSchema)
async def update_site(
        site_id: int,
        site_update: SiteCreate,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Update an existing protected site."""
    try:
        validated_host = validate_server_name(site_update.host)
        upstream_result = await run_in_threadpool(validate_upstream_url, site_update.upstream_url)
        validated_sni_override = _normalize_tls_sni_override(site_update.upstream_tls_server_name_override)
    except UpstreamValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    tls_certificate = await resolve_site_tls_certificate(session, site_update)

    db_site = await session.get(SiteModel, site_id)
    if not db_site:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Site with ID {site_id} not found.")

    if db_site.host != validated_host:
        conflict = await session.execute(
            select(SiteModel).filter_by(host=validated_host)
        )
        if conflict.scalars().first():
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Site with host '{validated_host}' already exists."
            )

    update_data = site_update.model_dump()
    update_data["host"] = validated_host
    update_data["upstream_url"] = upstream_result.normalized_url
    update_data["upstream_tls_server_name_override"] = validated_sni_override
    for key, value in update_data.items():
        setattr(db_site, key, value)

    try:
        await session.flush()
        await sync_site_proxy_config_hook(db_site, "update", tls_certificate)
        await session.commit()
    except Exception:
        await session.rollback()
        raise

    await session.refresh(db_site)

    return db_site


@router.delete("/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
        site_id: int,
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Delete a protected site."""
    db_site = await session.get(SiteModel, site_id)
    if not db_site:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Site with ID {site_id} not found.")

    deleted_site = db_site
    try:
        await session.delete(db_site)
        await session.flush()
        await sync_site_proxy_config_hook(deleted_site, "delete")
        await session.commit()
    except Exception:
        await session.rollback()
        raise
