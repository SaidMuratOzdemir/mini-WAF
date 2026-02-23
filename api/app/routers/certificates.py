from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_super_admin_user
from app.database import get_session
from app.models import Certificate as CertificateModel
from app.models import Site as SiteModel
from app.schemas import CertificateOut, UserInDB
from app.services.audit_logger import write_audit_log
from app.services.certificate_storage import CertificateStorageError, CertificateStorageService
from app.services.nginx_config_manager import NginxConfigApplyError, NginxConfigManager
from app.services.upstream_policy_service import get_effective_upstream_policy
from app.utils.upstream_validation import UpstreamValidationError, validate_upstream_url


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/certificates", tags=["Certificates"])

certificate_storage = CertificateStorageService()
nginx_config_manager = NginxConfigManager()


def _to_certificate_out(certificate: CertificateModel) -> CertificateOut:
    return CertificateOut(
        id=certificate.id,
        name=certificate.name,
        is_default=certificate.is_default,
        has_chain=bool(certificate.chain_pem_path),
        created_at=certificate.created_at,
        updated_at=certificate.updated_at,
    )


def _certificate_state(certificate: CertificateModel) -> dict[str, object]:
    return {
        "id": certificate.id,
        "name": certificate.name,
        "cert_pem_path": certificate.cert_pem_path,
        "key_pem_path": certificate.key_pem_path,
        "chain_pem_path": certificate.chain_pem_path,
        "is_default": certificate.is_default,
    }


async def _sync_default_tls_sites(session: AsyncSession, certificate: CertificateModel) -> None:
    result = await session.execute(
        select(SiteModel)
        .where(SiteModel.tls_enabled.is_(True))
        .where(SiteModel.tls_certificate_id.is_(None))
        .order_by(SiteModel.id)
    )
    sites = result.scalars().all()

    for site in sites:
        try:
            policy = await get_effective_upstream_policy(session)
            revalidated = await run_in_threadpool(
                validate_upstream_url,
                site.upstream_url,
                policy.with_private_access(True),
            )
            site.resolved_upstream_ips = revalidated.resolved_ips
            site.last_resolved_at = datetime.utcnow()

            await run_in_threadpool(
                nginx_config_manager.apply_with_rollback,
                site,
                "update",
                certificate,
            )
        except UpstreamValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Upstream policy validation failed during certificate sync (site_id={site.id}): {exc}",
            )
        except NginxConfigApplyError as exc:
            logger.error(
                "Failed to sync site after default certificate change",
                extra={"site_id": site.id, "diagnostics": exc.diagnostics},
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to apply site config after certificate update (site_id={site.id}).",
            )


@router.get("", response_model=list[CertificateOut])
async def list_certificates(
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    result = await session.execute(select(CertificateModel).order_by(CertificateModel.id))
    certificates = result.scalars().all()
    return [_to_certificate_out(certificate) for certificate in certificates]


@router.post("/upload", response_model=CertificateOut, status_code=status.HTTP_201_CREATED)
async def upload_certificate(
    request: Request,
    name: str = Form(...),
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    chain_file: UploadFile | None = File(None),
    is_default: bool = Form(False),
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    cert_bytes = await cert_file.read()
    key_bytes = await key_file.read()
    chain_bytes = await chain_file.read() if chain_file else None

    try:
        certificate_storage.validate_pem_bundle(cert_bytes, key_bytes, chain_bytes)
    except CertificateStorageError as exc:
        await write_audit_log(
            action="cert.create",
            target_type="certificate",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            error_message=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    existing = await session.execute(select(CertificateModel).where(CertificateModel.name == name.strip()))
    if existing.scalars().first():
        await write_audit_log(
            action="cert.create",
            target_type="certificate",
            target_id=None,
            actor=current_user,
            request=request,
            success=False,
            error_message=f"Certificate with name '{name.strip()}' already exists.",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Certificate with name '{name.strip()}' already exists.",
        )

    certificate = CertificateModel(
        name=name.strip(),
        cert_pem_path="pending",
        key_pem_path="pending",
        chain_pem_path=None,
        is_default=is_default,
    )
    stored_paths = None

    try:
        if is_default:
            await session.execute(update(CertificateModel).values(is_default=False))

        session.add(certificate)
        await session.flush()

        stored_paths = certificate_storage.store_certificate_files(
            certificate_id=certificate.id,
            name=certificate.name,
            cert_pem=cert_bytes,
            key_pem=key_bytes,
            chain_pem=chain_bytes,
        )

        certificate.cert_pem_path = stored_paths.cert_path
        certificate.key_pem_path = stored_paths.key_path
        certificate.chain_pem_path = stored_paths.chain_path

        await session.flush()

        if certificate.is_default:
            await _sync_default_tls_sites(session, certificate)

        await session.commit()
        await session.refresh(certificate)
        await write_audit_log(
            action="cert.create",
            target_type="certificate",
            target_id=certificate.id,
            actor=current_user,
            request=request,
            success=True,
            after_json=_certificate_state(certificate),
        )
    except HTTPException:
        await session.rollback()
        if stored_paths:
            certificate_storage.delete_certificate_files(
                stored_paths.cert_path,
                stored_paths.key_path,
                stored_paths.chain_path,
            )
        await write_audit_log(
            action="cert.create",
            target_type="certificate",
            target_id=certificate.id if certificate.id else None,
            actor=current_user,
            request=request,
            success=False,
            error_message="Certificate apply failed during default-site sync.",
        )
        raise
    except Exception as exc:
        await session.rollback()
        if stored_paths:
            certificate_storage.delete_certificate_files(
                stored_paths.cert_path,
                stored_paths.key_path,
                stored_paths.chain_path,
            )
        await write_audit_log(
            action="cert.create",
            target_type="certificate",
            target_id=certificate.id if certificate.id else None,
            actor=current_user,
            request=request,
            success=False,
            error_message=str(exc),
        )
        raise

    return _to_certificate_out(certificate)


@router.put("/{certificate_id}/default", response_model=CertificateOut)
async def set_default_certificate(
    request: Request,
    certificate_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    certificate = await session.get(CertificateModel, certificate_id)
    if not certificate:
        await write_audit_log(
            action="cert.update_default",
            target_type="certificate",
            target_id=certificate_id,
            actor=current_user,
            request=request,
            success=False,
            error_message="Certificate not found.",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found.")

    before = _certificate_state(certificate)
    try:
        await session.execute(update(CertificateModel).values(is_default=False))
        certificate.is_default = True
        await session.flush()
        await _sync_default_tls_sites(session, certificate)
        await session.commit()
        await session.refresh(certificate)
        await write_audit_log(
            action="cert.update_default",
            target_type="certificate",
            target_id=certificate.id,
            actor=current_user,
            request=request,
            success=True,
            before_json=before,
            after_json=_certificate_state(certificate),
        )
    except Exception as exc:
        await session.rollback()
        await write_audit_log(
            action="cert.update_default",
            target_type="certificate",
            target_id=certificate_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            error_message=str(exc),
        )
        raise

    return _to_certificate_out(certificate)


@router.delete("/{certificate_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_certificate(
    request: Request,
    certificate_id: int,
    session: AsyncSession = Depends(get_session),
    current_user: UserInDB = Depends(get_current_super_admin_user),
):
    certificate = await session.get(CertificateModel, certificate_id)
    if not certificate:
        await write_audit_log(
            action="cert.delete",
            target_type="certificate",
            target_id=certificate_id,
            actor=current_user,
            request=request,
            success=False,
            error_message="Certificate not found.",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found.")

    before = _certificate_state(certificate)
    in_use_result = await session.execute(
        select(SiteModel.id)
        .where(SiteModel.tls_enabled.is_(True))
        .where(SiteModel.tls_certificate_id == certificate_id)
        .limit(1)
    )
    if in_use_result.first():
        await write_audit_log(
            action="cert.delete",
            target_type="certificate",
            target_id=certificate_id,
            actor=current_user,
            request=request,
            success=False,
            before_json=before,
            error_message="Certificate is in use by TLS-enabled sites.",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Certificate is still in use by one or more TLS-enabled sites.",
        )

    if certificate.is_default:
        default_in_use_result = await session.execute(
            select(SiteModel.id)
            .where(SiteModel.tls_enabled.is_(True))
            .where(SiteModel.tls_certificate_id.is_(None))
            .limit(1)
        )
        if default_in_use_result.first():
            await write_audit_log(
                action="cert.delete",
                target_type="certificate",
                target_id=certificate_id,
                actor=current_user,
                request=request,
                success=False,
                before_json=before,
                error_message="Default certificate still referenced by TLS sites.",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Default certificate cannot be deleted while TLS sites rely on it.",
            )

    cert_path = certificate.cert_pem_path
    key_path = certificate.key_pem_path
    chain_path = certificate.chain_pem_path

    await session.delete(certificate)
    await session.commit()

    certificate_storage.delete_certificate_files(cert_path, key_path, chain_path)
    await write_audit_log(
        action="cert.delete",
        target_type="certificate",
        target_id=certificate_id,
        actor=current_user,
        request=request,
        success=True,
        before_json=before,
    )
