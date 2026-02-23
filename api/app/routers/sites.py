# api/app/routers/sites.py
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import httpx
import logging

logger = logging.getLogger(__name__)

from app.database import get_session
from app.models import Site as SiteModel
from app.schemas import SiteCreate, Site as SiteSchema, UserInDB
from app.core.security import get_current_admin_user

router = APIRouter(prefix="/sites", tags=["Sites"])


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
    existing = await session.execute(
        select(SiteModel).filter_by(host=site.host)
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with host '{site.host}' already exists."
        )

    new_site = SiteModel(**site.model_dump())
    session.add(new_site)
    await session.commit()
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
    db_site = await session.get(SiteModel, site_id)
    if not db_site:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Site with ID {site_id} not found.")

    if db_site.host != site_update.host:
        conflict = await session.execute(
            select(SiteModel).filter_by(host=site_update.host)
        )
        if conflict.scalars().first():
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Site with host '{site_update.host}' already exists."
            )

    update_data = site_update.model_dump()
    for key, value in update_data.items():
        setattr(db_site, key, value)

    await session.commit()
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

    await session.delete(db_site)
    await session.commit()
