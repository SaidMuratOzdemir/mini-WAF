from typing import List
import logging
from sqlalchemy import select

try:
    from models import MaliciousPattern
except ImportError:  # Local-dev fallback when models.py is not copied to project root
    from api.app.models import MaliciousPattern
from waf.integration.db.connection import AsyncSessionLocal


async def fetch_all_patterns() -> List[MaliciousPattern]:
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(MaliciousPattern))
            return result.scalars().all()
        except Exception as e:
            logging.error(f"Error fetching malicious patterns: {e}")
            return []
