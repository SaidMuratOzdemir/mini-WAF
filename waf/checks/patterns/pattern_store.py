# ./waf/checks/patterns/pattern_store.py
"""
Legacy pattern storage interface with backward compatibility.

This module maintains the original API while delegating to the new
advanced pattern analysis system for enhanced security and performance.
"""

import asyncio
import logging
from typing import Dict, List, Any

from waf.checks.inspection_policy import InspectionPolicy
from waf.integration.db.repository import fetch_all_patterns
from .advanced_analyzer import get_analyzer, AdvancedPatternAnalyzer

logger = logging.getLogger(__name__)

# Legacy cache structure for backward compatibility
PATTERN_CACHE: Dict[str, List[str]] = {"xss": [], "sql": [], "custom": []}
PATTERN_CACHE_LAST = 0
PATTERN_CACHE_TTL = 60
_pattern_lock = asyncio.Lock()


async def fetch_patterns_from_db():
    """
    Load patterns via shared repository and refresh cache.
    
    This function maintains backward compatibility while ensuring
    the new advanced analyzer cache is also updated.
    """
    global PATTERN_CACHE, PATTERN_CACHE_LAST
    
    try:
        patterns = await fetch_all_patterns()
        cache = {"xss": [], "sql": [], "custom": []}
        
        for p in patterns:
            pattern_type = (p.type or "").strip().lower()
            pattern_str = (p.pattern or "").strip()
            
            if not pattern_type or not pattern_str:
                continue
                
            # Only include active patterns in legacy cache
            if getattr(p, 'is_active', True):
                cache.setdefault(pattern_type, []).append(pattern_str.lower())

        PATTERN_CACHE = cache
        PATTERN_CACHE_LAST = asyncio.get_event_loop().time()
        
        logger.debug(f"Legacy pattern cache updated with {sum(len(v) for v in cache.values())} patterns")
        
        # Ensure advanced analyzer cache is also updated
        try:
            analyzer = await get_analyzer()
            await analyzer.cache._refresh_cache()
        except Exception as e:
            logger.warning(f"Failed to update advanced analyzer cache: {e}")
            
    except Exception as e:
        logger.error(f"Failed to fetch patterns from database: {e}")
        raise


async def _ensure_fresh():
    """Ensure pattern cache is fresh, refresh if needed."""
    now = asyncio.get_event_loop().time()
    if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
        async with _pattern_lock:
            if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
                await fetch_patterns_from_db()


async def get_patterns():
    """
    Get legacy pattern cache format.
    
    Returns:
        Dictionary with pattern types as keys and pattern lists as values
    """
    await _ensure_fresh()
    return PATTERN_CACHE


async def _is_malicious(content: str, types_to_check: list):
    """
    Legacy malicious content detection using simple substring matching.
    
    This function is kept for backward compatibility but may be less
    effective than the new advanced analyzer.
    
    Args:
        content: Content to check
        types_to_check: List of pattern types to check against
        
    Returns:
        Tuple of (is_malicious, attack_type)
    """
    if not content or not types_to_check:
        return False, ""

    patterns = await get_patterns()
    content_lc = content.lower()

    for attack_type in types_to_check:
        for pattern in patterns.get(attack_type, []):
            if pattern in content_lc:
                return True, attack_type.upper()

    return False, ""


async def analyze_request_part(content: str, policy: InspectionPolicy):
    """
    Analyze request part using advanced pattern analysis system.
    
    Args:
        content: Request content to analyze
        policy: InspectionPolicy with xss_enabled / sql_enabled toggles
        
    Returns:
        Tuple of (is_malicious, attack_type) for backward compatibility
    """
    if not content:
        return False, ""
    
    try:
        # Use advanced analyzer for enhanced detection
        analyzer = await get_analyzer()
        result = await analyzer.analyze_request_part(content, policy)
        
        return result.is_malicious, result.attack_type
        
    except Exception as e:
        logger.error(f"Advanced pattern analysis failed, falling back to legacy: {e}")
        
        # Fallback to legacy analysis if advanced analyzer fails
        types_to_check = []
        if policy.xss_enabled:
            types_to_check.append("xss")
        if policy.sql_enabled:
            types_to_check.append("sql")
        types_to_check.append("custom")
        
        return await _is_malicious(content, types_to_check)

