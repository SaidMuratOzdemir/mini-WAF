# ./waf/checks/patterns/advanced_analyzer.py
"""
Advanced pattern analysis system for WAF security checks.

This module provides the main analysis interface that combines content
normalization, pattern matching engines, and security safeguards to detect
malicious requests with high accuracy and performance.
"""

import time
import asyncio
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from waf.checks.inspection_policy import InspectionPolicy
from .encoders import ContentNormalizer, has_encoding_bypass_indicators
from .pattern_engine import (
    Pattern, MatchResult, PatternEngine, 
    SubstringEngine, RegexEngine, HybridEngine
)
from .exceptions import AnalysisTimeoutError, PatternAnalysisError
from waf.integration.db.repository import fetch_all_patterns

logger = logging.getLogger(__name__)


@dataclass
class AnalysisConfig:
    """Configuration for pattern analysis behavior."""
    max_analysis_time_ms: int = 200
    max_patterns_per_site: int = 2000
    enable_encoding_detection: bool = True
    fail_secure: bool = True  # Block on analysis errors
    cache_ttl_seconds: int = 300  # 5 minutes


@dataclass 
class AnalysisResult:
    """Complete result of pattern analysis."""
    is_malicious: bool
    attack_type: str
    matched_pattern: str = None
    confidence_score: float = 0.0
    processing_time_ms: float = 0.0
    content_variations_count: int = 0
    patterns_checked: int = 0
    engine_used: str = None
    bypass_indicators_found: bool = False


class AdvancedPatternCache:
    """
    Advanced caching system for patterns with per-type TTL management.
    
    Provides efficient caching with automatic refresh and pattern
    organization by type for optimized lookup performance.
    """
    
    def __init__(self, config: AnalysisConfig):
        """
        Initialize advanced pattern cache.
        
        Args:
            config: Analysis configuration
        """
        self.config = config
        self.cache: Dict[str, List[Pattern]] = {}
        self.last_refresh: Dict[str, float] = {}
        self.locks: Dict[str, asyncio.Lock] = {}
        self.total_patterns = 0
        
        # Initialize locks for each pattern type
        pattern_types = ['xss', 'sql', 'custom']
        for ptype in pattern_types:
            self.locks[ptype] = asyncio.Lock()
    
    async def get_patterns(self, pattern_types: List[str]) -> List[Pattern]:
        """
        Get cached patterns for specified types with automatic refresh.
        
        Args:
            pattern_types: List of pattern types to retrieve
            
        Returns:
            List of active patterns for specified types
        """
        all_patterns = []
        
        for pattern_type in pattern_types:
            patterns = await self._get_patterns_by_type(pattern_type)
            all_patterns.extend(patterns)
            
        # Enforce pattern limit per site
        if len(all_patterns) > self.config.max_patterns_per_site:
            logger.warning(f"Pattern count ({len(all_patterns)}) exceeds limit ({self.config.max_patterns_per_site})")
            all_patterns = all_patterns[:self.config.max_patterns_per_site]
            
        return all_patterns
    
    async def _get_patterns_by_type(self, pattern_type: str) -> List[Pattern]:
        """
        Get patterns for a specific type with caching and refresh logic.
        
        Args:
            pattern_type: Type of patterns to retrieve
            
        Returns:
            List of patterns for the specified type
        """
        now = time.time()
        cache_key = pattern_type
        
        # Check if refresh is needed
        if (cache_key not in self.last_refresh or 
            now - self.last_refresh[cache_key] > self.config.cache_ttl_seconds):
            
            async with self.locks[pattern_type]:
                # Double-check locking pattern
                if (cache_key not in self.last_refresh or 
                    now - self.last_refresh[cache_key] > self.config.cache_ttl_seconds):
                    
                    await self._refresh_cache(pattern_type)
                    
        return self.cache.get(cache_key, [])
    
    async def _refresh_cache(self, pattern_type: str = None):
        """
        Refresh pattern cache from database.
        
        Args:
            pattern_type: Specific type to refresh, or None for all types
        """
        try:
            db_patterns = await fetch_all_patterns()
            
            if pattern_type:
                # Refresh specific type
                filtered_patterns = [
                    self._convert_db_pattern(p) 
                    for p in db_patterns 
                    if p.type.lower() == pattern_type.lower() and p.is_active
                ]
                
                self.cache[pattern_type] = filtered_patterns
                self.last_refresh[pattern_type] = time.time()
                
                logger.debug(f"Refreshed {len(filtered_patterns)} patterns for type '{pattern_type}'")
                
            else:
                # Refresh all types
                cache = {'xss': [], 'sql': [], 'custom': []}
                
                for p in db_patterns:
                    if not p.is_active:
                        continue
                        
                    pattern_obj = self._convert_db_pattern(p)
                    pattern_type_key = p.type.lower()
                    
                    if pattern_type_key in cache:
                        cache[pattern_type_key].append(pattern_obj)
                
                self.cache = cache
                now = time.time()
                for ptype in cache.keys():
                    self.last_refresh[ptype] = now
                    
                self.total_patterns = sum(len(patterns) for patterns in cache.values())
                logger.info(f"Refreshed {self.total_patterns} total patterns")
                
        except Exception as e:
            logger.error(f"Failed to refresh pattern cache: {e}")
            raise PatternAnalysisError(f"Pattern cache refresh failed: {e}")
    
    def _convert_db_pattern(self, db_pattern) -> Pattern:
        """
        Convert database pattern to Pattern object.
        
        Args:
            db_pattern: Database pattern object
            
        Returns:
            Pattern object for analysis
        """
        return Pattern(
            id=db_pattern.id,
            pattern=db_pattern.pattern,
            type=db_pattern.type.lower(),
            is_regex=getattr(db_pattern, 'is_regex', False),
            description=db_pattern.description,
            is_active=getattr(db_pattern, 'is_active', True)
        )


class AdvancedPatternAnalyzer:
    """
    Main pattern analysis system with advanced security features.
    
    Combines content normalization, multiple matching engines, and
    comprehensive security safeguards for accurate threat detection.
    """
    
    def __init__(self, config: AnalysisConfig = None):
        """
        Initialize advanced pattern analyzer.
        
        Args:
            config: Analysis configuration, uses defaults if None
        """
        self.config = config or AnalysisConfig()
        self.normalizer = ContentNormalizer()
        self.cache = AdvancedPatternCache(self.config)
        
        # Initialize pattern matching engines
        self.engines = {
            'hybrid': HybridEngine(
                max_regex_steps=10000,
                timeout_ms=self.config.max_analysis_time_ms
            ),
            'substring': SubstringEngine(),
            'regex': RegexEngine(
                max_steps=10000,
                timeout_ms=self.config.max_analysis_time_ms // 2
            )
        }
        
        # Performance metrics
        self.analysis_count = 0
        self.total_analysis_time = 0.0
        self.bypass_detections = 0
        
    async def analyze_request_part(self, content: str, policy: InspectionPolicy) -> AnalysisResult:
        """
        Analyze request content part for malicious patterns.
        
        Args:
            content: Request content to analyze (body, path, headers, etc.)
            policy: InspectionPolicy with pattern type toggles
            
        Returns:
            AnalysisResult with detection details
            
        Raises:
            PatternAnalysisError: If analysis fails and fail_secure is True
        """
        if not content:
            return AnalysisResult(
                is_malicious=False,
                attack_type="",
                processing_time_ms=0.0
            )
            
        start_time = time.perf_counter()
        
        try:
            # Determine which pattern types to check based on site config
            pattern_types = self._get_enabled_pattern_types(policy)
            if not pattern_types:
                return AnalysisResult(
                    is_malicious=False,
                    attack_type="",
                    processing_time_ms=(time.perf_counter() - start_time) * 1000
                )
            
            # Get patterns from cache
            patterns = await self.cache.get_patterns(pattern_types)
            if not patterns:
                logger.warning(f"No patterns found for types: {pattern_types}")
                return AnalysisResult(
                    is_malicious=False,
                    attack_type="",
                    processing_time_ms=(time.perf_counter() - start_time) * 1000
                )
            
            # Check for encoding bypass indicators (quick heuristic)
            bypass_indicators = False
            if self.config.enable_encoding_detection:
                bypass_indicators = has_encoding_bypass_indicators(content)
                if bypass_indicators:
                    self.bypass_detections += 1
                    logger.debug(f"Encoding bypass indicators detected in content")
            
            # Normalize content to prevent encoding bypasses
            content_variations = self.normalizer.normalize_all(content)
            
            # Select appropriate engine based on pattern complexity
            engine = self._select_engine(patterns)
            
            # Perform pattern matching with timeout
            try:
                match_result = await asyncio.wait_for(
                    engine.match(content_variations, patterns),
                    timeout=self.config.max_analysis_time_ms / 1000
                )
                
            except asyncio.TimeoutError:
                raise AnalysisTimeoutError(
                    timeout_ms=self.config.max_analysis_time_ms,
                    content_length=len(content)
                )
            
            # Calculate total processing time
            processing_time = (time.perf_counter() - start_time) * 1000
            
            # Update performance metrics
            self.analysis_count += 1
            self.total_analysis_time += processing_time
            
            # Create comprehensive result
            if match_result:
                return AnalysisResult(
                    is_malicious=True,
                    attack_type=match_result.attack_type,
                    matched_pattern=match_result.matched_pattern,
                    confidence_score=match_result.confidence_score,
                    processing_time_ms=processing_time,
                    content_variations_count=len(content_variations),
                    patterns_checked=len(patterns),
                    engine_used=engine.engine_name,
                    bypass_indicators_found=bypass_indicators
                )
            else:
                return AnalysisResult(
                    is_malicious=False,
                    attack_type="",
                    processing_time_ms=processing_time,
                    content_variations_count=len(content_variations),
                    patterns_checked=len(patterns),
                    engine_used=engine.engine_name,
                    bypass_indicators_found=bypass_indicators
                )
                
        except AnalysisTimeoutError as e:
            logger.warning(f"Pattern analysis timeout: {e}")
            if self.config.fail_secure:
                # In fail-secure mode, treat timeouts as potential threats
                return AnalysisResult(
                    is_malicious=True,
                    attack_type="ANALYSIS_TIMEOUT",
                    processing_time_ms=self.config.max_analysis_time_ms,
                    bypass_indicators_found=bypass_indicators
                )
            else:
                return AnalysisResult(
                    is_malicious=False,
                    attack_type="",
                    processing_time_ms=self.config.max_analysis_time_ms
                )
                
        except Exception as e:
            logger.error(f"Pattern analysis error: {e}")
            if self.config.fail_secure:
                # In fail-secure mode, treat analysis errors as potential threats
                return AnalysisResult(
                    is_malicious=True,
                    attack_type="ANALYSIS_ERROR",
                    processing_time_ms=(time.perf_counter() - start_time) * 1000
                )
            else:
                return AnalysisResult(
                    is_malicious=False,
                    attack_type="",
                    processing_time_ms=(time.perf_counter() - start_time) * 1000
                )
    
    def _get_enabled_pattern_types(self, policy: InspectionPolicy) -> List[str]:
        """
        Get enabled pattern types based on inspection policy.
        
        Args:
            policy: InspectionPolicy with toggle flags
            
        Returns:
            List of enabled pattern types
        """
        pattern_types = []
        
        if policy.xss_enabled:
            pattern_types.append('xss')
        if policy.sql_enabled:
            pattern_types.append('sql')
            
        # Custom patterns are always enabled
        pattern_types.append('custom')
        
        return pattern_types
    
    def _select_engine(self, patterns: List[Pattern]) -> PatternEngine:
        """
        Select appropriate matching engine based on pattern complexity.
        
        Args:
            patterns: List of patterns to analyze
            
        Returns:
            Selected pattern matching engine
        """
        # Count regex patterns to determine best engine
        regex_count = sum(1 for p in patterns if p.is_regex)
        substring_count = len(patterns) - regex_count
        
        if regex_count == 0:
            # All substring patterns - use fast substring engine
            return self.engines['substring']
        elif substring_count == 0:
            # All regex patterns - use regex engine
            return self.engines['regex']
        else:
            # Mixed patterns - use hybrid engine for optimal performance
            return self.engines['hybrid']
    
    async def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get performance metrics for monitoring and optimization.
        
        Returns:
            Dictionary containing performance statistics
        """
        avg_analysis_time = (
            self.total_analysis_time / self.analysis_count 
            if self.analysis_count > 0 else 0.0
        )
        
        return {
            'analysis_count': self.analysis_count,
            'total_analysis_time_ms': self.total_analysis_time,
            'average_analysis_time_ms': avg_analysis_time,
            'bypass_detections': self.bypass_detections,
            'cache_stats': {
                'total_patterns': self.cache.total_patterns,
                'last_refresh_times': dict(self.cache.last_refresh)
            }
        }
    
    async def warm_up_cache(self):
        """
        Pre-load pattern cache for optimal performance.
        
        Should be called during application startup to avoid
        cold cache performance impact on first requests.
        """
        logger.info("Warming up pattern cache...")
        pattern_types = ['xss', 'sql', 'custom']
        
        try:
            patterns = await self.cache.get_patterns(pattern_types)
            logger.info(f"Cache warmed up with {len(patterns)} patterns")
        except Exception as e:
            logger.error(f"Cache warm-up failed: {e}")


# Global analyzer instance for backward compatibility
_global_analyzer = None


async def get_analyzer() -> AdvancedPatternAnalyzer:
    """
    Get global analyzer instance with lazy initialization.
    
    Returns:
        Shared AdvancedPatternAnalyzer instance
    """
    global _global_analyzer
    
    if _global_analyzer is None:
        _global_analyzer = AdvancedPatternAnalyzer()
        await _global_analyzer.warm_up_cache()
        
    return _global_analyzer


# Backward compatibility functions
async def analyze_request_part(content: str, policy: InspectionPolicy) -> tuple[bool, str]:
    """
    Backward compatible analysis function.
    
    Args:
        content: Content to analyze
        policy: InspectionPolicy with toggle flags
        
    Returns:
        Tuple of (is_malicious, attack_type) for compatibility
    """
    analyzer = await get_analyzer()
    result = await analyzer.analyze_request_part(content, policy)
    
    return result.is_malicious, result.attack_type
