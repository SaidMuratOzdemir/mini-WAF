# ./waf/checks/patterns/pattern_engine.py
"""
Pattern matching engines for WAF security analysis.

This module provides different pattern matching strategies including
substring matching and regex-based analysis with security safeguards.
"""

import re
import time
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from .exceptions import (
    RegexComplexityError, 
    PatternCompilationError, 
    AnalysisTimeoutError
)

logger = logging.getLogger(__name__)


@dataclass
class Pattern:
    """Pattern data structure for analysis."""
    id: int
    pattern: str
    type: str
    is_regex: bool = False
    description: str = None
    is_active: bool = True


@dataclass
class MatchResult:
    """Result of pattern matching analysis."""
    is_match: bool
    attack_type: str
    matched_pattern: str = None
    confidence_score: float = 1.0
    processing_time_ms: float = 0.0


class PatternEngine(ABC):
    """Abstract base class for pattern matching engines."""
    
    @abstractmethod
    async def match(self, content_variations: List[str], patterns: List[Pattern]) -> Optional[MatchResult]:
        """
        Analyze content variations against patterns.
        
        Args:
            content_variations: List of normalized content versions
            patterns: List of patterns to match against
            
        Returns:
            MatchResult if match found, None otherwise
        """
        pass


class SubstringEngine(PatternEngine):
    """
    Fast substring-based pattern matching engine.
    
    Optimized for performance with basic substring matching,
    suitable for simple pattern detection.
    """
    
    def __init__(self):
        """Initialize substring engine."""
        self.engine_name = "substring"
        
    async def match(self, content_variations: List[str], patterns: List[Pattern]) -> Optional[MatchResult]:
        """
        Perform substring matching against all content variations.
        
        Args:
            content_variations: Normalized content to analyze
            patterns: Substring patterns to match
            
        Returns:
            MatchResult if any pattern matches any content variation
        """
        start_time = time.perf_counter()
        
        try:
            for pattern in patterns:
                if not pattern.is_active or pattern.is_regex:
                    continue
                    
                pattern_lower = pattern.pattern.lower()
                
                for content in content_variations:
                    if pattern_lower in content:
                        processing_time = (time.perf_counter() - start_time) * 1000
                        
                        return MatchResult(
                            is_match=True,
                            attack_type=pattern.type.upper(),
                            matched_pattern=pattern.pattern,
                            confidence_score=1.0,
                            processing_time_ms=processing_time
                        )
                        
            return None
            
        except Exception as e:
            logger.error(f"Substring engine error: {e}")
            return None


class RegexEngine(PatternEngine):
    """
    Regex-based pattern matching engine with security safeguards.
    
    Provides advanced pattern matching capabilities with protection
    against ReDoS attacks and complexity limits.
    """
    
    def __init__(self, max_steps: int = 10000, timeout_ms: int = 100):
        """
        Initialize regex engine with security limits.
        
        Args:
            max_steps: Maximum regex execution steps (ReDoS protection)
            timeout_ms: Maximum analysis time per pattern
        """
        self.engine_name = "regex"
        self.max_steps = max_steps
        self.timeout_ms = timeout_ms
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.compilation_failures: set = set()
        
    async def match(self, content_variations: List[str], patterns: List[Pattern]) -> Optional[MatchResult]:
        """
        Perform regex matching with security safeguards.
        
        Args:
            content_variations: Normalized content to analyze
            patterns: Regex patterns to match
            
        Returns:
            MatchResult if any regex pattern matches
            
        Raises:
            AnalysisTimeoutError: If analysis exceeds timeout
        """
        start_time = time.perf_counter()
        
        try:
            for pattern in patterns:
                if not pattern.is_active or not pattern.is_regex:
                    continue
                    
                # Skip patterns that failed compilation before
                if pattern.pattern in self.compilation_failures:
                    continue
                    
                compiled_regex = await self._get_compiled_pattern(pattern)
                if not compiled_regex:
                    continue
                    
                # Check timeout
                if (time.perf_counter() - start_time) * 1000 > self.timeout_ms:
                    raise AnalysisTimeoutError(
                        timeout_ms=self.timeout_ms,
                        content_length=sum(len(c) for c in content_variations)
                    )
                
                # Match against all content variations
                for content in content_variations:
                    try:
                        # Use asyncio to allow for timeout control
                        match_task = asyncio.create_task(
                            self._safe_regex_match(compiled_regex, content)
                        )
                        
                        match = await asyncio.wait_for(
                            match_task, 
                            timeout=self.timeout_ms / 1000
                        )
                        
                        if match:
                            processing_time = (time.perf_counter() - start_time) * 1000
                            
                            return MatchResult(
                                is_match=True,
                                attack_type=pattern.type.upper(),
                                matched_pattern=pattern.pattern,
                                confidence_score=self._calculate_confidence(match),
                                processing_time_ms=processing_time
                            )
                            
                    except asyncio.TimeoutError:
                        logger.warning(f"Regex timeout for pattern: {pattern.pattern[:50]}...")
                        continue
                    except Exception as e:
                        logger.warning(f"Regex match error: {e}")
                        continue
                        
            return None
            
        except AnalysisTimeoutError:
            raise
        except Exception as e:
            logger.error(f"Regex engine error: {e}")
            return None
    
    async def _get_compiled_pattern(self, pattern: Pattern) -> Optional[re.Pattern]:
        """
        Get compiled regex pattern with caching and error handling.
        
        Args:
            pattern: Pattern to compile
            
        Returns:
            Compiled regex pattern or None if compilation fails
        """
        cache_key = f"{pattern.id}:{pattern.pattern}"
        
        if cache_key in self.compiled_patterns:
            return self.compiled_patterns[cache_key]
            
        try:
            # Validate regex complexity before compilation
            if not self._validate_regex_complexity(pattern.pattern):
                raise RegexComplexityError(pattern.pattern, self.max_steps)
                
            # Compile with security flags
            compiled = re.compile(
                pattern.pattern,
                re.IGNORECASE | re.MULTILINE | re.DOTALL
            )
            
            self.compiled_patterns[cache_key] = compiled
            return compiled
            
        except re.error as e:
            logger.warning(f"Regex compilation failed for pattern {pattern.id}: {e}")
            self.compilation_failures.add(pattern.pattern)
            raise PatternCompilationError(pattern.pattern, str(e))
        except RegexComplexityError:
            logger.warning(f"Regex too complex for pattern {pattern.id}")
            self.compilation_failures.add(pattern.pattern)
            raise
    
    def _validate_regex_complexity(self, pattern: str) -> bool:
        """
        Validate regex complexity to prevent ReDoS attacks.
        
        Args:
            pattern: Regex pattern to validate
            
        Returns:
            True if pattern complexity is acceptable
        """
        # Check for potentially dangerous constructs
        dangerous_patterns = [
            r'\(\?\=.*\)\+',     # Positive lookahead with quantifier
            r'\(\?\!.*\)\+',     # Negative lookahead with quantifier
            r'\(\?\<\=.*\)\+',   # Positive lookbehind with quantifier
            r'\(\?\<\!.*\)\+',   # Negative lookbehind with quantifier
            r'\(\.\*\)\+\1',     # Catastrophic backtracking pattern
            r'\(.*\)\1\+',       # Recursive reference pattern
        ]
        
        for dangerous in dangerous_patterns:
            if re.search(dangerous, pattern):
                return False
                
        # Check pattern length (simple complexity heuristic)
        if len(pattern) > 500:
            return False
            
        # Count nested groups (another complexity indicator)
        open_groups = pattern.count('(')
        if open_groups > 20:
            return False
            
        return True
    
    async def _safe_regex_match(self, compiled_regex: re.Pattern, content: str) -> Optional[re.Match]:
        """
        Perform regex match with step counting (simulated).
        
        Args:
            compiled_regex: Compiled regex pattern
            content: Content to match against
            
        Returns:
            Match object if found, None otherwise
        """
        try:
            # In a real implementation, you would use a regex engine
            # that supports step counting (like PCRE2 with limits)
            # For now, we rely on asyncio timeout for safety
            return compiled_regex.search(content)
            
        except Exception as e:
            logger.warning(f"Safe regex match failed: {e}")
            return None
    
    def _calculate_confidence(self, match: re.Match) -> float:
        """
        Calculate confidence score based on match characteristics.
        
        Args:
            match: Regex match object
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        # Higher confidence for longer matches
        match_length = len(match.group(0))
        
        if match_length >= 10:
            return 1.0
        elif match_length >= 5:
            return 0.8
        elif match_length >= 3:
            return 0.6
        else:
            return 0.4


class HybridEngine(PatternEngine):
    """
    Hybrid engine that uses both substring and regex matching.
    
    Optimizes performance by using fast substring matching first,
    then falling back to regex for complex patterns.
    """
    
    def __init__(self, max_regex_steps: int = 10000, timeout_ms: int = 200):
        """
        Initialize hybrid engine.
        
        Args:
            max_regex_steps: Maximum regex steps
            timeout_ms: Total timeout for analysis
        """
        self.engine_name = "hybrid"
        self.substring_engine = SubstringEngine()
        self.regex_engine = RegexEngine(max_regex_steps, timeout_ms // 2)
        self.timeout_ms = timeout_ms
        
    async def match(self, content_variations: List[str], patterns: List[Pattern]) -> Optional[MatchResult]:
        """
        Perform hybrid matching (substring first, then regex).
        
        Args:
            content_variations: Normalized content to analyze
            patterns: Mixed patterns (substring and regex)
            
        Returns:
            MatchResult from first successful match
        """
        start_time = time.perf_counter()
        
        try:
            # Phase 1: Fast substring matching
            substring_patterns = [p for p in patterns if not p.is_regex]
            if substring_patterns:
                result = await self.substring_engine.match(content_variations, substring_patterns)
                if result:
                    return result
            
            # Check timeout before regex phase
            if (time.perf_counter() - start_time) * 1000 > self.timeout_ms:
                raise AnalysisTimeoutError(
                    timeout_ms=self.timeout_ms,
                    content_length=sum(len(c) for c in content_variations)
                )
            
            # Phase 2: Regex matching for complex patterns
            regex_patterns = [p for p in patterns if p.is_regex]
            if regex_patterns:
                result = await self.regex_engine.match(content_variations, regex_patterns)
                if result:
                    return result
                    
            return None
            
        except AnalysisTimeoutError:
            raise
        except Exception as e:
            logger.error(f"Hybrid engine error: {e}")
            return None