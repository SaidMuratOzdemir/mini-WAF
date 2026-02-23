# ./waf/checks/patterns/__init__.py
"""
Advanced WAF Pattern Analysis System

This package provides comprehensive pattern matching capabilities for web application
firewall security analysis. Features include:

- Multi-encoding content normalization (URL, HTML, Unicode)
- Regex and substring pattern matching engines
- Performance optimization with intelligent caching
- Security safeguards against ReDoS attacks
- Backward compatibility with legacy systems

Main Components:
- AdvancedPatternAnalyzer: Primary analysis interface
- ContentNormalizer: Encoding bypass prevention
- PatternEngine: Multiple matching strategies
- AdvancedPatternCache: High-performance pattern caching

Usage:
    from waf.checks.patterns import analyze_request_part
    
    # Legacy compatible interface
    is_malicious, attack_type = await analyze_request_part(content, policy)
    
    # Advanced interface with detailed results
    from waf.checks.patterns.advanced_analyzer import get_analyzer
    analyzer = await get_analyzer()
    result = await analyzer.analyze_request_part(content, policy)
"""

from .pattern_store import analyze_request_part, fetch_patterns_from_db, get_patterns
from .advanced_analyzer import (
    AdvancedPatternAnalyzer, 
    AnalysisConfig, 
    AnalysisResult,
    get_analyzer
)
from .encoders import ContentNormalizer, has_encoding_bypass_indicators
from .pattern_engine import Pattern, MatchResult, PatternEngine
from .exceptions import (
    PatternAnalysisError,
    RegexComplexityError, 
    ContentNormalizationError,
    PatternCompilationError,
    AnalysisTimeoutError
)

__version__ = "2.0.0"
__author__ = "WAF Security Team"

# Export main interface functions
__all__ = [
    # Legacy interface
    'analyze_request_part',
    'fetch_patterns_from_db', 
    'get_patterns',
    
    # Advanced interface
    'AdvancedPatternAnalyzer',
    'AnalysisConfig',
    'AnalysisResult',
    'get_analyzer',
    
    # Content processing
    'ContentNormalizer',
    'has_encoding_bypass_indicators',
    
    # Pattern engines
    'Pattern',
    'MatchResult', 
    'PatternEngine',
    
    # Exceptions
    'PatternAnalysisError',
    'RegexComplexityError',
    'ContentNormalizationError',
    'PatternCompilationError',
    'AnalysisTimeoutError'
]