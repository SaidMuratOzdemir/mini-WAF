# ./waf/checks/patterns/exceptions.py
"""
Custom exceptions for pattern matching system.

This module defines specific exception types for pattern analysis
to provide better error handling and debugging capabilities.
"""

import logging

logger = logging.getLogger(__name__)


class PatternAnalysisError(Exception):
    """Base exception for pattern analysis errors."""
    
    def __init__(self, message: str, pattern: str = None, content_snippet: str = None):
        self.pattern = pattern
        self.content_snippet = content_snippet[:100] if content_snippet else None
        super().__init__(message)
        logger.error(f"Pattern analysis error: {message}")


class RegexComplexityError(PatternAnalysisError):
    """Raised when regex pattern exceeds complexity limits."""
    
    def __init__(self, pattern: str, limit: int):
        message = f"Regex pattern exceeds complexity limit ({limit} steps): {pattern[:50]}..."
        super().__init__(message, pattern=pattern)


class ContentNormalizationError(PatternAnalysisError):
    """Raised when content normalization fails."""
    
    def __init__(self, content_snippet: str, encoding_type: str):
        message = f"Failed to normalize content with {encoding_type} encoding"
        super().__init__(message, content_snippet=content_snippet)


class PatternCompilationError(PatternAnalysisError):
    """Raised when regex pattern compilation fails."""
    
    def __init__(self, pattern: str, error: str):
        message = f"Failed to compile regex pattern: {error}"
        super().__init__(message, pattern=pattern)


class AnalysisTimeoutError(PatternAnalysisError):
    """Raised when pattern analysis exceeds time limit."""
    
    def __init__(self, timeout_ms: int, content_length: int):
        message = f"Pattern analysis timeout ({timeout_ms}ms) for content length {content_length}"
        super().__init__(message)