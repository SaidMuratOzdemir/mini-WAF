# ./waf/checks/patterns/tests/test_pattern_engine.py
"""
Tests for pattern matching engines.

These tests validate the functionality, security, and performance
of different pattern matching strategies.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch

from waf.checks.patterns.pattern_engine import (
    Pattern, MatchResult, 
    SubstringEngine, RegexEngine, HybridEngine
)
from waf.checks.patterns.exceptions import (
    RegexComplexityError, PatternCompilationError, AnalysisTimeoutError
)


class TestPattern:
    """Test Pattern data structure."""
    
    def test_pattern_creation(self):
        """Test basic pattern creation."""
        pattern = Pattern(
            id=1,
            pattern="<script>",
            type="xss",
            is_regex=False,
            description="Basic XSS pattern"
        )
        
        assert pattern.id == 1
        assert pattern.pattern == "<script>"
        assert pattern.type == "xss"
        assert not pattern.is_regex
        assert pattern.is_active is True  # Default value
    
    def test_regex_pattern_creation(self):
        """Test regex pattern creation."""
        pattern = Pattern(
            id=2,
            pattern=r"<script[^>]*>.*?</script>",
            type="xss",
            is_regex=True
        )
        
        assert pattern.is_regex is True


class TestSubstringEngine:
    """Test substring pattern matching engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = SubstringEngine()
    
    @pytest.mark.asyncio
    async def test_basic_substring_matching(self):
        """Test basic substring pattern matching."""
        patterns = [
            Pattern(1, "<script>", "xss", False),
            Pattern(2, "union select", "sql", False)
        ]
        
        # Test XSS detection
        content_variations = ["<script>alert()</script>", "test content"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is not None
        assert result.is_match is True
        assert result.attack_type == "XSS"
        assert result.matched_pattern == "<script>"
        
        # Test SQL injection detection
        content_variations = ["SELECT * FROM users UNION SELECT password FROM admin"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is not None
        assert result.is_match is True
        assert result.attack_type == "SQL"
    
    @pytest.mark.asyncio
    async def test_case_insensitive_matching(self):
        """Test case insensitive matching."""
        patterns = [Pattern(1, "script", "xss", False)]
        
        content_variations = ["<SCRIPT>alert()</SCRIPT>"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is not None
        assert result.is_match is True
    
    @pytest.mark.asyncio
    async def test_no_match(self):
        """Test when no patterns match."""
        patterns = [Pattern(1, "<script>", "xss", False)]
        
        content_variations = ["normal content"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_inactive_patterns_ignored(self):
        """Test that inactive patterns are ignored."""
        patterns = [
            Pattern(1, "<script>", "xss", False, is_active=False),
            Pattern(2, "union select", "sql", False, is_active=True)
        ]
        
        content_variations = ["<script>alert()</script>"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is None  # Inactive pattern should be ignored
    
    @pytest.mark.asyncio
    async def test_regex_patterns_ignored(self):
        """Test that regex patterns are ignored by substring engine."""
        patterns = [Pattern(1, r"<script.*?>", "xss", True)]
        
        content_variations = ["<script>alert()</script>"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is None  # Regex patterns should be ignored


class TestRegexEngine:
    """Test regex pattern matching engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = RegexEngine(max_steps=10000, timeout_ms=100)
    
    @pytest.mark.asyncio
    async def test_basic_regex_matching(self):
        """Test basic regex pattern matching."""
        patterns = [
            Pattern(1, r"<script[^>]*>.*?</script>", "xss", True),
            Pattern(2, r"union\s+select", "sql", True)
        ]
        
        # Test XSS detection
        content_variations = ["<script type='text/javascript'>alert()</script>"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is not None
        assert result.is_match is True
        assert result.attack_type == "XSS"
    
    @pytest.mark.asyncio
    async def test_regex_compilation_error(self):
        """Test handling of invalid regex patterns."""
        patterns = [Pattern(1, r"[invalid(regex", "xss", True)]
        
        content_variations = ["test content"]
        
        # Should handle compilation error gracefully
        result = await self.engine.match(content_variations, patterns)
        assert result is None
        
        # Pattern should be added to compilation failures
        assert patterns[0].pattern in self.engine.compilation_failures
    
    @pytest.mark.asyncio
    async def test_regex_complexity_validation(self):
        """Test regex complexity validation."""
        # This should trigger complexity validation
        complex_pattern = r"(.*)*" * 50  # Very complex pattern
        
        assert not self.engine._validate_regex_complexity(complex_pattern)
    
    @pytest.mark.asyncio
    async def test_dangerous_regex_detection(self):
        """Test detection of dangerous regex patterns."""
        dangerous_patterns = [
            r"(?=.*)+",      # Positive lookahead with quantifier
            r"(?!.*)+",      # Negative lookahead with quantifier
            r"(.*)\1+",      # Recursive reference
        ]
        
        for pattern in dangerous_patterns:
            assert not self.engine._validate_regex_complexity(pattern)
    
    @pytest.mark.asyncio
    async def test_confidence_scoring(self):
        """Test confidence score calculation."""
        import re
        
        # Mock match objects with different lengths
        short_match = Mock()
        short_match.group.return_value = "ab"
        
        long_match = Mock()
        long_match.group.return_value = "<script>alert()</script>"
        
        short_confidence = self.engine._calculate_confidence(short_match)
        long_confidence = self.engine._calculate_confidence(long_match)
        
        assert long_confidence > short_confidence
        assert 0.0 <= short_confidence <= 1.0
        assert 0.0 <= long_confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_substring_patterns_ignored(self):
        """Test that non-regex patterns are ignored."""
        patterns = [Pattern(1, "<script>", "xss", False)]
        
        content_variations = ["<script>alert()</script>"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is None  # Non-regex patterns should be ignored


class TestHybridEngine:
    """Test hybrid pattern matching engine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = HybridEngine(max_regex_steps=10000, timeout_ms=200)
    
    @pytest.mark.asyncio
    async def test_substring_first_matching(self):
        """Test that substring patterns are matched first."""
        patterns = [
            Pattern(1, "<script>", "xss", False),  # Substring
            Pattern(2, r"<script[^>]*>", "xss", True)  # Regex
        ]
        
        content_variations = ["<script>alert()</script>"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is not None
        assert result.is_match is True
        assert result.attack_type == "XSS"
        # Should match substring pattern first
        assert result.matched_pattern == "<script>"
    
    @pytest.mark.asyncio
    async def test_regex_fallback(self):
        """Test regex matching when substring doesn't match."""
        patterns = [
            Pattern(1, "exact_match", "test", False),  # Won't match
            Pattern(2, r"script.*alert", "xss", True)  # Will match
        ]
        
        content_variations = ["<script type='text/javascript'>alert(1)</script>"]
        result = await self.engine.match(content_variations, patterns)
        
        assert result is not None
        assert result.is_match is True
        assert result.attack_type == "XSS"
    
    @pytest.mark.asyncio
    async def test_mixed_pattern_performance(self):
        """Test performance with mixed pattern types."""
        # Create mix of substring and regex patterns
        patterns = []
        
        # Add substring patterns
        for i in range(50):
            patterns.append(Pattern(i, f"pattern{i}", "test", False))
        
        # Add regex patterns
        for i in range(50, 60):
            patterns.append(Pattern(i, rf"pattern{i}\d+", "test", True))
        
        content_variations = ["test content with pattern55 and numbers 123"]
        
        start_time = time.time()
        result = await self.engine.match(content_variations, patterns)
        processing_time = time.time() - start_time
        
        # Should complete quickly
        assert processing_time < 0.5  # 500ms max
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test timeout handling in hybrid engine."""
        # Create engine with very short timeout
        short_timeout_engine = HybridEngine(timeout_ms=1)  # 1ms timeout
        
        patterns = [Pattern(1, r".*" * 100, "test", True)]  # Complex regex
        content_variations = ["a" * 10000]  # Large content
        
        with pytest.raises(AnalysisTimeoutError):
            await short_timeout_engine.match(content_variations, patterns)


# Performance and integration tests
class TestEnginePerformance:
    """Test performance characteristics of different engines."""
    
    @pytest.mark.asyncio
    async def test_substring_engine_performance(self):
        """Test substring engine performance with large pattern sets."""
        engine = SubstringEngine()
        
        # Create large pattern set
        patterns = [
            Pattern(i, f"pattern{i}", "test", False)
            for i in range(1000)
        ]
        
        content_variations = ["test content with pattern500 embedded"]
        
        start_time = time.time()
        result = await engine.match(content_variations, patterns)
        processing_time = time.time() - start_time
        
        assert result is not None
        assert result.is_match is True
        assert processing_time < 0.1  # Should be very fast
    
    @pytest.mark.asyncio
    async def test_engine_selection_logic(self):
        """Test that appropriate engines are selected based on pattern types."""
        hybrid_engine = HybridEngine()
        
        # Test with only substring patterns
        substring_patterns = [Pattern(1, "test", "test", False)]
        # Engine selection logic is internal, but we can test behavior
        result = await hybrid_engine.match(["test content"], substring_patterns)
        assert result is not None
        
        # Test with only regex patterns  
        regex_patterns = [Pattern(1, r"test.*", "test", True)]
        result = await hybrid_engine.match(["test content"], regex_patterns)
        assert result is not None