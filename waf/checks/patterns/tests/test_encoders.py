# ./waf/checks/patterns/tests/test_encoders.py
"""
Tests for content normalization and encoding bypass prevention.

These tests validate the security of content normalization against
various encoding-based bypass techniques.
"""

import pytest
from waf.checks.patterns.encoders import (
    ContentNormalizer, 
    has_encoding_bypass_indicators,
    BYPASS_INDICATORS
)


class TestContentNormalizer:
    """Test content normalization functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ContentNormalizer()
    
    def test_basic_normalization(self):
        """Test basic content normalization."""
        content = "Hello World"
        normalized = self.normalizer.normalize_all(content)
        
        assert "hello world" in normalized
        assert len(normalized) >= 1
    
    def test_url_encoding_normalization(self):
        """Test URL encoding bypass prevention."""
        # Basic URL encoding
        content = "alert%28%29"  # alert()
        normalized = self.normalizer.normalize_all(content)
        
        assert "alert()" in normalized
        
        # Double URL encoding
        content = "alert%2528%2529"  # alert%28%29 -> alert()
        normalized = self.normalizer.normalize_all(content)
        
        assert "alert()" in normalized
    
    def test_html_entity_normalization(self):
        """Test HTML entity encoding bypass prevention."""
        # Named entities
        content = "&lt;script&gt;alert()&lt;/script&gt;"
        normalized = self.normalizer.normalize_all(content)
        
        assert "<script>alert()</script>" in normalized
        
        # Numeric entities
        content = "&#60;script&#62;alert()&#60;/script&#62;"
        normalized = self.normalizer.normalize_all(content)
        
        assert "<script>alert()</script>" in normalized
        
        # Hex entities
        content = "&#x3c;script&#x3e;alert()&#x3c;/script&#x3e;"
        normalized = self.normalizer.normalize_all(content)
        
        assert "<script>alert()</script>" in normalized
    
    def test_unicode_normalization(self):
        """Test Unicode normalization."""
        # Unicode variations
        content = "s\u0063ript"  # script with Unicode c
        normalized = self.normalizer.normalize_all(content)
        
        assert "script" in normalized
    
    def test_combined_encoding_bypass(self):
        """Test complex multi-encoding bypass attempts."""
        # URL + HTML combination
        content = "%26lt%3Bscript%26gt%3Balert()%26lt%3B/script%26gt%3B"
        normalized = self.normalizer.normalize_all(content)
        
        # Should decode to <script>alert()</script>
        assert any("<script>" in n and "alert()" in n for n in normalized)
    
    def test_empty_content(self):
        """Test handling of empty content."""
        normalized = self.normalizer.normalize_all("")
        assert normalized == ['']
        
        normalized = self.normalizer.normalize_all(None)
        assert normalized == ['']
    
    def test_max_decode_iterations(self):
        """Test protection against infinite decode loops."""
        # Create deeply nested encoding that could cause loops
        content = "%2525252525"  # Multiple levels of % encoding
        normalized = self.normalizer.normalize_all(content)
        
        # Should handle without infinite loop
        assert len(normalized) > 0
        assert all(isinstance(n, str) for n in normalized)


class TestBypassIndicatorDetection:
    """Test bypass indicator detection functionality."""
    
    def test_url_encoding_indicators(self):
        """Test detection of URL encoding indicators."""
        assert has_encoding_bypass_indicators("test%20content")
        assert has_encoding_bypass_indicators("alert%28%29")
        assert has_encoding_bypass_indicators("script%3e")
        assert not has_encoding_bypass_indicators("normal content")
    
    def test_html_entity_indicators(self):
        """Test detection of HTML entity indicators."""
        assert has_encoding_bypass_indicators("&lt;script&gt;")
        assert has_encoding_bypass_indicators("&#x3c;test&#x3e;")
        assert has_encoding_bypass_indicators("&#60;script&#62;")
        assert not has_encoding_bypass_indicators("normal & content")
    
    def test_unicode_indicators(self):
        """Test detection of Unicode bypass indicators."""
        assert has_encoding_bypass_indicators("test\\u0041content")
        assert has_encoding_bypass_indicators("script\\x3c")
        assert has_encoding_bypass_indicators("content\u200btest")
        assert not has_encoding_bypass_indicators("normal unicode content")
    
    def test_mixed_indicators(self):
        """Test detection with mixed encoding indicators."""
        content = "test%20&lt;script\\u0041&gt;"
        assert has_encoding_bypass_indicators(content)
    
    def test_case_insensitive_detection(self):
        """Test case insensitive indicator detection."""
        assert has_encoding_bypass_indicators("TEST%20CONTENT")
        assert has_encoding_bypass_indicators("&LT;SCRIPT&GT;")


# Integration tests with real-world bypass attempts
class TestRealWorldBypassAttempts:
    """Test against real-world bypass attempts."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ContentNormalizer()
    
    @pytest.mark.parametrize("bypass_attempt,expected_normalized", [
        # Common XSS bypasses
        ("javascript:alert%28%29", "javascript:alert()"),
        ("&lt;img src=x onerror=alert()&gt;", "<img src=x onerror=alert()>"),
        ("&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;", "javascript"),
        
        # SQL injection bypasses  
        ("UNION%20SELECT", "union select"),
        ("&#39;&#32;OR&#32;&#39;1&#39;=&#39;1", "' or '1'='1"),
        
        # Mixed encoding bypasses
        ("%26%2339%3B%20OR%20%26%2339%3B1%26%2339%3B%3D%26%2339%3B1", "' or '1'='1"),
    ])
    def test_common_bypass_normalization(self, bypass_attempt, expected_normalized):
        """Test normalization of common bypass attempts."""
        normalized = self.normalizer.normalize_all(bypass_attempt)
        
        assert any(expected_normalized.lower() in n.lower() for n in normalized), \
            f"Expected '{expected_normalized}' not found in normalized versions: {normalized}"
    
    def test_performance_with_large_content(self):
        """Test performance with large content."""
        import time
        
        # Generate large content with mixed encodings
        large_content = "test%20content" * 1000 + "&lt;script&gt;" * 500
        
        start_time = time.time()
        normalized = self.normalizer.normalize_all(large_content)
        processing_time = time.time() - start_time
        
        # Should complete within reasonable time (< 1 second)
        assert processing_time < 1.0
        assert len(normalized) > 0