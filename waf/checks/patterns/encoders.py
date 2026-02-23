# ./waf/checks/patterns/encoders.py
"""
Content normalization and encoding handlers for WAF pattern analysis.

This module provides secure content normalization to prevent encoding-based
bypass attacks. Supports URL encoding, HTML entities, and Unicode normalization.
"""

import html
import urllib.parse
import unicodedata
import logging
from typing import List, Set
from .exceptions import ContentNormalizationError

logger = logging.getLogger(__name__)


class ContentNormalizer:
    """
    Normalizes content to prevent encoding bypass attacks.
    
    Handles multiple encoding schemes and provides normalized versions
    of content for comprehensive pattern matching.
    """
    
    def __init__(self):
        """Initialize normalizer with supported encoding schemes."""
        self.supported_encodings = {'url', 'html', 'unicode'}
        self.max_decode_iterations = 3  # Prevent infinite decode loops
        
    def normalize_all(self, content: str) -> List[str]:
        """
        Generate all normalized versions of content.
        
        Args:
            content: Raw input content to normalize
            
        Returns:
            List of normalized content variations for pattern matching
            
        Raises:
            ContentNormalizationError: If normalization fails
        """
        if not content:
            return ['']
            
        try:
            normalized_versions = set()
            
            # Original content (lowercased)
            normalized_versions.add(content.lower())
            
            # URL decoded versions
            url_decoded = self._normalize_url_encoding(content)
            normalized_versions.update(url_decoded)
            
            # HTML entity decoded versions
            html_decoded = self._normalize_html_entities(content)
            normalized_versions.update(html_decoded)
            
            # Unicode normalized versions
            unicode_normalized = self._normalize_unicode(content)
            normalized_versions.update(unicode_normalized)
            
            # Combined normalizations (URL + HTML)
            combined = self._normalize_combined(content)
            normalized_versions.update(combined)
            
            return list(normalized_versions)
            
        except Exception as e:
            raise ContentNormalizationError(
                content_snippet=content,
                encoding_type="multiple"
            ) from e
    
    def _normalize_url_encoding(self, content: str) -> Set[str]:
        """
        Normalize URL encoded content with multiple decode iterations.
        
        Args:
            content: Content potentially containing URL encoding
            
        Returns:
            Set of URL decoded variations
        """
        decoded_set = {content.lower()}
        current = content
        
        for iteration in range(self.max_decode_iterations):
            try:
                # Standard URL decoding
                decoded = urllib.parse.unquote(current)
                if decoded == current:
                    break  # No more changes
                    
                decoded_set.add(decoded.lower())
                current = decoded
                
                # Plus-space decoding
                plus_decoded = urllib.parse.unquote_plus(current)
                decoded_set.add(plus_decoded.lower())
                
            except Exception as e:
                logger.warning(f"URL decode iteration {iteration} failed: {e}")
                break
                
        return decoded_set
    
    def _normalize_html_entities(self, content: str) -> Set[str]:
        """
        Normalize HTML entity encoded content.
        
        Args:
            content: Content potentially containing HTML entities
            
        Returns:
            Set of HTML decoded variations
        """
        decoded_set = {content.lower()}
        current = content
        
        for iteration in range(self.max_decode_iterations):
            try:
                # HTML entity decoding
                decoded = html.unescape(current)
                if decoded == current:
                    break  # No more changes
                    
                decoded_set.add(decoded.lower())
                current = decoded
                
            except Exception as e:
                logger.warning(f"HTML decode iteration {iteration} failed: {e}")
                break
                
        return decoded_set
    
    def _normalize_unicode(self, content: str) -> Set[str]:
        """
        Normalize Unicode variations (NFKD, NFKC, etc.).
        
        Args:
            content: Content with potential Unicode variations
            
        Returns:
            Set of Unicode normalized variations
        """
        normalized_set = {content.lower()}
        
        try:
            # Unicode normalization forms
            forms = ['NFKD', 'NFKC', 'NFD', 'NFC']
            
            for form in forms:
                normalized = unicodedata.normalize(form, content)
                normalized_set.add(normalized.lower())
                
        except Exception as e:
            logger.warning(f"Unicode normalization failed: {e}")
            
        return normalized_set
    
    def _normalize_combined(self, content: str) -> Set[str]:
        """
        Apply combined normalization (URL + HTML + Unicode).
        
        Args:
            content: Content to normalize with combined methods
            
        Returns:
            Set of combined normalized variations
        """
        combined_set = set()
        
        try:
            # Start with URL decoding
            url_decoded = urllib.parse.unquote_plus(content)
            
            # Then HTML decoding
            html_decoded = html.unescape(url_decoded)
            
            # Finally Unicode normalization
            unicode_normalized = unicodedata.normalize('NFKD', html_decoded)
            
            combined_set.add(unicode_normalized.lower())
            
            # Reverse order combination
            unicode_first = unicodedata.normalize('NFKD', content)
            html_then = html.unescape(unicode_first)
            url_last = urllib.parse.unquote_plus(html_then)
            
            combined_set.add(url_last.lower())
            
        except Exception as e:
            logger.warning(f"Combined normalization failed: {e}")
            
        return combined_set


# Pre-compiled common bypass patterns for quick detection
BYPASS_INDICATORS = {
    'url_encoding': ['%3c', '%3e', '%22', '%27', '%2b', '%20'],
    'html_entities': ['&lt;', '&gt;', '&quot;', '&#x', '&#'],
    'unicode_tricks': ['\\u', '\\x', '\u200b', '\u200c', '\u200d'],
}


def has_encoding_bypass_indicators(content: str) -> bool:
    """
    Quick check for common encoding bypass indicators.
    
    Args:
        content: Content to check for bypass patterns
        
    Returns:
        True if potential bypass patterns detected
    """
    content_lower = content.lower()
    
    for category, indicators in BYPASS_INDICATORS.items():
        for indicator in indicators:
            if indicator in content_lower:
                return True
                
    return False