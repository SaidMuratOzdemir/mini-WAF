"""Security inspection engine for decoupled auth_request flow."""

from __future__ import annotations

import logging
from typing import Any, Mapping
from urllib.parse import urlsplit

from waf.checks.inspection_policy import InspectionPolicy, DEFAULT_POLICY
from waf.checks.patterns.pattern_store import analyze_request_part

logger = logging.getLogger(__name__)

# Re-export so existing `from waf.checks.security_engine import InspectionPolicy` keeps working
__all__ = ["InspectionPolicy", "DEFAULT_POLICY", "analyze_forwarded_request"]


def _extract_path_and_query(metadata: Mapping[str, Any]) -> tuple[str, str]:
    raw_uri = str(metadata.get("uri") or metadata.get("original_uri") or "")

    if raw_uri:
        parsed = urlsplit(raw_uri)
        path = parsed.path or str(metadata.get("path") or "")
        query = parsed.query or str(metadata.get("query") or "")
    else:
        path = str(metadata.get("path") or "")
        query = str(metadata.get("query") or "")

    return path, query


def _decode_body(body_bytes: bytes, content_type: str) -> str:
    if not body_bytes:
        return ""

    binary_types = (
        "image/",
        "video/",
        "audio/",
        "application/pdf",
        "application/zip",
        "application/octet-stream",
    )

    lowered = (content_type or "").lower()
    if any(marker in lowered for marker in binary_types):
        return ""

    try:
        return body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        logger.debug("Failed to decode request body, skipping body pattern analysis")
        return ""


def _normalize_headers(raw_headers: Any) -> dict[str, str]:
    if not isinstance(raw_headers, Mapping):
        return {}

    normalized: dict[str, str] = {}
    for key, value in raw_headers.items():
        if not key:
            continue
        normalized[str(key)] = str(value)

    return normalized


async def analyze_forwarded_request(
    metadata: Mapping[str, Any],
    body_bytes: bytes,
    policy: InspectionPolicy = DEFAULT_POLICY,
) -> tuple[bool, str]:
    """
    Analyze a forwarded request payload.

    The pattern analyzer itself applies ContentNormalizer (URL/Unicode/etc.)
    before regex/substring matching.
    """

    path, query = _extract_path_and_query(metadata)
    headers = _normalize_headers(metadata.get("headers"))
    body_str = _decode_body(body_bytes, str(metadata.get("content_type") or ""))

    parts_to_check: dict[str, str] = {
        "BODY": body_str,
        "PATH": path,
        "QUERY": query,
    }

    for header_name, header_value in headers.items():
        parts_to_check[f"HEADER_{header_name.upper()}"] = header_value

    for location, content in parts_to_check.items():
        if not content:
            continue

        is_malicious, attack_type = await analyze_request_part(content, policy)
        if is_malicious:
            return True, f"{attack_type}_IN_{location}" if attack_type else f"PATTERN_IN_{location}"

    return False, ""
