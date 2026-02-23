from pydantic import ValidationError
import pytest

from app.schemas import SiteCreate


def _base_site_payload() -> dict:
    return {
        "name": "phase8-test",
        "host": "app.example.com",
        "upstream_url": "https://upstream.example.com",
    }


@pytest.mark.parametrize(
    "profile",
    ["strict", "default", "headers_only", "upload_friendly", "custom"],
)
def test_phase8_accepts_supported_body_profiles(profile: str) -> None:
    site = SiteCreate(**_base_site_payload(), body_inspection_profile=profile)
    assert site.body_inspection_profile == profile


def test_phase8_rejects_unknown_body_profile() -> None:
    with pytest.raises(ValidationError):
        SiteCreate(**_base_site_payload(), body_inspection_profile="fast")


@pytest.mark.parametrize(
    "field,value",
    [
        ("proxy_read_timeout_sec", 0),
        ("proxy_send_timeout_sec", 0),
        ("proxy_connect_timeout_sec", 0),
    ],
)
def test_phase8_rejects_non_positive_timeouts(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        SiteCreate(**_base_site_payload(), **{field: value})


@pytest.mark.parametrize("size", [0, 2048])
def test_phase8_rejects_invalid_body_size(size: int) -> None:
    with pytest.raises(ValidationError):
        SiteCreate(**_base_site_payload(), client_max_body_size_mb=size)


def test_phase8_rejects_invalid_proxy_redirect_mode() -> None:
    with pytest.raises(ValidationError):
        SiteCreate(**_base_site_payload(), proxy_redirect_mode="rewrite_everything")


def test_phase8_rejects_invalid_waf_decision_mode() -> None:
    with pytest.raises(ValidationError):
        SiteCreate(**_base_site_payload(), waf_decision_mode="best_effort")
