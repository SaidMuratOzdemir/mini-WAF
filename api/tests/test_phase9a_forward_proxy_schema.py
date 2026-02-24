import pytest
from pydantic import ValidationError

from app.schemas import (
    OutboundDestinationRuleCreate,
    OutboundProxyProfileCreate,
)


def test_phase9a_profile_accepts_valid_payload() -> None:
    profile = OutboundProxyProfileCreate(
        name="corp-outbound",
        listen_port=3128,
        is_enabled=True,
        require_auth=False,
        allow_connect_ports="443,563",
        allowed_client_cidrs="10.0.0.0/24,192.168.1.10/32",
        default_action="deny",
    )

    assert profile.allow_connect_ports == "443,563"
    assert profile.allowed_client_cidrs == "10.0.0.0/24,192.168.1.10/32"


@pytest.mark.parametrize("port", [0, 65536])
def test_phase9a_profile_rejects_invalid_listen_port(port: int) -> None:
    with pytest.raises(ValidationError):
        OutboundProxyProfileCreate(
            name="bad-port",
            listen_port=port,
            is_enabled=False,
            require_auth=False,
            allow_connect_ports="443",
            allowed_client_cidrs=None,
            default_action="deny",
        )


def test_phase9a_profile_rejects_require_auth_true() -> None:
    """Phase 9A.2-A: require_auth=true is now accepted; this test verifies it no longer rejects."""
    profile = OutboundProxyProfileCreate(
        name="auth-not-supported",
        listen_port=3128,
        is_enabled=False,
        require_auth=True,
        allow_connect_ports="443",
        allowed_client_cidrs=None,
        default_action="deny",
    )
    assert profile.require_auth is True


@pytest.mark.parametrize(
    "rule_type,value,expected",
    [
        ("domain_exact", "github.com", "github.com"),
        ("domain_suffix", "github.com", ".github.com"),
        ("host_exact", "example.com", "example.com"),
        ("cidr", "10.0.0.5/24", "10.0.0.0/24"),
        ("port", "443", "443"),
    ],
)
def test_phase9a_rule_normalization(rule_type: str, value: str, expected: str) -> None:
    rule = OutboundDestinationRuleCreate(
        action="allow",
        rule_type=rule_type,
        value=value,
        priority=10,
        is_enabled=True,
    )
    assert rule.value == expected


@pytest.mark.parametrize(
    "rule_type,value",
    [
        ("domain_exact", "bad host name"),
        ("cidr", "bad-cidr"),
        ("port", "70000"),
    ],
)
def test_phase9a_rule_rejects_invalid_values(rule_type: str, value: str) -> None:
    with pytest.raises(ValidationError):
        OutboundDestinationRuleCreate(
            action="deny",
            rule_type=rule_type,
            value=value,
            priority=1,
            is_enabled=True,
        )
