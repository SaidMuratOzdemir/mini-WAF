from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import UpstreamPolicy as UpstreamPolicyModel
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _split_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _bool_from_env(env_key: str, default: bool = False) -> bool:
    raw = os.getenv(env_key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_networks(values: Iterable[str], field_name: str) -> tuple[IPNetwork, ...]:
    networks: list[IPNetwork] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR entry in {field_name}: '{value}'") from exc
    return tuple(networks)


def _parse_ports(values: Iterable[str]) -> tuple[int, ...]:
    ports: list[int] = []
    for value in values:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise ValueError(f"Invalid port value '{value}' in ALLOWED_UPSTREAM_PORTS") from exc
        if parsed < 1 or parsed > 65535:
            raise ValueError(f"Port value '{value}' out of range (1-65535)")
        ports.append(parsed)
    return tuple(sorted(set(ports)))


def _normalize_suffixes(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        suffix = value.lower()
        if not suffix.startswith("."):
            suffix = f".{suffix}"
        normalized.append(suffix)
    return tuple(sorted(set(normalized)))


@dataclass(frozen=True, slots=True)
class UpstreamPolicySnapshot:
    allow_private_upstreams: bool
    allowed_private_cidrs_raw: tuple[str, ...]
    denied_cidrs_raw: tuple[str, ...]
    allowed_upstream_ports: tuple[int, ...]
    denied_hostnames: tuple[str, ...]
    allowed_hostname_suffixes: tuple[str, ...]

    @property
    def allowed_private_cidrs(self) -> tuple[IPNetwork, ...]:
        return _parse_networks(self.allowed_private_cidrs_raw, "allowed_private_cidrs")

    @property
    def denied_cidrs(self) -> tuple[IPNetwork, ...]:
        return _parse_networks(self.denied_cidrs_raw, "denied_cidrs")

    def allows_hostname(self, hostname: str) -> bool:
        candidate = hostname.lower()

        for pattern in self.denied_hostnames:
            if fnmatch(candidate, pattern):
                return False

        if not self.allowed_hostname_suffixes:
            return True

        if candidate in {suffix.lstrip(".") for suffix in self.allowed_hostname_suffixes}:
            return True

        return any(candidate.endswith(suffix) for suffix in self.allowed_hostname_suffixes)

    def with_private_access(self, enabled: bool) -> "UpstreamPolicySnapshot":
        return UpstreamPolicySnapshot(
            allow_private_upstreams=enabled,
            allowed_private_cidrs_raw=self.allowed_private_cidrs_raw,
            denied_cidrs_raw=self.denied_cidrs_raw,
            allowed_upstream_ports=self.allowed_upstream_ports,
            denied_hostnames=self.denied_hostnames,
            allowed_hostname_suffixes=self.allowed_hostname_suffixes,
        )


def policy_from_env() -> UpstreamPolicySnapshot:
    return UpstreamPolicySnapshot(
        allow_private_upstreams=_bool_from_env("ALLOW_PRIVATE_UPSTREAMS", False),
        allowed_private_cidrs_raw=tuple(_split_csv(os.getenv("ALLOWED_PRIVATE_CIDRS"))),
        denied_cidrs_raw=tuple(_split_csv(os.getenv("DENIED_CIDRS"))),
        allowed_upstream_ports=_parse_ports(_split_csv(os.getenv("ALLOWED_UPSTREAM_PORTS"))),
        denied_hostnames=tuple(item.lower() for item in _split_csv(os.getenv("DENIED_HOSTNAMES"))),
        allowed_hostname_suffixes=_normalize_suffixes(_split_csv(os.getenv("ALLOWED_HOSTNAME_SUFFIXES"))),
    )


def policy_from_model(model: UpstreamPolicyModel) -> UpstreamPolicySnapshot:
    return UpstreamPolicySnapshot(
        allow_private_upstreams=bool(model.allow_private_upstreams),
        allowed_private_cidrs_raw=tuple(_split_csv(model.allowed_private_cidrs)),
        denied_cidrs_raw=tuple(_split_csv(model.denied_cidrs)),
        allowed_upstream_ports=_parse_ports(_split_csv(model.allowed_upstream_ports)),
        denied_hostnames=tuple(item.lower() for item in _split_csv(model.denied_hostnames)),
        allowed_hostname_suffixes=_normalize_suffixes(_split_csv(model.allowed_hostname_suffixes)),
    )


async def get_effective_upstream_policy(session: AsyncSession) -> UpstreamPolicySnapshot:
    result = await session.execute(select(UpstreamPolicyModel).order_by(UpstreamPolicyModel.id.asc()))
    model = result.scalars().first()
    if model:
        return policy_from_model(model)
    return policy_from_env()
