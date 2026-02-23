from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


DISALLOWED_HOSTNAMES = {"localhost"}
METADATA_IPV4 = ipaddress.ip_address("169.254.169.254")
VALID_SERVER_NAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


class UpstreamValidationError(ValueError):
    pass


@dataclass(slots=True)
class UpstreamValidationResult:
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: list[str]


def _bool_from_env(env_key: str, default: bool = False) -> bool:
    raw = os.getenv(env_key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _strip_ipv6_brackets(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def validate_server_name(host: str) -> str:
    if not host or host.isspace():
        raise UpstreamValidationError("Host alanı boş olamaz.")

    normalized = host.strip().lower()

    if any(char in normalized for char in {" ", "\t", "\n", "\r", ";", "{", "}", "/", "\\", "'", '"'}):
        raise UpstreamValidationError("Host alanı geçersiz karakter içeriyor.")

    bare_host = _strip_ipv6_brackets(normalized)
    try:
        ip_obj = ipaddress.ip_address(bare_host)
        if ip_obj.version == 6:
            return f"[{ip_obj.compressed}]"
        return ip_obj.compressed
    except ValueError:
        pass

    if not VALID_SERVER_NAME_RE.fullmatch(normalized):
        raise UpstreamValidationError("Host alanı geçerli bir domain veya IP olmalıdır.")

    return normalized


def _evaluate_ip_policy(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> None:
    if ip_obj.is_loopback:
        raise UpstreamValidationError("Bu hedef güvenlik politikası nedeniyle yasaklandı (loopback).")

    if ip_obj == METADATA_IPV4:
        raise UpstreamValidationError("Bu hedef güvenlik politikası nedeniyle yasaklandı (metadata).")

    if ip_obj.is_private and not allow_private:
        raise UpstreamValidationError("Bu hedef güvenlik politikası nedeniyle yasaklandı (private IP).")


def _resolve_hostname_ips(hostname: str, port: int) -> list[str]:
    try:
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UpstreamValidationError("Upstream host çözümlenemedi.") from exc

    resolved: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        if ip_str not in resolved:
            resolved.append(ip_str)

    if not resolved:
        raise UpstreamValidationError("Upstream host için DNS sonucu bulunamadı.")

    return resolved


def validate_upstream_url(upstream_url: str, allow_private: bool | None = None) -> UpstreamValidationResult:
    if not upstream_url or upstream_url.isspace():
        raise UpstreamValidationError("Geçersiz URL: upstream URL boş olamaz.")

    normalized_url = upstream_url.strip()
    parsed = urlsplit(normalized_url)

    if parsed.scheme not in {"http", "https"}:
        raise UpstreamValidationError("Geçersiz URL: yalnızca http/https desteklenir.")

    if parsed.username or parsed.password:
        raise UpstreamValidationError("Geçersiz URL: upstream URL içinde kullanıcı bilgisi desteklenmez.")

    if not parsed.hostname:
        raise UpstreamValidationError("Geçersiz URL: host eksik.")

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UpstreamValidationError("Geçersiz URL: port değeri hatalı.") from exc

    if port < 1 or port > 65535:
        raise UpstreamValidationError("Geçersiz URL: port 1-65535 aralığında olmalıdır.")

    allow_private_effective = _bool_from_env("ALLOW_PRIVATE_UPSTREAMS", False) if allow_private is None else allow_private

    hostname = parsed.hostname.lower()
    if hostname in DISALLOWED_HOSTNAMES:
        raise UpstreamValidationError("Bu hedef güvenlik politikası nedeniyle yasaklandı (localhost).")

    resolved_ips: list[str] = []

    try:
        ip_obj = ipaddress.ip_address(hostname)
        _evaluate_ip_policy(ip_obj, allow_private_effective)
        resolved_ips = [ip_obj.compressed]
    except ValueError:
        resolved_ips = _resolve_hostname_ips(hostname, port)
        for ip_str in resolved_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            _evaluate_ip_policy(ip_obj, allow_private_effective)

    # NOTE: DNS rebinding'e karşı tam koruma için runtime çözümleme/allowlist yaklaşımı sonraki fazlarda eklenmelidir.
    return UpstreamValidationResult(
        normalized_url=normalized_url,
        scheme=parsed.scheme,
        hostname=hostname,
        port=port,
        resolved_ips=resolved_ips,
    )
