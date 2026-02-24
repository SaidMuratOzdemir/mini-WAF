# api/app/schemas.py

from __future__ import annotations
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from typing import Optional, List
from datetime import datetime
import ipaddress
import re
from urllib.parse import urlsplit

BODY_INSPECTION_PROFILES = {"strict", "default", "headers_only", "upload_friendly", "custom"}
PROXY_REDIRECT_MODES = {"default", "off", "rewrite_to_public_host"}
WAF_DECISION_MODES = {"fail_open", "fail_close"}
FORWARD_PROXY_DEFAULT_ACTIONS = {"allow", "deny"}
FORWARD_PROXY_RULE_ACTIONS = {"allow", "deny"}
FORWARD_PROXY_RULE_TYPES = {"domain_exact", "domain_suffix", "host_exact", "cidr", "port"}
HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")

# --- Token Schemas ---
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None

# --- User Schemas ---
class UserBase(BaseModel):
    username: str

class UserInDB(UserBase):
    id: int
    is_admin: bool
    role: str = "admin"
    model_config = ConfigDict(from_attributes=True)

# --- Site Schemas ---
class SiteBase(BaseModel):
    name: str
    host: str = Field(..., description='Host header to match (e.g., "api.example.com")')
    upstream_url: str = Field(..., description='Upstream URL (http/https) to proxy requests to')
    is_active: bool = True
    preserve_host_header: bool = False
    enable_sni: bool = True
    websocket_enabled: bool = True
    sse_enabled: bool = False
    body_inspection_profile: str = "default"
    client_max_body_size_mb: Optional[int] = None
    proxy_request_buffering: Optional[bool] = None
    proxy_read_timeout_sec: int = 60
    proxy_send_timeout_sec: int = 60
    proxy_connect_timeout_sec: int = 10
    proxy_redirect_mode: str = "default"
    cookie_rewrite_enabled: bool = False
    waf_decision_mode: str = "fail_close"
    tls_enabled: bool = False
    http_redirect_to_https: bool = False
    tls_certificate_id: Optional[int] = None
    upstream_tls_verify: bool = True
    upstream_tls_server_name_override: Optional[str] = None
    hsts_enabled: bool = False
    xss_enabled: bool = True
    sql_enabled: bool = True
    vt_enabled: bool = False

    @field_validator('host')
    def validate_host(cls, v):
        if not v or v.isspace():
            raise ValueError("Host cannot be empty")
        return v.lower()

    @field_validator('upstream_url')
    def validate_upstream_url(cls, v):
        if not v or v.isspace():
            raise ValueError("Upstream URL cannot be empty")

        parsed = urlsplit(v.strip())
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Upstream URL scheme must be http or https")
        if not parsed.netloc:
            raise ValueError("Upstream URL must include a host")
        return v.strip()

    @field_validator('body_inspection_profile')
    def validate_body_inspection_profile(cls, v):
        if not v or v.isspace():
            raise ValueError("Body inspection profile cannot be empty")
        normalized = v.strip().lower()
        if normalized not in BODY_INSPECTION_PROFILES:
            raise ValueError("body_inspection_profile must be one of strict/default/headers_only/upload_friendly/custom")
        return normalized

    @field_validator("client_max_body_size_mb")
    def validate_client_max_body_size_mb(cls, v):
        if v is None:
            return None
        if v < 1 or v > 1024:
            raise ValueError("client_max_body_size_mb must be between 1 and 1024")
        return v

    @field_validator("proxy_read_timeout_sec", "proxy_send_timeout_sec", "proxy_connect_timeout_sec")
    def validate_timeouts(cls, v):
        if v < 1 or v > 3600:
            raise ValueError("timeout must be between 1 and 3600 seconds")
        return v

    @field_validator("proxy_redirect_mode")
    def validate_proxy_redirect_mode(cls, v):
        normalized = v.strip().lower()
        if normalized not in PROXY_REDIRECT_MODES:
            raise ValueError("proxy_redirect_mode must be one of default/off/rewrite_to_public_host")
        return normalized

    @field_validator("waf_decision_mode")
    def validate_waf_decision_mode(cls, v):
        normalized = v.strip().lower()
        if normalized not in WAF_DECISION_MODES:
            raise ValueError("waf_decision_mode must be one of fail_open/fail_close")
        return normalized

    @field_validator("upstream_tls_server_name_override")
    def validate_upstream_tls_server_name_override(cls, v):
        if v is None:
            return None
        if not v.strip():
            return None

        candidate = v.strip().lower()
        parsed = urlsplit(f"https://{candidate}")
        if not parsed.hostname:
            raise ValueError("upstream_tls_server_name_override is invalid")
        return parsed.hostname

    @model_validator(mode="after")
    def validate_tls_fields(self):
        if self.http_redirect_to_https and not self.tls_enabled:
            raise ValueError("http_redirect_to_https requires tls_enabled=true")
        if self.hsts_enabled and not self.tls_enabled:
            raise ValueError("hsts_enabled requires tls_enabled=true")
        if self.tls_certificate_id is not None and self.tls_certificate_id < 1:
            raise ValueError("tls_certificate_id must be a positive integer")
        return self

class SiteCreate(SiteBase):
    pass

class Site(SiteBase):
    id: int
    health_status: Optional[str] = None
    resolved_upstream_ips: Optional[list[str]] = None
    last_resolved_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class CertificateOut(BaseModel):
    id: int
    name: str
    is_default: bool
    has_chain: bool = False
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class UpstreamPolicyBase(BaseModel):
    allow_private_upstreams: bool = False
    allowed_private_cidrs: Optional[str] = None
    denied_cidrs: Optional[str] = None
    allowed_upstream_ports: Optional[str] = None
    denied_hostnames: Optional[str] = None
    allowed_hostname_suffixes: Optional[str] = None


class UpstreamPolicyUpdate(UpstreamPolicyBase):
    pass


class UpstreamPolicyOut(UpstreamPolicyBase):
    id: int
    updated_by_user_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AuditLogOut(BaseModel):
    id: int
    actor_user_id: Optional[int] = None
    actor_username: Optional[str] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    before_json: Optional[dict] = None
    after_json: Optional[dict] = None
    success: bool
    error_message: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class OutboundProxyProfileBase(BaseModel):
    name: str
    listen_port: int = 3128
    is_enabled: bool = False
    require_auth: bool = False
    allow_connect_ports: str = "443,563"
    allowed_client_cidrs: Optional[str] = None
    default_action: str = "deny"
    block_private_destinations: bool = True

    @field_validator("name")
    def validate_name(cls, v):
        value = v.strip()
        if not value:
            raise ValueError("Profile name cannot be empty")
        if len(value) > 128:
            raise ValueError("Profile name is too long")
        return value

    @field_validator("listen_port")
    def validate_listen_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError("listen_port must be between 1 and 65535")
        return v

    @field_validator("allow_connect_ports")
    def validate_allow_connect_ports(cls, v):
        raw = v.strip()
        if not raw:
            raise ValueError("allow_connect_ports cannot be empty")
        normalized_ports: list[str] = []
        for token in raw.split(","):
            candidate = token.strip()
            if not candidate:
                continue
            port = int(candidate)
            if port < 1 or port > 65535:
                raise ValueError("CONNECT port must be between 1 and 65535")
            normalized_ports.append(str(port))
        if not normalized_ports:
            raise ValueError("allow_connect_ports must include at least one port")
        deduplicated = sorted(set(normalized_ports), key=int)
        return ",".join(deduplicated)

    @field_validator("allowed_client_cidrs")
    def validate_allowed_client_cidrs(cls, v):
        if v is None:
            return None
        raw = v.strip()
        if not raw:
            return None

        normalized: list[str] = []
        for token in raw.split(","):
            candidate = token.strip()
            if not candidate:
                continue
            network = ipaddress.ip_network(candidate, strict=False)
            normalized.append(str(network))
        if not normalized:
            return None
        return ",".join(sorted(set(normalized)))

    @field_validator("default_action")
    def validate_default_action(cls, v):
        normalized = v.strip().lower()
        if normalized not in FORWARD_PROXY_DEFAULT_ACTIONS:
            raise ValueError("default_action must be allow or deny")
        return normalized

    @field_validator("require_auth")
    def validate_require_auth(cls, v):
        if v:
            raise ValueError("require_auth=true is not supported in phase-9a")
        return v


class OutboundProxyProfileCreate(OutboundProxyProfileBase):
    pass


class OutboundProxyProfileUpdate(OutboundProxyProfileBase):
    pass


class OutboundProxyProfileOut(OutboundProxyProfileBase):
    id: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class OutboundDestinationRuleBase(BaseModel):
    action: str
    rule_type: str
    value: str
    priority: int = 100
    is_enabled: bool = True

    @field_validator("action")
    def validate_rule_action(cls, v):
        normalized = v.strip().lower()
        if normalized not in FORWARD_PROXY_RULE_ACTIONS:
            raise ValueError("action must be allow or deny")
        return normalized

    @field_validator("rule_type")
    def validate_rule_type(cls, v):
        normalized = v.strip().lower()
        if normalized not in FORWARD_PROXY_RULE_TYPES:
            raise ValueError("rule_type must be one of domain_exact/domain_suffix/host_exact/cidr/port")
        return normalized

    @field_validator("value")
    def validate_rule_value_non_empty(cls, v):
        value = v.strip()
        if not value:
            raise ValueError("Rule value cannot be empty")
        return value

    @field_validator("priority")
    def validate_priority(cls, v):
        if v < 0 or v > 1_000_000:
            raise ValueError("priority must be between 0 and 1000000")
        return v

    @model_validator(mode="after")
    def validate_rule_value_by_type(self):
        value = self.value.strip()
        if self.rule_type == "domain_exact":
            normalized = value.lower().rstrip(".")
            if not HOSTNAME_RE.match(normalized):
                raise ValueError("domain_exact contains invalid characters")
            self.value = normalized
        elif self.rule_type == "domain_suffix":
            normalized = value.lower().lstrip(".").rstrip(".")
            if not HOSTNAME_RE.match(normalized):
                raise ValueError("domain_suffix contains invalid characters")
            self.value = f".{normalized}"
        elif self.rule_type == "host_exact":
            normalized = value.lower().rstrip(".")
            try:
                parsed_ip = ipaddress.ip_address(normalized)
                self.value = str(parsed_ip)
            except ValueError:
                if not HOSTNAME_RE.match(normalized):
                    raise ValueError("host_exact must be a valid hostname or IP")
                self.value = normalized
        elif self.rule_type == "cidr":
            self.value = str(ipaddress.ip_network(value, strict=False))
        elif self.rule_type == "port":
            port = int(value)
            if port < 1 or port > 65535:
                raise ValueError("port rule value must be between 1 and 65535")
            self.value = str(port)
        return self


class OutboundDestinationRuleCreate(OutboundDestinationRuleBase):
    pass


class OutboundDestinationRuleUpdate(OutboundDestinationRuleBase):
    pass


class OutboundDestinationRuleOut(OutboundDestinationRuleBase):
    id: int
    profile_id: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ForwardProxyStatusOut(BaseModel):
    active_profile_id: Optional[int] = None
    active_profile_name: Optional[str] = None
    active_rule_count: int = 0
    config_path: str
    validation: dict[str, object]


# --- Malicious Pattern Schemas ---
class MaliciousPatternBase(BaseModel):
    pattern: str
    type: str
    description: Optional[str] = None

class MaliciousPatternCreate(MaliciousPatternBase):
    pass

class MaliciousPatternUpdate(BaseModel):
    pattern: Optional[str] = None
    type: Optional[str] = None
    description: Optional[str] = None

class MaliciousPatternOut(MaliciousPatternBase):
    id: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class PatternPage(BaseModel):
    items: List[MaliciousPatternOut]
    total: int

# --- IP Management Schemas ---
class BannedIP(BaseModel):
    ip: str
    banned_at: Optional[datetime] = None

class CleanIP(BaseModel):
    ip: str
    added_at: Optional[datetime] = None
