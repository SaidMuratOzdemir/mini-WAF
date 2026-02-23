# api/app/schemas.py

from __future__ import annotations
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from typing import Optional, List
from datetime import datetime
from urllib.parse import urlsplit

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
    body_inspection_profile: str = "default"
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
        return v.strip()

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
    model_config = ConfigDict(from_attributes=True)


class CertificateOut(BaseModel):
    id: int
    name: str
    is_default: bool
    has_chain: bool = False
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

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
