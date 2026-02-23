# ./api/app/models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now())


class Site(Base):
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    upstream_url = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    preserve_host_header = Column(Boolean, default=False, nullable=False)
    enable_sni = Column(Boolean, default=True, nullable=False)
    websocket_enabled = Column(Boolean, default=True, nullable=False)
    body_inspection_profile = Column(String, default="default", nullable=False)
    tls_enabled = Column(Boolean, default=False, nullable=False)
    http_redirect_to_https = Column(Boolean, default=False, nullable=False)
    tls_certificate_id = Column(Integer, ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True)
    upstream_tls_verify = Column(Boolean, default=True, nullable=False)
    upstream_tls_server_name_override = Column(String, nullable=True)
    hsts_enabled = Column(Boolean, default=False, nullable=False)
    xss_enabled = Column(Boolean, default=True)
    sql_enabled = Column(Boolean, default=True)
    vt_enabled = Column(Boolean, default=False)


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    cert_pem_path = Column(String, nullable=False)
    key_pem_path = Column(String, nullable=False)
    chain_pem_path = Column(String, nullable=True)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)


class MaliciousPattern(Base):
    __tablename__ = "malicious_patterns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    pattern = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    is_regex = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
