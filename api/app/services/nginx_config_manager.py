from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined


SAFE_FILENAME_RE = re.compile(r"[^a-z0-9]+")
DEFAULT_SITE_ORDER = 120
BODY_PROFILE_DEFAULTS: dict[str, dict[str, object]] = {
    "strict": {
        "waf_forward_body": True,
        "client_max_body_size_mb": 1,
        "proxy_request_buffering": True,
    },
    "default": {
        "waf_forward_body": True,
        "client_max_body_size_mb": 5,
        "proxy_request_buffering": True,
    },
    "headers_only": {
        "waf_forward_body": False,
        "client_max_body_size_mb": 10,
        "proxy_request_buffering": True,
    },
    "upload_friendly": {
        "waf_forward_body": False,
        "client_max_body_size_mb": 100,
        "proxy_request_buffering": False,
    },
    "custom": {
        "waf_forward_body": True,
        "client_max_body_size_mb": 5,
        "proxy_request_buffering": True,
    },
}


@dataclass(slots=True)
class CommandResult:
    ok: bool
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class NginxConfigApplyError(RuntimeError):
    def __init__(self, detail: str, diagnostics: dict[str, object]):
        super().__init__(detail)
        self.detail = detail
        self.diagnostics = diagnostics


class NginxConfigManager:
    def __init__(
        self,
        generated_config_dir: str | Path | None = None,
        template_path: str | Path | None = None,
        site_order: int = DEFAULT_SITE_ORDER,
        validate_command: Sequence[str] | None = None,
        reload_command: Sequence[str] | None = None,
        command_timeout_seconds: int = 15,
    ) -> None:
        default_template = Path(__file__).resolve().parents[1] / "templates" / "nginx" / "site.conf.j2"
        self.generated_config_dir = Path(
            generated_config_dir
            or os.getenv("NGINX_GENERATED_CONFIG_DIR", "/tmp/waf-nginx/generated")
        )
        self.template_path = Path(template_path or default_template)
        self.site_order = site_order
        self.validate_command = list(validate_command or self._read_command_from_env("NGINX_TEST_COMMAND", "/bin/true"))
        self.reload_command = list(reload_command or self._read_command_from_env("NGINX_RELOAD_COMMAND", "/bin/true"))
        self.command_timeout_seconds = int(os.getenv("NGINX_COMMAND_TIMEOUT_SECONDS", str(command_timeout_seconds)))
        self.upstream_ca_bundle_path = os.getenv(
            "NGINX_UPSTREAM_CA_BUNDLE_PATH",
            "/etc/ssl/certs/ca-certificates.crt",
        )

        self.generated_config_dir.mkdir(parents=True, exist_ok=True)

        self._jinja = Environment(
            loader=FileSystemLoader(str(self.template_path.parent)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
            undefined=StrictUndefined,
        )

    @staticmethod
    def _read_command_from_env(env_key: str, fallback: str) -> list[str]:
        raw_value = os.getenv(env_key, fallback).strip()
        command = shlex.split(raw_value)
        if not command:
            raise ValueError(f"{env_key} cannot be empty.")
        return command

    @staticmethod
    def _sanitize_host_for_filename(host: str, site_id: int) -> str:
        safe = SAFE_FILENAME_RE.sub("-", host.strip().lower()).strip("-")
        if safe:
            return safe
        return f"site-{site_id}"

    @staticmethod
    def _format_upstream_host_header(parsed_url) -> str:
        hostname = parsed_url.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        if not parsed_url.port:
            return hostname

        is_default_http = parsed_url.scheme == "http" and parsed_url.port == 80
        is_default_https = parsed_url.scheme == "https" and parsed_url.port == 443
        if is_default_http or is_default_https:
            return hostname
        return f"{hostname}:{parsed_url.port}"

    @staticmethod
    def _normalize_upstream_ssl_name(value: str | None) -> str | None:
        if not value:
            return None
        if value.startswith("[") and value.endswith("]"):
            return value[1:-1]
        return value

    def _validate_tls_certificate_assets(self, certificate) -> None:
        cert_path = Path(certificate.cert_pem_path)
        key_path = Path(certificate.key_pem_path)
        chain_path = Path(certificate.chain_pem_path) if certificate.chain_pem_path else None

        if not cert_path.is_file():
            raise ValueError(f"TLS certificate file not found: {cert_path}")
        if not key_path.is_file():
            raise ValueError(f"TLS private key file not found: {key_path}")
        if chain_path and not chain_path.is_file():
            raise ValueError(f"TLS certificate chain file not found: {chain_path}")

    def _template_context(self, site, certificate=None) -> dict[str, object]:
        parsed_url = urlsplit(site.upstream_url)
        tls_enabled = bool(getattr(site, "tls_enabled", False))
        if tls_enabled and not certificate:
            raise ValueError("TLS is enabled for site but no certificate was provided.")
        if tls_enabled and certificate:
            self._validate_tls_certificate_assets(certificate)

        upstream_override = self._normalize_upstream_ssl_name(
            getattr(site, "upstream_tls_server_name_override", None)
        )
        upstream_ssl_name = upstream_override or (parsed_url.hostname or "")
        body_profile = str(getattr(site, "body_inspection_profile", "default") or "default").strip().lower()
        if body_profile not in BODY_PROFILE_DEFAULTS:
            body_profile = "default"
        profile_defaults = BODY_PROFILE_DEFAULTS[body_profile]

        configured_body_mb = getattr(site, "client_max_body_size_mb", None)
        if configured_body_mb is None:
            client_max_body_size_mb = int(profile_defaults["client_max_body_size_mb"])
        else:
            client_max_body_size_mb = max(1, int(configured_body_mb))

        configured_request_buffering = getattr(site, "proxy_request_buffering", None)
        if configured_request_buffering is None:
            proxy_request_buffering = bool(profile_defaults["proxy_request_buffering"])
        else:
            proxy_request_buffering = bool(configured_request_buffering)

        proxy_read_timeout_sec = max(1, int(getattr(site, "proxy_read_timeout_sec", 60) or 60))
        proxy_send_timeout_sec = max(1, int(getattr(site, "proxy_send_timeout_sec", 60) or 60))
        proxy_connect_timeout_sec = max(1, int(getattr(site, "proxy_connect_timeout_sec", 10) or 10))

        proxy_redirect_mode = str(getattr(site, "proxy_redirect_mode", "default") or "default").strip().lower()
        if proxy_redirect_mode not in {"default", "off", "rewrite_to_public_host"}:
            proxy_redirect_mode = "default"

        waf_decision_mode = str(getattr(site, "waf_decision_mode", "fail_close") or "fail_close").strip().lower()
        if waf_decision_mode not in {"fail_open", "fail_close"}:
            waf_decision_mode = "fail_close"

        return {
            "site_host": site.host,
            "upstream_url": site.upstream_url,
            "preserve_host_header": bool(site.preserve_host_header),
            "upstream_host_header": self._format_upstream_host_header(parsed_url),
            "is_https_upstream": parsed_url.scheme == "https",
            "enable_sni": bool(site.enable_sni),
            "upstream_ssl_name": upstream_ssl_name,
            "upstream_tls_verify": bool(getattr(site, "upstream_tls_verify", True)),
            "upstream_ca_bundle_path": self.upstream_ca_bundle_path,
            "websocket_enabled": bool(site.websocket_enabled),
            "sse_enabled": bool(getattr(site, "sse_enabled", False)),
            "tls_enabled": tls_enabled,
            "http_redirect_to_https": bool(getattr(site, "http_redirect_to_https", False)),
            "hsts_enabled": bool(getattr(site, "hsts_enabled", False)),
            "body_inspection_profile": body_profile,
            "waf_forward_body": bool(profile_defaults["waf_forward_body"]),
            "client_max_body_size_mb": client_max_body_size_mb,
            "proxy_request_buffering": proxy_request_buffering,
            "proxy_read_timeout_sec": proxy_read_timeout_sec,
            "proxy_send_timeout_sec": proxy_send_timeout_sec,
            "proxy_connect_timeout_sec": proxy_connect_timeout_sec,
            "proxy_redirect_mode": proxy_redirect_mode,
            "cookie_rewrite_enabled": bool(getattr(site, "cookie_rewrite_enabled", False)),
            "waf_fail_open": waf_decision_mode == "fail_open",
            "tls_cert_path": certificate.cert_pem_path if certificate else "",
            "tls_key_path": certificate.key_pem_path if certificate else "",
            "tls_chain_path": certificate.chain_pem_path if certificate else None,
        }

    def _site_config_candidates(self, site_id: int) -> Iterable[Path]:
        pattern = f"*-site-{site_id}-*.conf"
        return sorted(self.generated_config_dir.glob(pattern))

    def render_site_config(self, site, certificate=None) -> str:
        template = self._jinja.get_template(self.template_path.name)
        rendered = template.render(**self._template_context(site, certificate))
        return rendered.strip() + "\n"

    def get_site_config_path(self, site) -> Path:
        safe_host = self._sanitize_host_for_filename(site.host, site.id)
        filename = f"{self.site_order}-site-{site.id}-{safe_host}.conf"
        return self.generated_config_dir / filename

    @staticmethod
    def _write_file_atomic(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            delete=False,
        ) as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            temp_path = Path(tmp_file.name)
        os.replace(temp_path, path)

    def write_site_config_atomic(self, site, certificate=None) -> Path:
        if not getattr(site, "id", None):
            raise ValueError("Site must have an id before config generation.")

        target_path = self.get_site_config_path(site)
        config_content = self.render_site_config(site, certificate)

        self._write_file_atomic(target_path, config_content.encode("utf-8"))
        self._cleanup_stale_site_configs(site.id, target_path)
        return target_path

    def _cleanup_stale_site_configs(self, site_id: int, keep_path: Path) -> None:
        for candidate in self._site_config_candidates(site_id):
            if candidate != keep_path:
                candidate.unlink(missing_ok=True)

    def delete_site_config(self, site) -> list[Path]:
        removed_paths: list[Path] = []
        for candidate in self._site_config_candidates(site.id):
            candidate.unlink(missing_ok=True)
            removed_paths.append(candidate)
        return removed_paths

    def sync_site_config(self, site, operation: str, certificate=None) -> dict[str, object]:
        operation = operation.lower()
        if operation not in {"create", "update", "delete"}:
            raise ValueError(f"Unsupported sync operation: {operation}")

        if operation == "delete":
            removed = self.delete_site_config(site)
            return {"operation": operation, "removed": [str(path) for path in removed]}

        if not getattr(site, "is_active", True):
            removed = self.delete_site_config(site)
            return {"operation": operation, "removed": [str(path) for path in removed], "inactive": True}

        written_path = self.write_site_config_atomic(site, certificate)
        return {"operation": operation, "written": str(written_path)}

    def _run_command(self, command: Sequence[str]) -> CommandResult:
        command_list = list(command)
        try:
            completed = subprocess.run(
                command_list,
                capture_output=True,
                text=True,
                timeout=self.command_timeout_seconds,
                check=False,
            )
            returncode = completed.returncode
            stdout = completed.stdout.strip()
            stderr = completed.stderr.strip()
        except FileNotFoundError as exc:
            returncode = 127
            stdout = ""
            stderr = str(exc)
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            stdout = (exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""
            stderr = f"Command timed out after {self.command_timeout_seconds}s"

        return CommandResult(
            ok=returncode == 0,
            command=list(command),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def validate_nginx_config(self) -> CommandResult:
        return self._run_command(self.validate_command)

    def reload_nginx(self) -> CommandResult:
        return self._run_command(self.reload_command)

    def _capture_site_state(self, site_id: int) -> dict[Path, bytes]:
        snapshot: dict[Path, bytes] = {}
        for path in self._site_config_candidates(site_id):
            snapshot[path] = path.read_bytes()
        return snapshot

    def _restore_site_state(self, site_id: int, snapshot: dict[Path, bytes]) -> None:
        for candidate in self._site_config_candidates(site_id):
            candidate.unlink(missing_ok=True)

        for path, content in snapshot.items():
            self._write_file_atomic(path, content)

    def apply_with_rollback(self, site, operation: str, certificate=None) -> dict[str, object]:
        site_id = getattr(site, "id", None)
        if not site_id:
            raise ValueError("Site must have an id before apply_with_rollback.")

        before_state = self._capture_site_state(site_id)
        sync_result: dict[str, object] | None = None

        try:
            sync_result = self.sync_site_config(site, operation, certificate)
            validate_result = self.validate_nginx_config()
            if not validate_result.ok:
                self._restore_site_state(site_id, before_state)
                rollback_validate_result = self.validate_nginx_config()
                raise NginxConfigApplyError(
                    "Nginx config validation failed; reverted site config changes.",
                    {
                        "stage": "validate",
                        "sync_result": sync_result,
                        "validate": validate_result.as_dict(),
                        "rollback_validate": rollback_validate_result.as_dict(),
                    },
                )

            reload_result = self.reload_nginx()
            if not reload_result.ok:
                self._restore_site_state(site_id, before_state)
                rollback_validate_result = self.validate_nginx_config()
                rollback_reload_result = self.reload_nginx() if rollback_validate_result.ok else None
                raise NginxConfigApplyError(
                    "Nginx reload failed; reverted site config changes.",
                    {
                        "stage": "reload",
                        "sync_result": sync_result,
                        "validate": validate_result.as_dict(),
                        "reload": reload_result.as_dict(),
                        "rollback_validate": rollback_validate_result.as_dict(),
                        "rollback_reload": rollback_reload_result.as_dict() if rollback_reload_result else None,
                    },
                )

            return {
                "sync_result": sync_result,
                "validate": validate_result.as_dict(),
                "reload": reload_result.as_dict(),
            }
        except NginxConfigApplyError:
            raise
        except Exception as exc:
            self._restore_site_state(site_id, before_state)
            rollback_validate_result = self.validate_nginx_config()
            raise NginxConfigApplyError(
                "Failed to apply Nginx site config; reverted changes.",
                {
                    "stage": "apply",
                    "sync_result": sync_result,
                    "exception": str(exc),
                    "rollback_validate": rollback_validate_result.as_dict(),
                },
            ) from exc
