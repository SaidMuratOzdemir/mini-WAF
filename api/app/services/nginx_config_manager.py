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

    def _template_context(self, site) -> dict[str, object]:
        parsed_url = urlsplit(site.upstream_url)
        return {
            "site_host": site.host,
            "upstream_url": site.upstream_url,
            "preserve_host_header": bool(site.preserve_host_header),
            "upstream_host_header": self._format_upstream_host_header(parsed_url),
            "is_https_upstream": parsed_url.scheme == "https",
            "enable_sni": bool(site.enable_sni),
            "upstream_ssl_name": parsed_url.hostname or "",
            "websocket_enabled": bool(site.websocket_enabled),
        }

    def _site_config_candidates(self, site_id: int) -> Iterable[Path]:
        pattern = f"*-site-{site_id}-*.conf"
        return sorted(self.generated_config_dir.glob(pattern))

    def render_site_config(self, site) -> str:
        template = self._jinja.get_template(self.template_path.name)
        rendered = template.render(**self._template_context(site))
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

    def write_site_config_atomic(self, site) -> Path:
        if not getattr(site, "id", None):
            raise ValueError("Site must have an id before config generation.")

        target_path = self.get_site_config_path(site)
        config_content = self.render_site_config(site)

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

    def sync_site_config(self, site, operation: str) -> dict[str, object]:
        operation = operation.lower()
        if operation not in {"create", "update", "delete"}:
            raise ValueError(f"Unsupported sync operation: {operation}")

        if operation == "delete":
            removed = self.delete_site_config(site)
            return {"operation": operation, "removed": [str(path) for path in removed]}

        if not getattr(site, "is_active", True):
            removed = self.delete_site_config(site)
            return {"operation": operation, "removed": [str(path) for path in removed], "inactive": True}

        written_path = self.write_site_config_atomic(site)
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

    def apply_with_rollback(self, site, operation: str) -> dict[str, object]:
        site_id = getattr(site, "id", None)
        if not site_id:
            raise ValueError("Site must have an id before apply_with_rollback.")

        before_state = self._capture_site_state(site_id)
        sync_result: dict[str, object] | None = None

        try:
            sync_result = self.sync_site_config(site, operation)
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
