from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined


SAFE_FILENAME_RE = re.compile(r"[^a-z0-9]+")
DEFAULT_SITE_ORDER = 120


class NginxConfigManager:
    def __init__(
        self,
        generated_config_dir: str | Path | None = None,
        template_path: str | Path | None = None,
        site_order: int = DEFAULT_SITE_ORDER,
    ) -> None:
        default_template = Path(__file__).resolve().parents[1] / "templates" / "nginx" / "site.conf.j2"
        self.generated_config_dir = Path(
            generated_config_dir
            or os.getenv("NGINX_GENERATED_CONFIG_DIR", "/tmp/waf-nginx/generated")
        )
        self.template_path = Path(template_path or default_template)
        self.site_order = site_order

        self.generated_config_dir.mkdir(parents=True, exist_ok=True)

        self._jinja = Environment(
            loader=FileSystemLoader(str(self.template_path.parent)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
            undefined=StrictUndefined,
        )

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

    def write_site_config_atomic(self, site) -> Path:
        if not getattr(site, "id", None):
            raise ValueError("Site must have an id before config generation.")

        target_path = self.get_site_config_path(site)
        config_content = self.render_site_config(site)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self.generated_config_dir),
            prefix=f".{target_path.name}.",
            delete=False,
        ) as tmp_file:
            tmp_file.write(config_content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            temp_path = Path(tmp_file.name)

        os.replace(temp_path, target_path)
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
