from __future__ import annotations

import ipaddress
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from jinja2 import Environment, FileSystemLoader, StrictUndefined


DEFAULT_FORWARD_PROXY_PORT = 3128


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


class ForwardProxyConfigApplyError(RuntimeError):
    def __init__(self, detail: str, diagnostics: dict[str, object]):
        super().__init__(detail)
        self.detail = detail
        self.diagnostics = diagnostics


class ForwardProxyConfigManager:
    def __init__(
        self,
        generated_config_path: str | Path | None = None,
        template_path: str | Path | None = None,
        validate_command: Sequence[str] | None = None,
        reload_command: Sequence[str] | None = None,
        command_timeout_seconds: int = 15,
    ) -> None:
        default_template = Path(__file__).resolve().parents[1] / "templates" / "forward_proxy" / "squid.conf.j2"
        self.generated_config_path = Path(
            generated_config_path
            or os.getenv("FORWARD_PROXY_GENERATED_CONFIG_PATH", "/tmp/waf-forward-proxy/generated/squid.conf")
        )
        self.template_path = Path(template_path or default_template)
        self.validate_command = list(
            validate_command or self._read_command_from_env("FORWARD_PROXY_TEST_COMMAND", "true")
        )
        self.reload_command = list(
            reload_command or self._read_command_from_env("FORWARD_PROXY_RELOAD_COMMAND", "true")
        )
        self.command_timeout_seconds = int(
            os.getenv("FORWARD_PROXY_COMMAND_TIMEOUT_SECONDS", str(command_timeout_seconds))
        )

        self.generated_config_path.parent.mkdir(parents=True, exist_ok=True)
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
    def _normalize_connect_ports(raw_value: str | None) -> list[int]:
        if not raw_value or not raw_value.strip():
            return [443, 563]

        ports: list[int] = []
        for token in raw_value.split(","):
            candidate = token.strip()
            if not candidate:
                continue
            port = int(candidate)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid CONNECT port: {candidate}")
            ports.append(port)

        deduplicated = sorted(set(ports))
        return deduplicated or [443, 563]

    @staticmethod
    def _normalize_client_cidrs(raw_value: str | None) -> list[str]:
        if not raw_value or not raw_value.strip():
            return []

        cidrs: list[str] = []
        for token in raw_value.split(","):
            candidate = token.strip()
            if not candidate:
                continue
            network = ipaddress.ip_network(candidate, strict=False)
            cidrs.append(str(network))

        deduplicated = sorted(set(cidrs))
        return deduplicated

    @staticmethod
    def _normalize_domain(value: str) -> str:
        candidate = value.strip().lower().rstrip(".")
        if not candidate:
            raise ValueError("Domain value cannot be empty.")
        allowed = re.compile(r"^[a-z0-9.-]+$")
        if not allowed.match(candidate):
            raise ValueError(f"Domain contains invalid characters: {value}")
        return candidate

    @classmethod
    def _rule_to_acl(cls, rule, index: int) -> dict[str, object]:
        action = str(rule.action).strip().lower()
        rule_type = str(rule.rule_type).strip().lower()
        value = str(rule.value).strip()
        priority = int(getattr(rule, "priority", 0))

        acl_name = f"rule_{index}"

        if rule_type == "domain_exact":
            acl_type = "dstdomain"
            acl_value = cls._normalize_domain(value)
        elif rule_type == "domain_suffix":
            acl_type = "dstdomain"
            normalized = cls._normalize_domain(value)
            acl_value = normalized if normalized.startswith(".") else f".{normalized}"
        elif rule_type == "host_exact":
            try:
                parsed_ip = ipaddress.ip_address(value)
                acl_type = "dst"
                acl_value = str(parsed_ip)
            except ValueError:
                acl_type = "dstdomain"
                acl_value = cls._normalize_domain(value)
        elif rule_type == "cidr":
            acl_type = "dst"
            acl_value = str(ipaddress.ip_network(value, strict=False))
        elif rule_type == "port":
            acl_type = "port"
            port = int(value)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port rule value: {value}")
            acl_value = str(port)
        else:
            raise ValueError(f"Unsupported rule_type: {rule_type}")

        if action not in {"allow", "deny"}:
            raise ValueError(f"Unsupported rule action: {action}")

        return {
            "acl_name": acl_name,
            "acl_type": acl_type,
            "value": acl_value,
            "action": action,
            "priority": priority,
        }

    def _template_context(self, profile, rules: Sequence[object] | None) -> dict[str, object]:
        if profile is None:
            return {
                "listen_port": DEFAULT_FORWARD_PROXY_PORT,
                "connect_ports": [443, 563],
                "client_cidrs": [],
                "deny_rules": [],
                "allow_rules": [],
                "default_action": "deny",
            }

        compiled_rules: list[dict[str, object]] = []
        sorted_rules = sorted(rules or [], key=lambda item: (int(getattr(item, "priority", 0)), int(getattr(item, "id", 0))))
        for index, rule in enumerate(sorted_rules, start=1):
            compiled_rules.append(self._rule_to_acl(rule, index))

        deny_rules = sorted(
            (rule for rule in compiled_rules if rule["action"] == "deny"),
            key=lambda item: (int(item["priority"]), item["acl_name"]),
        )
        allow_rules = sorted(
            (rule for rule in compiled_rules if rule["action"] == "allow"),
            key=lambda item: (int(item["priority"]), item["acl_name"]),
        )

        default_action = str(getattr(profile, "default_action", "deny")).strip().lower()
        if default_action not in {"allow", "deny"}:
            default_action = "deny"

        listen_port = int(getattr(profile, "listen_port", DEFAULT_FORWARD_PROXY_PORT) or DEFAULT_FORWARD_PROXY_PORT)
        if listen_port < 1 or listen_port > 65535:
            raise ValueError(f"Invalid listen_port value: {listen_port}")

        return {
            "listen_port": listen_port,
            "connect_ports": self._normalize_connect_ports(getattr(profile, "allow_connect_ports", None)),
            "client_cidrs": self._normalize_client_cidrs(getattr(profile, "allowed_client_cidrs", None)),
            "deny_rules": deny_rules,
            "allow_rules": allow_rules,
            "default_action": default_action,
        }

    def render_proxy_config(self, profile, rules: Sequence[object] | None = None) -> str:
        template = self._jinja.get_template(self.template_path.name)
        rendered = template.render(**self._template_context(profile, rules))
        return rendered.strip() + "\n"

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

    def write_config_atomic(self, profile, rules: Sequence[object] | None = None) -> Path:
        config_content = self.render_proxy_config(profile, rules)
        self._write_file_atomic(self.generated_config_path, config_content.encode("utf-8"))
        return self.generated_config_path

    def sync_proxy_config(self, profile, rules: Sequence[object] | None = None) -> dict[str, object]:
        written_path = self.write_config_atomic(profile, rules)
        return {
            "written": str(written_path),
            "profile_id": getattr(profile, "id", None),
            "rule_count": len(rules or []),
        }

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
            command=command_list,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def validate_proxy_config(self) -> CommandResult:
        return self._run_command(self.validate_command)

    def reload_proxy(self) -> CommandResult:
        return self._run_command(self.reload_command)

    def _capture_state(self) -> bytes | None:
        if not self.generated_config_path.exists():
            return None
        return self.generated_config_path.read_bytes()

    def _restore_state(self, snapshot: bytes | None) -> None:
        if snapshot is None:
            self.generated_config_path.unlink(missing_ok=True)
            return
        self._write_file_atomic(self.generated_config_path, snapshot)

    def apply_with_rollback(self, profile, rules: Sequence[object] | None = None) -> dict[str, object]:
        before_state = self._capture_state()
        sync_result: dict[str, object] | None = None

        try:
            sync_result = self.sync_proxy_config(profile, rules)

            validate_result = self.validate_proxy_config()
            if not validate_result.ok:
                self._restore_state(before_state)
                rollback_validate = self.validate_proxy_config()
                raise ForwardProxyConfigApplyError(
                    "Forward proxy config validation failed; reverted config changes.",
                    {
                        "stage": "validate",
                        "sync_result": sync_result,
                        "validate": validate_result.as_dict(),
                        "rollback_validate": rollback_validate.as_dict(),
                    },
                )

            reload_result = self.reload_proxy()
            if not reload_result.ok:
                self._restore_state(before_state)
                rollback_validate = self.validate_proxy_config()
                rollback_reload = self.reload_proxy() if rollback_validate.ok else None
                raise ForwardProxyConfigApplyError(
                    "Forward proxy reload failed; reverted config changes.",
                    {
                        "stage": "reload",
                        "sync_result": sync_result,
                        "validate": validate_result.as_dict(),
                        "reload": reload_result.as_dict(),
                        "rollback_validate": rollback_validate.as_dict(),
                        "rollback_reload": rollback_reload.as_dict() if rollback_reload else None,
                    },
                )

            return {
                "sync_result": sync_result,
                "validate": validate_result.as_dict(),
                "reload": reload_result.as_dict(),
            }
        except ForwardProxyConfigApplyError:
            raise
        except Exception as exc:
            self._restore_state(before_state)
            rollback_validate = self.validate_proxy_config()
            raise ForwardProxyConfigApplyError(
                "Failed to apply forward proxy config; reverted changes.",
                {
                    "stage": "apply",
                    "sync_result": sync_result,
                    "exception": str(exc),
                    "rollback_validate": rollback_validate.as_dict(),
                },
            ) from exc
