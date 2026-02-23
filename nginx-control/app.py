from __future__ import annotations

import hmac
import os
import subprocess
import time
from typing import List

from fastapi import FastAPI, Header, HTTPException, status


app = FastAPI(title="Nginx Control Helper", version="1.0.0")
CONTROL_TOKEN = os.getenv("NGINX_CONTROL_TOKEN", "").strip()
COOLDOWN_SECONDS = float(os.getenv("NGINX_CONTROL_COOLDOWN_SECONDS", "0"))
_last_reload_at = 0.0


def run_command(command: List[str]) -> dict[str, object]:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    result = {
        "ok": completed.returncode == 0,
        "command": command,
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "").strip(),
        "stderr": (completed.stderr or "").strip(),
    }
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result)
    return result


def require_control_token(x_nginx_control_token: str | None = Header(default=None)) -> None:
    if not CONTROL_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Control token is not configured.",
        )
    if not x_nginx_control_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing control token.")
    if not hmac.compare_digest(x_nginx_control_token, CONTROL_TOKEN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid control token.")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/validate")
def validate_nginx(x_nginx_control_token: str | None = Header(default=None)) -> dict[str, object]:
    require_control_token(x_nginx_control_token)
    return run_command(["nginx", "-t", "-c", "/etc/nginx/nginx.conf"])


@app.post("/reload")
def reload_nginx(x_nginx_control_token: str | None = Header(default=None)) -> dict[str, object]:
    global _last_reload_at
    require_control_token(x_nginx_control_token)

    now = time.monotonic()
    if COOLDOWN_SECONDS > 0 and (now - _last_reload_at < COOLDOWN_SECONDS):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Reload cooldown is active. Please retry shortly.",
        )

    validate_result = run_command(["nginx", "-t", "-c", "/etc/nginx/nginx.conf"])
    reload_result = run_command(["nginx", "-s", "reload", "-c", "/etc/nginx/nginx.conf"])
    _last_reload_at = now
    return {"validate": validate_result, "reload": reload_result}
