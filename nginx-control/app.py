from __future__ import annotations

import subprocess
from typing import List

from fastapi import FastAPI, HTTPException


app = FastAPI(title="Nginx Control Helper", version="1.0.0")


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


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/validate")
def validate_nginx() -> dict[str, object]:
    return run_command(["nginx", "-t", "-c", "/etc/nginx/nginx.conf"])


@app.post("/reload")
def reload_nginx() -> dict[str, object]:
    validate_result = run_command(["nginx", "-t", "-c", "/etc/nginx/nginx.conf"])
    reload_result = run_command(["nginx", "-s", "reload", "-c", "/etc/nginx/nginx.conf"])
    return {"validate": validate_result, "reload": reload_result}
