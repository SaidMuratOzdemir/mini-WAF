from __future__ import annotations

import os
import sys
import time

import httpx


ENDPOINTS = {
    "validate": "/validate",
    "reload": "/reload",
}

# ── Phase 9A.1-E: Retry with exponential backoff ────────────────────
MAX_RETRIES = int(os.getenv("CONTROL_CLIENT_MAX_RETRIES", "3"))
BACKOFF_BASE = float(os.getenv("CONTROL_CLIENT_BACKOFF_BASE", "1.0"))


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ENDPOINTS:
        sys.stderr.write("Usage: forward_proxy_control_client.py [validate|reload]\n")
        return 2

    action = sys.argv[1]
    base_url = os.getenv("FORWARD_PROXY_CONTROL_BASE_URL", "http://forward-proxy-control:8082").rstrip("/")
    control_token = os.getenv("FORWARD_PROXY_CONTROL_TOKEN", "").strip()
    if not control_token:
        sys.stderr.write("FORWARD_PROXY_CONTROL_TOKEN is not configured.\n")
        return 1

    url = f"{base_url}{ENDPOINTS[action]}"

    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(url, headers={"X-Forward-Proxy-Control-Token": control_token})
            output = response.text.strip()
            if output:
                print(output)
            if response.status_code == 429:
                # Cooldown active — retry after backoff
                wait = BACKOFF_BASE * (2 ** (attempt - 1))
                sys.stderr.write(f"Forward proxy control cooldown (429), retry {attempt}/{MAX_RETRIES} in {wait:.1f}s\n")
                time.sleep(wait)
                continue
            return 0 if response.status_code < 400 else 1
        except Exception as exc:
            last_exc = exc
            if attempt < MAX_RETRIES:
                wait = BACKOFF_BASE * (2 ** (attempt - 1))
                sys.stderr.write(f"Forward proxy control call failed (attempt {attempt}/{MAX_RETRIES}): {exc}, retrying in {wait:.1f}s\n")
                time.sleep(wait)
            else:
                sys.stderr.write(f"Forward proxy control call failed after {MAX_RETRIES} attempts: {last_exc}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
