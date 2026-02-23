from __future__ import annotations

import os
import sys

import httpx


ENDPOINTS = {
    "validate": "/validate",
    "reload": "/reload",
}


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

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(url, headers={"X-Forward-Proxy-Control-Token": control_token})
        output = response.text.strip()
        if output:
            print(output)
        return 0 if response.status_code < 400 else 1
    except Exception as exc:
        sys.stderr.write(f"Forward proxy control call failed: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
