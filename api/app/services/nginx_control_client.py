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
        sys.stderr.write("Usage: nginx_control_client.py [validate|reload]\n")
        return 2

    action = sys.argv[1]
    base_url = os.getenv("NGINX_CONTROL_BASE_URL", "http://nginx-control:8081").rstrip("/")
    url = f"{base_url}{ENDPOINTS[action]}"

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(url)
        output = response.text.strip()
        if output:
            print(output)
        return 0 if response.status_code < 400 else 1
    except Exception as exc:
        sys.stderr.write(f"Nginx control call failed: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
