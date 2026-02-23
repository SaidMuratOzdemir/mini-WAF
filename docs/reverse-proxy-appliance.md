# Reverse Proxy WAF Appliance

This project now supports dynamic reverse-proxy site onboarding from Admin UI/API, including per-site TLS termination and control-plane hardening.

## Runtime Flow

When a site is created/updated/deleted:
1. Site config is validated (`host`, `upstream_url`, TLS and SSRF policy).
2. Site record is flushed in DB transaction scope.
3. Nginx per-site config is rendered to generated volume.
4. Nginx config validation (`nginx -t`) is triggered through `nginx-control` helper.
5. Nginx reload (`nginx -s reload`) is triggered on success.
6. On failure, generated config rollback is applied and DB transaction is rolled back.

Request path:
`client -> nginx -> auth_request(/auth-waf) -> waf -> upstream`

## Upstream URL Examples

- Docker internal service: `http://httpbin:8080`
- LAN/private target: `http://192.168.1.20:8080`
- Public HTTPS target: `https://httpbin.org`

## TLS / HTTPS

Site-level TLS options:
- `tls_enabled`
- `http_redirect_to_https`
- `tls_certificate_id` (or default certificate if empty)
- `upstream_tls_verify`
- `upstream_tls_server_name_override`
- `hsts_enabled`

Certificate management:
- Upload certificate PEM + private key PEM (optional chain PEM) from Admin UI.
- Files are stored under certificate storage volume (`/shared/certs` in containers).
- Private keys are written with strict file permissions.

HTTPS flow:
- HTTP `:80` can redirect to HTTPS if `http_redirect_to_https=true`.
- HTTPS `:443` terminates TLS in nginx and continues `auth_request` flow to WAF.
- Upstream HTTPS can enable/disable verify and override SNI name.

## Security Policy

- Allowed schemes: `http`, `https`
- Blocked by default: `localhost`, loopback (`127.0.0.0/8`, `::1`), metadata (`169.254.169.254`)
- Private IP policy is controlled by `ALLOW_PRIVATE_UPSTREAMS` (default `false`)
- Fine-grained upstream policy supports:
  - `ALLOWED_PRIVATE_CIDRS`
  - `DENIED_CIDRS` (always prioritized)
  - `ALLOWED_UPSTREAM_PORTS`
  - `DENIED_HOSTNAMES` (wildcard patterns)
  - `ALLOWED_HOSTNAME_SUFFIXES`
- Host/server_name validation rejects unsafe characters to prevent nginx config injection.
- DNS rebinding full mitigation is not in this phase (follow-up hardening required).

## RBAC

- `admin`
  - Site CRUD allowed.
  - Public upstreams allowed.
  - Private/LAN upstream targets are denied.
- `super_admin`
  - Site CRUD allowed, including private/LAN upstreams (policy permitting).
  - Certificate management allowed.
  - Upstream global policy updates allowed.
  - Audit log read access allowed.

## Audit Logging

Control-plane actions are persisted in `audit_logs`:
- Site create/update/delete
- Certificate create/update/delete
- Policy update / policy-driven site revalidation
- Failed apply operations and validation errors

Each entry stores actor, action, target, success/failure, request IP, and timestamp.

## nginx-control hardening

- API -> `nginx-control` calls require `X-Nginx-Control-Token`.
- Only fixed helper actions are supported:
  - `POST /validate` -> `nginx -t`
  - `POST /reload` -> `nginx -t` + `nginx -s reload`
- Command injection surface is minimized: no user-supplied shell command path/args.
- Reload cooldown (`NGINX_CONTROL_COOLDOWN_SECONDS`) can be enabled to mitigate rapid reload abuse (default `0`, disabled).
- `nginx-control` is attached to internal control network (`waf-control-net`) and is not published to host.

## Docker Wiring

- `nginx_generated_configs` named volume is shared:
  - API writes to `/shared/nginx/generated`
  - Nginx reads `/etc/nginx/conf.d/generated`
- `nginx_cert_store` named volume is shared:
  - API writes certificates to `/shared/certs`
  - Nginx and nginx-control read `/shared/certs` (read-only)
- `nginx-control` helper service validates and reloads nginx safely.
- API uses command client script:
  - `python /app/app/services/nginx_control_client.py validate`
  - `python /app/app/services/nginx_control_client.py reload`

## Deployment Notes (VM)

1. Point domain DNS A/AAAA to VM IP.
2. Open inbound `80` and `443`.
3. Start stack: `docker compose up -d --build`.
4. Upload certificate(s) from Admin UI (`/admin-ui/`), set default if desired.
5. Add sites with host + upstream URL + TLS options.
6. Enable HTTP->HTTPS redirect for production-facing domains.
7. Enable HSTS only after HTTPS behavior is validated for the domain.
8. Set `ALLOW_PRIVATE_UPSTREAMS=true` only if private/LAN upstreams are required.

## Environment Variables

- `ALLOW_PRIVATE_UPSTREAMS` (default `false`)
- `ALLOWED_PRIVATE_CIDRS` (CSV)
- `DENIED_CIDRS` (CSV, high priority deny list)
- `ALLOWED_UPSTREAM_PORTS` (CSV)
- `DENIED_HOSTNAMES` (CSV wildcard patterns)
- `ALLOWED_HOSTNAME_SUFFIXES` (CSV suffix list)
- `CERT_STORAGE_DIR` (default `/shared/certs`)
- `NGINX_GENERATED_CONFIG_DIR` (default `/shared/nginx/generated`)
- `NGINX_CONTROL_BASE_URL` (default `http://nginx-control:8081`)
- `NGINX_CONTROL_TOKEN` (required shared secret for API<->helper)
- `NGINX_CONTROL_COOLDOWN_SECONDS` (default `0`, set to `1`/`2` for cooldown)
- `NGINX_UPSTREAM_CA_BUNDLE_PATH` (default `/etc/ssl/certs/ca-certificates.crt`)

## Notes

- This phase does not implement automated ACME/Let's Encrypt provisioning.
- Certificate rotation automation and wildcard certificate automation are out of scope.
- DNS rebinding full mitigation remains a follow-up hardening task.
- This phase adds upstream IP snapshot (`resolved_upstream_ips`, `last_resolved_at`) and pre-apply revalidation.
- Optional periodic revalidation endpoint: `POST /api/v1/policies/upstream/revalidate-sites`.

## Non-Goals (This Phase)

- Explicit forward proxy / CONNECT proxy
- TLS MITM / CA distribution
- Full DNS rebinding protection
- Response body inspection
