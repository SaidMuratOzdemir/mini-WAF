# Reverse Proxy WAF Appliance

This project now supports dynamic reverse-proxy site onboarding from Admin UI/API.

## Runtime Flow

When a site is created/updated/deleted:
1. Site config is validated (`host`, `upstream_url`, SSRF policy).
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

## Security Policy

- Allowed schemes: `http`, `https`
- Blocked by default: `localhost`, loopback (`127.0.0.0/8`, `::1`), metadata (`169.254.169.254`)
- Private IP policy is controlled by `ALLOW_PRIVATE_UPSTREAMS` (default `false`)
- Host/server_name validation rejects unsafe characters to prevent nginx config injection.
- DNS rebinding full mitigation is not in this phase (follow-up hardening required).

## Docker Wiring

- `nginx_generated_configs` named volume is shared:
  - API writes to `/shared/nginx/generated`
  - Nginx reads `/etc/nginx/conf.d/generated`
- `nginx-control` helper service validates and reloads nginx safely.
- API uses command client script:
  - `python /app/app/services/nginx_control_client.py validate`
  - `python /app/app/services/nginx_control_client.py reload`

## Deployment Notes (VM)

1. Point domain DNS A/AAAA to VM IP.
2. Open inbound `80` (and `443` when TLS termination is added).
3. Start stack: `docker compose up -d --build`.
4. Add sites from Admin UI (`/admin-ui/`) with host + upstream URL.
5. Set `ALLOW_PRIVATE_UPSTREAMS=true` only if private/LAN upstreams are required.

## Non-Goals (This Phase)

- Explicit forward proxy / CONNECT proxy
- TLS MITM / CA distribution
- Full DNS rebinding protection
- Response body inspection
