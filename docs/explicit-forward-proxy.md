# Explicit Forward Proxy (Phase 9A)

This phase adds an explicit outbound proxy feature without changing reverse-proxy WAF behavior.

## Scope Summary

- Data plane: dedicated Squid container (`forward-proxy`), separate from Nginx reverse proxy.
- Control plane: Admin API + Admin UI manage outbound profiles and destination rules.
- Control bridge: `forward-proxy-control` helper validates and reloads Squid safely.
- TLS MITM is out of scope.
- CONNECT tunneling is supported.

## Reverse vs Forward Proxy

- Reverse proxy (existing): inbound app protection (`client -> nginx -> auth_request -> waf -> upstream`).
- Forward proxy (new): outbound internet access for proxy-configured clients (`client -> forward-proxy -> internet`).

These two planes are isolated; forward-proxy changes do not alter reverse-proxy WAF path.

## Browser / System Proxy Setup

Configure browser/system proxy to:

- HTTP proxy: `VM_IP:3128`
- HTTPS proxy: `VM_IP:3128` (CONNECT tunnel)

Quick smoke examples:

```bash
curl --proxy http://VM_IP:3128 http://example.com
curl --proxy http://VM_IP:3128 https://example.com
```

## Policy Model

### OutboundProxyProfile

- `name`
- `listen_port`
- `is_enabled`
- `require_auth` (enable Squid Basic Auth – requires at least one active proxy user)
- `auth_realm` (optional realm string shown in the 407 dialog, default `Outbound Proxy`)
- `allow_connect_ports` (CSV, e.g. `443,563`)
- `allowed_client_cidrs` (CSV allowlist)
- `default_action` (`allow` or `deny`)

Only one profile can be enabled at a time in Phase 9A.

### OutboundDestinationRule

- `action`: `allow` / `deny`
- `rule_type`: `domain_exact`, `domain_suffix`, `host_exact`, `cidr`, `port`
- `value`
- `priority`
- `is_enabled`

Rule evaluation order:

1. All deny rules (sorted by priority)
2. All allow rules (sorted by priority)
3. Profile `default_action`

This guarantees deny precedence over allow.

## CONNECT and Port Controls

- Squid enforces CONNECT method policy with `SSL_ports` from profile `allow_connect_ports`.
- CONNECT to disallowed ports (e.g. `:25`) is denied.
- General unsafe port requests are denied via `Safe_ports` ACL.

## Client CIDR Allowlist

If `allowed_client_cidrs` is set:

- Only clients in listed CIDRs can use proxy.
- Others are denied before destination rules.

If empty:

- Proxy accepts clients from all source IPs (high risk if internet-exposed).

## Basic Authentication (Phase 9A.2)

When `require_auth` is `true`, Squid requires HTTP Basic credentials via the `basic_ncsa_auth` helper.

### Enabling

1. Create at least one proxy user via the Admin API or Admin UI.
2. Set `require_auth = true` on the profile and apply.

The API will reject the apply if `require_auth` is `true` but no active users exist.

### Proxy User Management

- `POST /api/v1/forward-proxy/users` – create user (min 12-char password)
- `GET  /api/v1/forward-proxy/users` – list users
- `PUT  /api/v1/forward-proxy/users/{id}` – update password or toggle `is_active`
- `DELETE /api/v1/forward-proxy/users/{id}` – remove user

Usernames must match `[a-zA-Z0-9._@-]+` and are stored lowercase.
Passwords are bcrypt-hashed; plaintext is never persisted.

### Curl Examples

```bash
# With auth
curl --proxy http://VM_IP:3128 --proxy-user alice:S3cretP@ssw0rd http://example.com
curl --proxy http://VM_IP:3128 --proxy-user alice:S3cretP@ssw0rd https://example.com
```

Browsers configured with the proxy will show a native 407 authentication dialog.

### Security Warning

Basic Auth transmits credentials **base64-encoded (not encrypted)**.
If the client-to-proxy hop crosses an untrusted network, wrap it in a VPN or TLS tunnel.

## Logging

- Squid access logs: `/var/log/squid/access.log` (volume-backed).
- Log format includes timestamp, client IP, method, URL/target, status and bytes.
- Control-plane actions are written to API audit logs:
  - profile create/update/delete
  - rule create/update/delete
  - config apply success/failure

## Security Notes

1. Do not expose `3128` publicly without CIDR restrictions.
2. Prefer `default_action=deny` with explicit allow rules.
3. Keep `allow_connect_ports` limited (e.g. `443,563`).
4. When `require_auth` is enabled, ensure all proxy clients have valid credentials.
5. No payload inspection in CONNECT tunnel in this phase.

## Non-Goals in 9A

- TLS MITM / CA distribution
- Content-level inspection of HTTPS payload
- SSO / LDAP / external auth integration (only local ncsa_auth)
- URL categorization / malware scanning
