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
- `require_auth` (reserved; must remain `false` in 9A)
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
4. `require_auth` is not implemented in 9A; do not rely on it.
5. No payload inspection in CONNECT tunnel in this phase.

## Non-Goals in 9A

- TLS MITM / CA distribution
- Content-level inspection of HTTPS payload
- SSO/user auth integration
- URL categorization/malware scanning
