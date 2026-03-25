# muWAF

**Web Application Firewall engine.** Pattern-based request inspection, IP ban/whitelist management, VirusTotal reputation — fully managed through a React admin dashboard.

---

## Responsibility

muWAF owns exactly three things:

1. **Request inspection** — pattern matching (XSS, SQLi, custom), VirusTotal IP reputation
2. **Threat state** — IP bans and whitelist stored in Redis with configurable TTL
3. **Security event logging** — full inspection results (decision, reason, matched pattern) stored in MongoDB

Traffic routing, TLS termination, and access logging are handled by [DiaLog](../diaLOG). muWAF integrates with it through a single interface — see [DIALOG_WAF_INTEGRATION.md](../diaLOG/DIALOG_WAF_INTEGRATION.md).

---

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │          Inspection Engine           │
                    │          FastAPI  :8000              │
  DiaLog ──POST────▶│  /inspect                           │
  (auth_request     │  ┌─────────────────────────────┐   │
   pattern)         │  │  1. Redis lookup (sync)      │   │
                    │  │     banned_ip: → 403         │   │
                    │  │     clean_ip:  → 200         │   │
                    │  │     unknown   → 200 + queue  │   │
                    │  └──────────────┬──────────────┘   │
                    └─────────────────┼──────────────────┘
                                      │ async workers
                    ┌─────────────────▼──────────────────┐
                    │         Deep Analysis               │
                    │  • Pattern matching (XSS/SQLi)      │
                    │  • Encoding bypass normalization     │
                    │  • VirusTotal IP reputation          │
                    │  • Ban decision → Redis SET          │
                    │  • Security event → MongoDB          │
                    └────────────────────────────────────┘

  [ Admin Web (React) ] → [ Admin API (FastAPI :8001) ] → Postgres / Redis / MongoDB
```

### Request Flow

1. A client request arrives at the edge proxy (DiaLog or Nginx).
2. The proxy calls `POST /inspect` on the WAF engine.
3. The WAF engine performs **synchronous fast checks** (Redis lookup, ≤1ms):
   - `banned_ip:{ip}` exists → returns `403 {"allowed":false,"reason":"SQL_IN_QUERY"}` → edge blocks the request.
   - `clean_ip:{ip}` exists → returns `200 {"allowed":true}` → edge forwards immediately.
   - Otherwise → returns `200 {"allowed":true}` (fail-open) and **queues** a job for deep analysis.
4. In the background, inspection workers run:
   - **Pattern analysis** — XSS and SQLi patterns with multi-layer encoding bypass detection (URL decode, HTML entity, Unicode normalisation, double-encoding)
   - **VirusTotal** — async IP reputation lookup (non-blocking, skipped if no API key)
   - **Decision** — if malicious: `SET banned_ip:{ip} {reason}` in Redis (default TTL: 1 hour); log full event to MongoDB
5. The next request from the same IP is blocked in step 3 without re-running analysis.

### Fail-Open by Design

The inspection engine always returns `200` for unknown IPs. If the engine is unreachable or times out, the edge proxy forwards the request normally. Traffic is never lost due to WAF availability. The cost is that the very first request from a malicious IP may slip through; it will be banned before the second.

---

## Repository Structure

```
WAF/
├── api/                     Admin API (FastAPI + SQLAlchemy)
│   ├── app/
│   │   ├── core/            settings, JWT security, dependencies
│   │   ├── models.py        SQLAlchemy models
│   │   ├── routers/         auth, sites, ips, patterns, logs, system, audits
│   │   └── main.py          FastAPI app entry
│   ├── alembic/             database migrations
│   └── Dockerfile
│
├── waf/                     Inspection Engine (FastAPI)
│   ├── app/server.py        /inspect endpoint, async worker queue, lifespan
│   ├── checks/
│   │   ├── inspection_policy.py   per-site toggle flags
│   │   ├── security_engine.py     analysis orchestrator
│   │   └── patterns/              cache, advanced analyzer, encoding decoders
│   ├── ip/                  ban_actions, banlist (Redis helpers), local IP detection
│   └── Dockerfile
│
├── web/                     Admin Web (React 18 + TypeScript + MUI)
│   ├── src/
│   │   ├── api/             typed fetch wrappers (auth, sites, ips, patterns, logs)
│   │   ├── components/      IP Mgmt, Patterns, Logs, Sites, VT Stats
│   │   ├── context/         Auth context (JWT lifecycle)
│   │   └── App.tsx          routes, layout, protected routes
│   └── Dockerfile
│
├── nginx/                   Nginx edge gateway (standalone mode)
├── nginx-control/           Nginx config reload helper
├── forward-proxy/           Outbound proxy (CONNECT)
├── forward-proxy-control/   Forward proxy control helper
├── docker-compose.yml       Full stack (standalone mode)
└── init-db.sql
```

---

## Data Models

| Model | Description |
|---|---|
| `User` | Admin dashboard accounts (username, bcrypt hash, role, is_active) |
| `Site` | Protected host entry with per-site inspection toggles (`xss_enabled`, `sql_enabled`, `vt_enabled`) |
| `MaliciousPattern` | Detection rule: `pattern`, `type` (XSS/SQL/CUSTOM), `is_regex`, `is_active`, `description` |
| `Certificate` | TLS certificate (PEM, expiry, is_default) |
| `OutboundProxy` | Forward proxy profile (auth, destination ACLs, inspection TTL) |
| `AuditLog` | Control-plane action history (user, action, status, timestamp) |

Models defined in `api/app/models.py`.

---

## Admin API

Base path: `/admin-api/v1/`
Authentication: `POST /auth/login` → JWT Bearer token

| Router | Key Endpoints | Description |
|---|---|---|
| `auth` | `POST /login`, `GET /me` | JWT authentication |
| `sites` | CRUD `/sites` | Protected host management with inspection toggles |
| `ips` | `GET /banned`, `GET /clean`, `POST /ban/{ip}`, `DELETE /unban/{ip}`, `POST /whitelist` | IP ban/whitelist |
| `patterns` | CRUD `/patterns`, `POST /patterns/bulk` | Detection rule management |
| `logs` | `GET /logs`, `GET /logs/stats` | MongoDB inspection log viewer |
| `system` | `GET /health`, `GET /vt-cache/stats` | Health and VirusTotal cache stats |
| `audits` | `GET /audits` | Control-plane audit trail |

OpenAPI docs available at `/admin-api/v1/docs` when running.

---

## Admin Web

React SPA served at `/admin-ui/`

| Page | Route | Purpose |
|---|---|---|
| Sites | `/sites` | Create/edit protected sites with inspection toggles |
| IP Management | `/ip-management` | View/ban/unban/whitelist IPs (live Redis state) |
| Patterns | `/patterns` | Create/edit detection rules, bulk import |
| Logs | `/logs` | MongoDB inspection log viewer with filtering |
| VirusTotal Stats | `/sites` (panel) | VT API cache metrics |

---

## Quickstart (standalone with Nginx)

```bash
# Prerequisites: Docker + Docker Compose

# 1. Create the shared network
docker network create waf-core-net

# 2. Create .env
cat > .env <<EOF
JWT_SECRET=$(openssl rand -hex 32)
VIRUSTOTAL_API_KEY=        # optional
POSTGRES_PASSWORD=changeme
EOF

# 3. Start the stack
docker compose up --build -d

# 4. Access
#    Admin UI:    http://localhost/admin-ui/
#    Admin API:   http://localhost/admin-api/v1/docs
#    WAF Engine:  http://localhost/health   (internal only in production)
```

---

## Integration with DiaLog

When used alongside DiaLog (recommended), muWAF's Nginx is **not** in the request path. DiaLog calls the WAF engine directly via `/inspect`.

muWAF's Nginx serves only the admin panel. All user traffic goes through DiaLog.

```
Internet → DiaLog :443 → (per-route) POST /inspect → muWAF engine :8000
                       →                             backend
```

See [DIALOG_WAF_INTEGRATION.md](../diaLOG/DIALOG_WAF_INTEGRATION.md) for the complete integration guide.

---

## Configuration

| Variable | Component | Description |
|---|---|---|
| `DATABASE_URL` | API | PostgreSQL connection string |
| `REDIS_URL` | WAF, API | Redis for ban/whitelist state |
| `MONGODB_URL` | WAF, API | MongoDB for inspection logs |
| `VIRUSTOTAL_API_KEY` | WAF | Optional — enables IP reputation checks |
| `JWT_SECRET` | API | JWT signing key |
| `BAN_TTL_SECONDS` | WAF | IP ban duration (default: `3600`) |
| `INSPECTION_QUEUE_SIZE` | WAF | Max queued async jobs (default: `5000`) |
| `INSPECTION_WORKERS` | WAF | Concurrent analysis workers (default: `8`) |
| `WAF_INSPECTION_TTL_DAYS` | WAF | MongoDB document TTL, `0` = unlimited (default: `30`) |
| `VT_TIMEOUT_SECONDS` | WAF | VirusTotal API call timeout (default: `8`) |
| `VT_CACHE_TTL_SECONDS` | WAF | Redis cache TTL for VirusTotal results, `0` = disabled (default: `3600`) |
| `WAF_BLOCK_RESPONSE_BODY` | WAF | Custom 403 response body; use `{reason}` as placeholder (default: JSON `{"allowed":false,"reason":"..."}`) |
| `WAF_BLOCK_RESPONSE_CONTENT_TYPE` | WAF | Content-Type for custom block response (default: `application/json`) |
| `ALLOW_PRIVATE_UPSTREAMS` | API | Allow RFC1918 upstream URLs (default: `false`) |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `/inspect` returns 500 | Check WAF engine logs: `docker compose logs waf` |
| No bans appearing | Confirm Redis is connected in `GET /health` response |
| MongoDB logs empty | Check `MONGODB_URL`; `inspections` collection is created on first ban event |
| Pattern not matching | Verify pattern `is_active=true` in Admin Web; check encoding — the engine normalises URL/HTML/Unicode before matching |
| VT checks always skipped | `VIRUSTOTAL_API_KEY` not set, or IP is RFC1918 (local IPs are never checked) |
| `waf.*` import error on startup | Confirm Dockerfile copies `./waf/` to `/app/waf/` and CMD is `python -m waf.app.server` |
| Admin site create returns config error | Check `nginx-control` logs; run `docker compose exec nginx nginx -t` |
