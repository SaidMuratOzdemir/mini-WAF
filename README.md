# WAF – Web Application Firewall

A self-contained, auth-request style WAF with an admin dashboard built for learning and portfolio purposes.

**What's inside:**
- **Nginx Edge Gateway** — receives all traffic and uses `auth_request` to consult the WAF Engine
- **WAF Engine** (FastAPI) — inspects requests, bans/whitelists IPs, queues offline analysis (VirusTotal, pattern matching)
- **Admin API** (FastAPI) — manage sites, IPs, patterns, logs, and VirusTotal cache
- **Admin Web** (React + MUI) — visual control panel

---

## Highlights
- Request inspection across path, query, headers, and body
- Pattern-based blocking (XSS / SQL / CUSTOM) sourced from DB, with advanced encoding bypass normalization
- VirusTotal IP reputation checks (async, non-blocking)
- Ban/whitelist stored in Redis (`banned_ip:` / `clean_ip:`)
- Inspection logging to MongoDB (decision, pattern analysis, VT result)
- Fail-open queue design: Nginx always gets a response; deep analysis happens asynchronously
- Full admin dashboard with Docker Compose

---

## Architecture

```
                           ┌─────────────────────────┐
 [ Client ] ──HTTP──────▶  │   Nginx (Edge Gateway)   │
                           │   port 80                 │
                           └──────┬──────────┬────────┘
                                  │          │
                    auth_request  │          │  proxy_pass
                    (sub-request) │          │  (on 200)
                                  ▼          ▼
                     ┌──────────────┐   ┌──────────────────┐
                     │  WAF Engine  │   │  Upstream Targets │
                     │  (FastAPI)   │   │  (your apps)      │
                     │  :8000       │   └──────────────────┘
                     └──────┬───┬──┘
                            │   │
               ┌────────────┘   └────────────┐
               ▼                             ▼
       ┌──────────────┐            ┌──────────────┐
       │    Redis      │            │   MongoDB     │
       │ ban/whitelist │            │  inspections  │
       └──────────────┘            └──────────────┘

 [ Admin Web (React) ] ──▶ [ Admin API (FastAPI) ] ──▶ Postgres / Redis / MongoDB
```

### Request Flow

1. Client HTTP request arrives at **Nginx** (port 80).
2. Nginx issues an `auth_request` sub-request to the **WAF Engine** (`/inspect`).
3. The WAF Engine performs **synchronous fast checks** (Redis ban/whitelist lookup):
   - If the IP is banned → responds `403` → Nginx blocks the request.
   - If the IP is whitelisted → responds `200` → Nginx forwards to upstream.
   - Otherwise → responds `200` (fail-open) and **queues** the request for deep analysis.
4. Nginx routes the traffic to the correct **upstream target** based on `server_name`.
5. In the background, inspection workers perform:
   - **Pattern analysis** (XSS, SQL injection, custom patterns with encoding bypass detection)
   - **VirusTotal IP reputation** check
   - If a threat is detected → the IP is **banned in Redis** for future requests.
   - The full inspection result is **logged to MongoDB** (`inspections` collection).

---

## Repository Structure
```
WAF/
├─ api/                    # Admin API (FastAPI)
│  ├─ app/
│  │  ├─ core/             # settings, security, dependencies
│  │  ├─ database.py       # async engine/session provider
│  │  ├─ models.py         # SQLAlchemy models (User, Site, MaliciousPattern)
│  │  ├─ routers/          # auth, sites, ips, patterns, system, logs
│  │  └─ main.py           # FastAPI app entry point
│  ├─ alembic/             # database migrations
│  └─ Dockerfile
│
├─ waf/                    # WAF Engine (FastAPI + auth_request)
│  ├─ app/server.py        # /inspect endpoint, queue workers
│  ├─ checks/
│  │  ├─ inspection_policy.py          # InspectionPolicy dataclass
│  │  ├─ security_engine.py            # request analysis orchestrator
│  │  └─ patterns/                     # pattern cache, advanced analyzer, encoders
│  ├─ ip/                  # ban_actions, banlist, local IP utils
│  └─ Dockerfile
│
├─ web/                    # Admin Web (React + Vite + MUI)
│  ├─ src/
│  │  ├─ api/              # fetch wrapper with JWT
│  │  ├─ components/       # IP Mgmt, Patterns, Logs, VT Stats, Sites
│  │  ├─ context/          # Auth context
│  │  └─ App.tsx           # Routes & layout
│  └─ Dockerfile
│
├─ nginx.conf              # Nginx config with auth_request
├─ nginx/conf.d/           # per-site upstream configs (add yours here)
├─ docker-compose.yml      # full local stack
└─ init-db.sql
```

---

## Data Model
| Model | Description |
|---|---|
| `Site` | Host mapping with check toggles (`xss_enabled`, `sql_enabled`, `vt_enabled`) |
| `MaliciousPattern` | `pattern`, `type` (XSS/SQL/CUSTOM), `is_regex`, `is_active`, `description` |
| `User` | Admin users for the dashboard — seeded via Alembic migrations |

Models live in `api/app/models.py`.

---

## Admin API
| Router | Endpoints |
|---|---|
| `auth` | Login → JWT token |
| `sites` | CRUD for protected sites |
| `ips` | List / ban / unban / whitelist / unwhitelist |
| `patterns` | CRUD + bulk upload (text file) |
| `system` | VT cache stats and cleanup |
| `logs` | Inspection logs, statistics, blocked entries (MongoDB) |

Base path: `/admin-api/v1/`

---

## Admin Web
- Protected routes (JWT in localStorage)
- Views: Sites, IP Management, Patterns, Logs, VirusTotal Stats
- Base path: `/admin-ui/`

---

## Quickstart

**Prerequisites:** Docker + Docker Compose

```bash
# 1. Create external network
docker network create waf-core-net

# 2. Create .env at project root
echo 'JWT_SECRET=change-me' > .env
echo 'VIRUSTOTAL_API_KEY=' >> .env

# 3. Start the stack
docker compose up --build -d

# 4. Open
#    Admin UI:  http://localhost/admin-ui/
#    Admin API: http://localhost/admin-api/v1/docs
```

---

## Configuration

**Environment variables:**
| Variable | Used by | Description |
|---|---|---|
| `DATABASE_URL` | API | PostgreSQL connection string |
| `REDIS_URL` | WAF, API | Redis for ban/whitelist |
| `MONGODB_URL` | WAF, API | MongoDB for inspection logs |
| `VIRUSTOTAL_API_KEY` | WAF | Optional — enables VT IP reputation |
| `JWT_SECRET` | API | JWT signing key |
| `BAN_TTL_SECONDS` | WAF | How long an IP stays banned (default: 3600) |
| `INSPECTION_QUEUE_SIZE` | WAF | Max queued inspections (default: 5000) |
| `INSPECTION_WORKERS` | WAF | Concurrent inspection workers (default: 8) |

**Site-level toggles** (per-site in DB): `xss_enabled`, `sql_enabled`, `vt_enabled`

---

## Adding Protected Sites

Upstream apps are reached by Nginx via Docker-internal DNS. Both the app and Nginx must share the same Docker network.

1. Run your target app on `waf-core-net`:
    ```yaml
    services:
      my-app:
        image: my-app-image
        networks:
          waf-core-net:
            aliases: ["my-app-internal"]
    networks:
      waf-core-net:
        external: true
    ```
2. Add a server block in `nginx/conf.d/my-app.conf`:
    ```nginx
    server {
        listen 80;
        server_name my-app.local;

        location = /auth-waf {
            internal;
            proxy_pass http://waf_auth_engine/inspect;
            # copy full auth_request config from nginx.conf
        }

        location / {
            auth_request /auth-waf;
            proxy_pass http://my-app-internal;
        }
    }
    ```
3. Add `127.0.0.1 my-app.local` to `/etc/hosts`.
4. Register the site in **Admin Web → Sites** with host `my-app.local`.
5. Restart nginx: `docker compose restart nginx`

---

## Troubleshooting
| Symptom | Fix |
|---|---|
| WAF fails to import `waf.*` | Ensure Dockerfile copies `./waf/` to `/app/waf/` and CMD is `python -m waf.app.server` |
| VT checks disabled/failing | VT is optional per-site; errors are non-fatal (fail-open) |
| Logs empty | Confirm `MONGODB_URL` is reachable; `inspections` collection is auto-created at startup |
| Nginx returning 500 | Check WAF engine is reachable at `http://waf:8000/inspect` |
