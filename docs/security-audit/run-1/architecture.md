# Architecture summary — bunkerweb-whitelister (run-1, profile standard)

## 1. Product, principals, authority, protected resources
Single-tenant FastAPI/Starlette web app (v0.1.0) that maintains BunkerWeb's global IP whitelist. One shared password, no user names, no roles. Entries (host or CIDR, label, optional expiry) live in SQLite under `DATA_DIR`. BunkerWeb's scheduler downloads the active list as plain text from `GET /ips.txt`; after each change the app asks the BunkerWeb API to drop the job's cache file so the list is re-fetched and BunkerWeb reloads.

Principals, lowest trust first:
- **Anonymous internet client** (via BunkerWeb reverse proxy): `GET /healthz`, `GET/POST /login`, `/static/*`. Can try passwords (throttled per IPv4 address / IPv6 /64, plus a global budget of 30 failures per minute), sees its own resolved IP on the login page.
- **Logged-in operator** (anyone with the password; all sessions equal): `GET /`, `POST /entries`, `POST /entries/{id}/extend`, `POST /entries/{id}/delete`, `POST /logout`. Full add/extend/delete over every entry; "forever" entries bypass `MAX_DAYS`; upsert of an existing network replaces its expiry.
- **BunkerWeb scheduler** (same Docker network): `GET /ips.txt`, gated by peer network, absence of forwarding headers, optional `LIST_TOKEN`.
- **BunkerWeb API** (upstream, trusted via status code only): receives `DELETE /cache/global/whitelist/whitelist-download/<sha1(WHITELIST_URL)>.list`, on 404 `POST /jobs/run`.
- **Container operator**: env vars / `*_FILE` secrets / `/data` volume; full control.

Protected resources: the whitelist (whoever can add an entry makes BunkerWeb skip its security checks for that network), the password/session, the BunkerWeb API credential, the audit trail.

## 2. Comparable baseline
No source-grounded comparable product. Protocol conventions in use: X-Forwarded-For walked right-to-left over trusted hops, `__Host-` cookie prefix, Fetch Metadata (`Sec-Fetch-Site`) plus Origin check, Django-style `pbkdf2_sha256$iter$salt$hash` strings. BunkerWeb 1.6.17 API/job behaviour (cache file naming, one-hour download cache) is documented in `whitelister/bunkerweb.py:1-10` but no BunkerWeb source is present locally.

## 3. Stack, deployment paths, offline limits
Python ≥3.13 (image `python:3.14-slim`), FastAPI 0.162 / Starlette 1.10 / Uvicorn 0.54 (`proxy_headers=False`, `forwarded_allow_ips=[]`, `limit_concurrency=100`, `h11_max_incomplete_event_size=16KiB`), Jinja2 (autoescape + StrictUndefined), itsdangerous cookies, httpx client, stdlib sqlite3 (WAL). Hash-pinned `requirements.txt`. Dev tools pytest/ruff unpinned.

Deployment: `ENTRYPOINT python -m whitelister` (`whitelister/__main__.py`), non-root uid 10001, `/data` 0700, pip removed. `docker-compose.example.yml` adds read_only, cap_drop ALL, no-new-privileges, mem/pids limits, BunkerWeb labels (`USE_WHITELIST=no`, `/login` 6r/m). CI (`.github/workflows/ci.yml`): test job (pytest, ruff, pip-audit), image job (build, smoke test, Trivy, push to GHCR on main / v* tags with provenance+SBOM).

Offline execution: the test suite (`pytest -p no:cacheprovider`) needs no network (ASGITransport + MockTransport fake BunkerWeb). The app can run on isolated loopback with `LISTEN_HOST=127.0.0.1 TRUSTED_PROXIES=... COOKIE_SECURE=no DATA_DIR=<scratch>` and no `BW_API_URL`. Prohibited: pip/pip-compile/pip-audit, docker build/run/push, trivy, any real `BW_API_URL`. Docker daemon is not running; Python 3.14 is not available locally (3.13 is). The required OS sandbox is available (see run-metadata / tools): user+mount+net namespaces, read-only target, empty allowlisted env, scratch-only writes, rlimits.

## 4. Entry surfaces and important paths
- `POST /login` (`whitelister/app.py:312-344`): `same_origin` → client IP must resolve → `throttle_key`/`LoginThrottle` → 2-slot semaphore → `PasswordChecker` (PBKDF2 or compare_digest) in a threadpool → `sessions_purge`/`session_add` → signed cookie.
- Session (`security.py:86-118`, `app.py:152-170`): itsdangerous `{sid,iat}` with `max_age=SESSION_HOURS`; sid must also exist unexpired in SQLite `sessions`; CSRF = HMAC(sha256("csrf:"+secret), sid), embedded in every form; `require_post` = session + `same_origin` + token. `/logout` checks token only.
- Client IP (`security.py:237-272`, `app.py:147-150,494-499`): forwarding headers honoured only when TCP peer ∈ `TRUSTED_PROXIES` (mandatory setting, `none` allowed). XFF walked from the right; unparsable hop → None → login 403. Any other `CLIENT_IP_HEADER` taken verbatim. Repeated headers joined. `parse_ip` accepts `ip:port`, `[v6]`, and stdlib IPv6 scope IDs (`fe80::1%scope`).
- `GET /ips.txt` (`app.py:294-303`): peer ∈ `LIST_ALLOWED_NETWORKS` (default RFC1918+loopback+ULA) AND none of x-forwarded-for/forwarded/x-real-ip/x-forwarded-host/x-forwarded-proto AND optional `?token=` (constant-time). Renders `render_list(active_networks)`: `# bunkerweb-whitelister` then one stored `network` string per line.
- Entry forms (`app.py:396-486`): `parse_network` (`entries.py:36-52`: ≤64 chars, `ip_network(strict=False)`, min prefix, refuses multicast/unspecified/loopback/reserved, private configurable) → `network_text` (`str(network_address)` for single hosts — keeps an IPv6 `%scope` if present) → parameterised SQLite upsert (UNIQUE network, 5000 cap). `normalize_label` NFC, collapses whitespace, strips Unicode category C, ≤64. Durations: int days 1..MAX_DAYS, `forever`, or `date` (end of day in `TZ`). Extend counts from current end, capped at now+MAX_DAYS; "forever" uncapped. Every change → audit JSON line (`app.py:219-221`) + `refresh_after_change` → BunkerWeb API; failure → syncer retry.
- Rendering (`app.py:356-394`, `templates/index.html`): autoescaped context; one nonce'd inline `<style>` with integer ids and clamped percentages; flash cookie (signed, 60 s, not session-bound) rendered as text; `list_url` (= `WHITELIST_URL`, may contain `?token=`) rendered in the footer.
- Middleware (`app.py:62-93`): 413 if Content-Length > 16 KiB; 411 for chunked POST/PUT/PATCH; CSP `default-src 'none'; script-src 'self'; style-src 'self' 'nonce-…'`, XFO DENY, nosniff, Referrer-Policy same-origin, COOP/CORP, no-store, optional HSTS.
- Outbound API (`bunkerweb.py:42-115`): base URL from config (http/https only), fixed paths, hex sha1 segment, `follow_redirects=False`, Basic or Bearer, only status codes read; error text (class name / "HTTP n") shown truncated to 24 chars in header, untruncated in flash.
- Config (`config.py`): `*_FILE` wins over plain var (empty file → "" not default); `session.key` created 0600 without O_NOFOLLOW; `LOG_LEVEL`, `LISTEN_HOST`, `LIST_TOKEN`, `CLIENT_IP_HEADER` unvalidated strings.
- Background `Syncer` (`bunkerweb.py:118-172`): 30 s tick, detects newly expired entries (logged plain-text with label), purges after `EXPIRED_RETENTION_DAYS`, debounced API refresh with retry.

## 5. Trust boundaries and strongest source-visible control
1. Internet → login: password check (constant-time / full PBKDF2), per-key + global throttle, hashing off the event loop with 2 slots, `same_origin` refusal not counted.
2. Browser → state change: server-side session row + signed cookie + per-session CSRF token + `Sec-Fetch-Site`/Origin-vs-Host + `SameSite=Strict`.
3. Proxy metadata → client identity: `TRUSTED_PROXIES` peer gate, right-to-left XFF walk; identity used only for throttle key, audit, display, `created_by`.
4. Network peer → `/ips.txt`: peer allowlist + forwarding-header absence + optional token.
5. Operator input → list line / HTML / SQL / log: `ipaddress` parsing, label normalisation, parameterised SQL, autoescape, JSON audit.
6. App → BunkerWeb API: fixed path construction, credential from config.
7. Image/compose/CI: non-root, read-only FS, cap_drop, hashed deps, GHCR push gated to main/tags.

## 6. Starting paths
`whitelister/app.py`, `whitelister/security.py`, `whitelister/entries.py`, `whitelister/config.py`, `whitelister/bunkerweb.py`, `whitelister/i18n.py`, `whitelister/__main__.py`, `whitelister/templates/*.html`, `whitelister/static/app.js`, `Dockerfile`, `docker-compose.example.yml`, `.env.example`, `.github/workflows/ci.yml`, `requirements.txt`, `tests/`.

## 7. Prior coverage
No prior run; no prior ledger or findings (first run). Nothing carried or excluded.

## 8. Companion selection
- `WEB-PROTOCOL-AND-AUTH.md`: sessions, CSRF, forwarded-header trust (boundaries 2, 3). Excluded: federated identity, MFA/passkey, API-key/mTLS classes (no such code), request framing/cache classes (no proxy or cache source in repo; a single backend behind an unobserved proxy).
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: pre-auth PBKDF2 work, throttle accounting, body/cardinality limits (boundary 1, middleware).
- `CLOUD-AND-DEPLOYMENT.md`: container/compose hardening, trusted-proxy topology (boundary 7). Excluded: IAM, Kubernetes, serverless, managed storage/event classes (absent).
- `SUPPLY-CHAIN-AND-RELEASE.md`: CI permissions, mutable action/base-image tags, build-to-promotion (boundary 7). Excluded: updater/plugin classes (absent).
- Not selected: AI/LLM, MEMORY-SAFETY, PROTOCOLS-RPC, DATA-ISOLATION (single tenant, no export/restore), DESKTOP-MOBILE, CLIENT-SIDE (no SPA/postMessage/service worker; DOM handling is 60 lines of progressive enhancement reviewed under ordinary Injection).
