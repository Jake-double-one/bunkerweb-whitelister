# Architecture summary — bunkerweb-whitelister (run-3, profile standard, source 0e90ff4 / v0.4.6)

## 1. Product, principals, authority, protected resources
Single-tenant FastAPI/Starlette app that maintains BunkerWeb's global IP whitelist: entries (host/CIDR, label, optional expiry) in SQLite under `DATA_DIR`; BunkerWeb's scheduler downloads the active list from `GET /ips.txt`; after each change the app asks bw-api to drop the job's cache file (or run the job). Changed since run-2 (4ce6e0d): invitation state logic (`invite_status`, `removed_at`, renewal gain, per-address-only throttle), `GET /whoami` + "check my address again" button, QR code of the invitation link on the invitation page (new dependency `segno`), countdown default 30 s, Python 3.15 image, re-pinned requirements, daily Dependabot.

Principals, lowest trust first:
- **Anonymous internet client**: `/healthz` (app.py:427), `/sw.js`, `/offline`, `/static/*`, `/i/og.png` (749), `GET/POST /login` (460/470; `next` via `safe_next`, 251), `GET /?add=&days=&label=` (redirect to login).
- **Invitation-link holder**: `GET /i/{token}` (754, read-only) and `POST /i/{token}` (768). Token `secrets.token_urlsafe(24)`, only SHA-256 stored (697-700); `open_invite` (729-743): client key, per-address throttle (`invite_throttle`, app.py:123, `global_budget=None`), length gate 20..64, hash lookup, `is_open`. Redeems only the caller's resolved address (IPv4 host or IPv6 /64, `redeemer_network` 284-293). `invite_status` (295-312) → `removed` / `exhausted` (409), `known`, `ready`. Redeem (784-797): new entry via `upsert`, or `set_expiry` only when it gains ≥ `INVITE_RENEWAL_GAIN` (1 h, app.py:71) on a finite entry; operator entries are never shortened or relabelled; `invite_touch_address` (801) spends budget for a new address. Page (`invite_view`, 314-336) shows name, remaining count, validity, own expiry; countdown CSS (int `wait_seconds`); **QR code** of `page_url = public_origin(request) + request.url.path` when `INVITE_QR` (default on), state ∈ ready/known/done and `remaining != 0`; `qr_code` (936-956) runs `segno.make(text, error="m", micro=False)` synchronously in the handler and returns one SVG path string, `None` on overflow.
- **Logged-in operator** (shared password): `/`, `/entries*` (570, 604, 651), `/invites` (666), revoke (716), `/export` (835, GET, session only), `/import` (857), `/whoami` (820-833: 401 JSON without session; else `{ip, listed, note, at}`, `no-store`), `/logout` (504, CSRF token only).
- **List fetcher** (`/ips.txt`, 447-458): TCP peer ∈ `LIST_ALLOWED_NETWORKS` (default private + loopback), no forwarding headers (security.py:277), optional constant-time `?token=`; writes `meta.list_fetched_at`.
- **bw-api** (outbound, bunkerweb.py:43-151): Basic → Biscuit Bearer or static token, re-auth once on 401, fixed paths, no redirects.
- **Container operator / CI actors**: env, `*_FILE` secrets, `/data`; GitHub Actions and Dependabot.

Protected resources: the whitelist (an entry bypasses BunkerWeb's checks for that network), password/session, bw-api credentials, invite tokens (bearer capability; now also rendered as a scannable image), audit trail/history, the single event loop (availability of the operator UI and `/ips.txt`).

## 2. Comparable baseline
BunkerWeb's own whitelist plugin and bw-api are the integration target; the invitation flow is a magic-link / capability-URL pattern (random, hashed, expiring, budgeted). Capability URLs conventionally accept that whoever sees the URL holds the capability; that calibrates, it does not dismiss.

## 3. Stack, deployment paths, offline limits
Python ≥3.13 (image `python:3.15-slim`, tag-pinned, both stages; local venv 3.13 with the pinned set incl. segno 1.6.6), FastAPI 0.162.5 / Starlette 1.10.0 / Uvicorn 0.54.0 (single process, `proxy_headers=False`, `limit_concurrency=100`), Jinja2 autoescape + StrictUndefined, itsdangerous, httpx, python-multipart, sqlite3. Hash-pinned `requirements.txt` compiled from `requirements.in` (`scripts/compile-requirements.sh`); `pyproject.toml` dependencies do not list segno. Image uid 10001, entrypoint `python -m whitelister`; compose example read-only, `cap_drop ALL`, bunkerweb pinned at 10.20.30.2 with `TRUSTED_PROXIES=10.20.30.2/32`. CI: push (all branches, `v*` tags), pull_request, weekly cron; top-level `contents: read`, image job adds `packages: write`/`security-events: write`; GHCR push only on main / `v*` and never on PRs; actions pinned by tag; unpinned `pip install pytest ruff pip-audit`; tag==version check; two-step Trivy. Dependabot daily for pip, docker, github-actions.

Offline execution: `pytest -q` in-process (ASGITransport + `FakeBunkerWeb` MockTransport; helpers `make_client(**env)`, `login`, `_proxied` (trusted peer 10.0.0.5, XFF 203.0.113.9), `_guest(app, ip)` (XFF=ip, Host wl.example), `_make_invite`, `_csrf`). Prohibited: pip, pip-compile, pip-audit, docker, trivy, gh, any real `BW_API_URL`. Sandbox: user+mount+net namespaces, read-only target/venv/tools, empty env, scratch cwd, 60 s / 1 GiB / 64 procs / 64 MiB files; promotion via `promote.py`.

## 4. Entry surfaces and important paths
- Middleware (app.py:75-108): 413 over 16 KiB (256 KiB `/import`) by Content-Length; chunked POST refused; CSP `default-src 'none'; script-src 'self'; style-src 'self' 'nonce-…'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'`; `no-store` except `/static/` and `/i/og.png`.
- `public_origin` (278-282): `PUBLIC_URL`, else `https|scheme://<Host header>` with no allowlist → invite link shown to the operator (713), `og:url`/`og:image`, and now the QR content. Request Host length is bounded only by the HTTP server's header limits.
- Invite page: inlined app.css (`| safe`, read at start), nonce'd `<style>` with int value, inline `<svg>` with autoescaped `qr.size`/`qr.path` (invite.html:81-87), no script.
- `/whoami` → `static/app.js:55-72`: `fetch('/whoami?t=…')`, 401 → reload, compares `data.ip` with `#client-ip` text, reload on change, otherwise sets `status.textContent` from `data-*` attributes.
- Delete (entries.py:270-282) stamps `invite_addresses.removed_at` for every link that saw the network; expiry purge does not; `invite_touch_address` never clears it; schema migration `ALTER TABLE … ADD COLUMN removed_at` (entries.py:200-201).
- Prefill (`prefill_from_query`), import (all-or-nothing validation, 5000 cap), history (200 rows), service worker (static only), client IP resolution (security.py:239-274), Syncer (bunkerweb.py) as in run-2.

## 5. Trust boundaries and strongest source-visible control
1. Internet → login: password compare / PBKDF2 off-loop (2 slots), per-key + global throttle, `same_origin`.
2. Link holder → whitelist: token unguessability + hash lookup + per-address throttle + open-state + own-address-only + budget + `removed` tombstone + `same_origin` on POST; GET side-effect free.
3. Link holder → server CPU/event loop: valid token required before `qr_code`; QR input bounded by segno's capacity; no explicit length cap on `page_url`.
4. Browser → operator state change: session row + signed cookie + CSRF HMAC + `same_origin` + SameSite=Strict; `/export` and `/whoami` are session-only GETs.
5. Proxy metadata → identity: `TRUSTED_PROXIES` peer gate.
6. Peer → `/ips.txt`: allowlist + no forwarding headers + token.
7. Operator input / import → list line / HTML / SQL / log / CSS / SVG: `ipaddress` parsing, label normalisation, parameterised SQL, autoescape, int-only CSS.
8. Build inputs → image: hash-pinned requirements, tag-pinned base image and actions, Dependabot PRs run CI without push rights.

## 6. Starting paths
`whitelister/*.py`, `whitelister/templates/*.html`, `whitelister/static/{app.js,sw.js,app.css}`, `whitelister/locales/*.json`, `Dockerfile`, `docker-compose.example.yml`, `.env.example`, `.github/`, `requirements.in`, `requirements.txt`, `scripts/`, `tests/`. `docs/security-audit/` holds old reports and is not a source of facts.

## 7. Prior coverage
run-1 (033b4ce) and run-2 (4ce6e0d, standard, 44 units: 5 confirmed low, 2 needs_validation, 1 rejected). All 5 confirmed run-2 records were changed in source (0.4.3): their 7 linked units are `prior_confirmed_changed_source` revalidation work, nothing is excluded from hunting. The 2 needs_validation leads (unpinned bw-universe leg outside `TRUSTED_PROXIES`; `/ips.txt` direct-request gate vs. `CLIENT_IP_HEADER`) are current work for their units. 33 units are `prior_covered_changed_source`, 1 `prior_rejected_claim_changed`, 1 stays `out_of_scope` (proxy access logs holding the token URL). 9 new units: `/whoami` (access, DOM), QR (CPU, Host trust, capability exposure), `invite_status` logic, `removed_at` migration, segno supply path, Dependabot/CI automation.

## 8. Companion selection
- `WEB-PROTOCOL-AND-AUTH.md`: sessions, CSRF, Host/forwarded-header trust (`public_origin` → link, OG, QR), private-response caching (`/whoami`), token links, bw-api credentials.
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: login and invite throttles, body/cardinality limits, QR generation on the event loop, refresh triggering.
- `DATA-ISOLATION-AND-LIFECYCLE.md`: export/import, revocation and the `removed_at` tombstone, migration defaults, capability-link exposure.
- `CLIENT-SIDE.md`: service worker, storage, DOM sinks (list tools, copy, refresh handler), navigation.
- `CLOUD-AND-DEPLOYMENT.md`, `SUPPLY-CHAIN-AND-RELEASE.md`: container, compose, CI, Dependabot, new dependency.
- Not selected: AI/LLM, MEMORY-SAFETY, PROTOCOLS-RPC, DESKTOP-MOBILE (no such surfaces).
