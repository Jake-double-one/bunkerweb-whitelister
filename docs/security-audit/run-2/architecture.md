# Architecture summary — bunkerweb-whitelister (run-2, profile standard, source 4ce6e0d / v0.4.2)

## 1. Product, principals, authority, protected resources
Single-tenant FastAPI/Starlette app that maintains BunkerWeb's global IP whitelist: entries (host/CIDR, label, optional expiry) in SQLite under `DATA_DIR`; BunkerWeb's scheduler downloads the active list from `GET /ips.txt`; after each change the app asks bw-api to drop the job's cache file (or run the job) so the list is re-fetched. New since run-1 (033b4ce): invitation links, prefill links + login `next`, export/import, on-page history, fetch marks from `/ips.txt`, PWA shell, OG preview, CSS countdown, Biscuit-token flow.

Principals, lowest trust first:
- **Anonymous internet client**: `GET /healthz`, `/sw.js`, `/offline`, `/i/og.png`, `/static/*`, `GET/POST /login` (`next` form/query → `safe_next`, app.py:247-251), `GET /?add=&days=&label=` (redirects to login with encoded `next`).
- **Invitation-link holder** (new): `GET /i/{token}` read-only; `POST /i/{token}` puts *their own resolved address* (IPv4 host or IPv6 /64, app.py:275-284) on the list for `invite.access_days` via `store.upsert(..., created_by="invite:<name>")` (app.py:724-751). Token: `secrets.token_urlsafe(24)`, only SHA-256 stored (app.py:650-653, 827), length gate 20..64, separate `invite_throttle` (same limits as login, global budget 30 failures/min shared by all clients), `record_success` on a valid token (app.py:682-696). Budget: distinct addresses in `invite_addresses`, 0 = unlimited; check at 736-738 and write at 744 are separate statements. Revoke sets `revoked_at`; redeemed entries stay. Page shows invite name, remaining count, validity, own IP, expiry; OG tags carry the name.
- **Logged-in operator** (anyone with the password): `/`, `/entries*`, `/invites` (create: name, access days, link days ∈ {7,14,30}, budget 0..1000), `/invites/{id}/revoke`, `/export` (GET, session only), `/import` (multipart JSON, session+CSRF, 256 KiB body via Content-Length), `/logout` (CSRF token, no `same_origin`).
- **List fetcher** (`/ips.txt`): TCP peer ∈ `LIST_ALLOWED_NETWORKS` (default all private + loopback), no forwarding headers, optional constant-time `?token=`; now also writes `meta.list_fetched_at` (app.py:404-415), which drives the ✓/… marks and the "BunkerWeb last fetched" line.
- **bw-api** (outbound): `POST /auth` Basic → Biscuit Bearer, re-auth once on 401; `DELETE /cache/.../<sha1(WHITELIST_URL)>.list`, `POST /jobs/run` on 404 (bunkerweb.py:43-151). `BW_API_VERIFY_TLS` may be off; `BW_API_URL` may be http.
- **Container operator**: env / `*_FILE` secrets / `/data`.

Protected resources: the whitelist (an entry bypasses BunkerWeb's checks for that network), password/session, bw-api credentials, invite tokens (a valid link whitelists any address one can connect from), audit trail and history.

## 2. Comparable baseline
No source-grounded comparable product. Patterns: magic-link style tokens (random, hashed, expiring, budgeted), XFF right-to-left walk, `__Host-` cookies, Fetch Metadata + Origin, PWA app-shell caching. BunkerWeb 1.6.17 behaviour is documented, not local.

## 3. Stack, deployment paths, offline limits
Python ≥3.13 (image 3.14-slim; local venv 3.13.17), FastAPI 0.162 / Starlette 1.10 / Uvicorn 0.54 (`proxy_headers=False`, `limit_concurrency=100`), Jinja2 autoescape+StrictUndefined, itsdangerous cookies, httpx, python-multipart 0.0.33, sqlite3 WAL (sessions, entries, events, meta, invites, invite_addresses). Hash-pinned requirements; image uid 10001, pip-free venv; compose example hardened, image tag still `0.1.0`; CI as in run-1 plus tag-version check and a two-step Trivy scan; actions pinned by tag.

Offline execution: `pytest -q` (84 tests; ASGITransport + fake bw-api with token mode; helpers `_proxied`, `_guest(app, ip)` simulate a trusted proxy peer 10.0.0.5 + XFF). App runs on isolated loopback without `BW_API_URL`. Prohibited: pip, docker, trivy, gh, any real `BW_API_URL`. Sandbox: user+mount+net namespaces, read-only target/venv/tools, empty env, scratch cwd, 60 s / 1 GiB / 64 procs / 64 MiB files; promotion via `promote.py` with the required checks.

## 4. Entry surfaces and important paths
- Middleware (app.py:73-106): 413 over 16 KiB (256 KiB for `/import`) by Content-Length; 411 chunked; strict CSP with style nonce; `no-store` except `/static/` and `/i/og.png`.
- Invite creation → link in signed flash cookie (`l`, 60 s) → rendered once in a readonly input (index.html:183); `public_origin` = `PUBLIC_URL` or `scheme://Host` (app.py:269-273) → link, `og:url`, `og:image`.
- Invite page: inlined app.css (`| safe`, read from disk at start), nonce'd `<style>` with int `wait_seconds`, OG/Twitter meta with autoescaped name, `<form action="">` POST, no script.
- Prefill: `prefill_from_query` (app.py:253-267) only fills form values; `add` goes through `parse_network`, `days` must be a preset, `label` normalised.
- Import (app.py:775-819): multipart parsed before `require_post`; `file.read(MAX+1)`; JSON dict/list; each row `parse_network`, `normalize_label`, `_parse_import_expiry` (ISO ≤ max_days, naive = UTC, null = forever); validation all-or-nothing, upsert loop not transactional (5000 cap mid-way); every row logged as event.
- History: `events` capped at 200 rows, rendered via translation templates with `str.format(**params)` (user values are parameters only).
- Service worker (static/sw.js): cache `whitelister-static-<version>`, precache `/offline` + `/static/*`; navigations network-first with `/offline` fallback; runtime cache only same-origin `/static/` basic ok responses; registered only in secure contexts; `/sw.js` served from root scope.
- Client IP (security.py:237-272): headers honoured only from `TRUSTED_PROXIES` peers; this identity now decides what an invite redeems, throttle keys, `add=me`, `created_by`, events.actor.
- Syncer (bunkerweb.py:164-229): expiry events, purges incl. `invites_purge(30 d)`, debounced refresh; tick guarded.

## 5. Trust boundaries and strongest source-visible control
1. Internet → login: password compare / PBKDF2 off-loop, per-key + global throttle, `same_origin`.
2. Link holder → whitelist: token unguessability + SHA-256 lookup + throttle + open-state + `redeemer_network` (own address only, policy via `parse_network`) + budget (non-atomic) + `same_origin` on POST; GET side-effect free.
3. Browser → operator state change: session row + signed cookie + CSRF HMAC + `same_origin` + SameSite=Strict; `/export` is GET with session only.
4. Proxy metadata → identity: `TRUSTED_PROXIES` peer gate; `CLIENT_IP_HEADER` verbatim.
5. Peer → `/ips.txt`: allowlist + no forwarding headers + token; now also a writer of the fetch timestamp.
6. Operator input / import file → list line / HTML / SQL / log / inline CSS: `ipaddress` parsing, label normalisation, parameterised SQL, autoescape, int-only CSS values, JSON audit.
7. Browser persistence: service-worker cache (static only), localStorage (skin, label).
8. App → bw-api: Biscuit token in memory, fixed paths, `follow_redirects=False`, optional TLS verify.

## 6. Starting paths
`whitelister/*.py`, `whitelister/templates/*.html`, `whitelister/static/{app.js,sw.js,manifest.webmanifest}`, `whitelister/locales/*.json`, `Dockerfile`, `docker-compose.example.yml`, `.env.example`, `.github/workflows/ci.yml`, `requirements.txt`, `tests/`.

## 7. Prior coverage (run-1 at 033b4ce, standard, 24 units, 2 confirmed low + 3 needs_validation)
Every prior unit's relevant source changed (app.py, entries.py, bunkerweb.py, config.py, templates, Dockerfile, ci.yml): all 24 are re-seeded as `prior_covered_changed_source`, `prior_confirmed_changed_source` (extend-policy, scope-id list smuggling — both fixed in f1c18de; revalidate) or `prior_needs_validation` (compose subnet trust, persistent-404 reporting, syncer fault — all changed in f1c18de; current work, records not carried). Nothing is carried same-source and nothing is on the hunter exclusion list. 12 new units cover invitations, export/import, fetch marks, prefill/`next`, the service worker and the Biscuit flow.

## 8. Companion selection
- `WEB-PROTOCOL-AND-AUTH.md`: sessions, CSRF (incl. the cookie-less invite POST), forwarded-header/Host trust (`public_origin`), password-reset-style token links, API-key exposure (Biscuit/Bearer over the bw-api link).
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`: pre-auth work and quota scope for login and the invite throttle (shared global budget), body/cardinality limits incl. import.
- `DATA-ISOLATION-AND-LIFECYCLE.md` (new): export/import scope and restore authority, revocation vs. redeemed copies, fetch-mark staleness, events retention.
- `CLIENT-SIDE.md` (new): service-worker cache/scope, browser storage, DOM sinks of the list tools and copy button, navigation (`next`).
- `CLOUD-AND-DEPLOYMENT.md`, `SUPPLY-CHAIN-AND-RELEASE.md`: as in run-1 (container, compose, CI).
- Not selected: AI/LLM, MEMORY-SAFETY, PROTOCOLS-RPC, DESKTOP-MOBILE (no such surfaces).
