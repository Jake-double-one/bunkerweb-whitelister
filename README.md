# bunkerweb-whitelister

A small, password-protected web page that maintains the **global IP whitelist of
[BunkerWeb](https://www.bunkerweb.io/)**. It detects the visitor's public address,
proposes it for the list, lets entries expire after a number of days or on a date
(or never), and lets you extend them. BunkerWeb picks changes up within seconds.

Built in the [Feierabend design system](https://github.com/Jake-double-one/design-systems)
(six skins, self-hosted fonts, works without JavaScript). English by default, German
included, more languages are one JSON file away.

## How it works

```
browser ──HTTPS──▶ BunkerWeb ──▶ whitelister:8080   (login, the page, the forms)
                                  │
bw-scheduler ◀── GET /ips.txt ────┘   WHITELIST_IP_URLS=http://whitelister:8080/ips.txt
      ▲
      └── bw-api ◀── DELETE /cache/global/whitelist/whitelist-download/<sha1(url)>.list
```

1. Entries live in a SQLite file under `/data`. Each one has a network (host or CIDR),
   a label and an end (or none).
2. `GET /ips.txt` serves the active entries, one per line. BunkerWeb's
   `whitelist-download` job fetches it like any other `WHITELIST_IP_URLS` source.
3. That job caches every URL for one hour. After each change the whitelister deletes
   the cached copy through the BunkerWeb API, which marks the whitelist plugin as
   changed; the scheduler re-downloads the list, regenerates the configuration and
   reloads BunkerWeb. If no cached copy exists yet, the job is scheduled directly
   (`POST /jobs/run`).
4. A background loop watches for entries that reach their end, triggers the same
   refresh, and deletes expired entries after `EXPIRED_RETENTION_DAYS` (they stay
   visible, marked red and extendable, until then). A storage error in one tick is logged
   and retried on the next; `GET /healthz` answers 503 if the loop ever stops. Without the
   API the hourly job still picks the list up on its own, so an expiry can lag up to an hour.
   `WHITELIST_URL` must be byte-identical to `WHITELIST_IP_URLS`: it names the cache file
   that gets dropped, and a persistent miss is shown as an API error in the header.

The whitelister never writes BunkerWeb settings. It needs an API user with
`cache_read`, `cache_delete` and `job_execute` permissions only (no admin).

## Security model

The page sits in front of a sensitive control, so it is built accordingly:

- **One password, no user name.** Plain (`WHITELISTER_PASSWORD`, 12+ characters) or
  PBKDF2-SHA256 hash (`WHITELISTER_PASSWORD_HASH`, made with
  `python -m whitelister.hashpw`). Both accept Docker secrets via `*_FILE`.
  Comparison is constant-time; with a hash the full PBKDF2 work runs for wrong
  passwords too.
- **Login throttling.** Per client (IPv4 address, IPv6 /64): after `LOGIN_MAX_FAILURES` the
  client waits `LOGIN_LOCK_SECONDS`, doubling with every further failure (max 1 h). More than
  30 failures per minute from all clients together close the login for a minute, so a
  distributed guessing run costs attempts rather than CPU. Password hashing runs off the
  event loop, at most two checks at a time. Cross-site posts are refused without counting.
  Every attempt is written to the audit log.
- **Sessions.** Signed, time-limited cookie (`itsdangerous`), `HttpOnly`,
  `SameSite=Strict`, `Secure` and the `__Host-` prefix when `COOKIE_SECURE=yes`
  (default). Nothing but a random id is stored in it; the id is also kept server-side, so
  logging out really ends the session. Rotating `SESSION_SECRET` logs everyone out.
- **CSRF.** Every form carries a per-session token; posts are also checked against
  `Sec-Fetch-Site` and `Origin`.
- **Trusted proxies.** `TRUSTED_PROXIES` is mandatory (networks, or `none`). Forwarding
  headers are honoured only when the TCP peer is inside it; `X-Forwarded-For` is walked from
  the right, skipping trusted hops, and a chain that does not parse means no login. With
  `none` the TCP peer is the client, full stop. Uvicorn's own proxy-header handling is
  disabled so there is exactly one place that decides. Name the ingress address alone (the
  compose example pins BunkerWeb to `10.20.30.2`), never a shared subnet: every host inside
  `TRUSTED_PROXIES` can choose the client identity it reports.
- **The plain list is not public.** `/ips.txt` answers only direct requests (any
  forwarding header means "came through a proxy" and is refused) from
  `LIST_ALLOWED_NETWORKS`, and requires `LIST_TOKEN` in the URL when one is set (the example
  configuration sets one; the footer never shows it).
- **Headers.** Strict CSP (`default-src 'none'`, scripts, styles and fonts from `self`
  only), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`,
  `Cache-Control: no-store`, optional HSTS. No external requests from the browser.
- **Input.** Addresses are parsed with `ipaddress`; loopback, multicast, unspecified and
  reserved ranges are refused, networks wider than `MIN_PREFIX_V4` / `MIN_PREFIX_V6`
  too, as are IPv6 scope ids and inner whitespace (the stdlib accepts newlines inside a scope id,
  which would otherwise smuggle extra lines into the list; the list writer also refuses anything
  that is not one network token). Extending an entry re-applies the current policy, so a row
  accepted under an earlier, looser `MIN_PREFIX_*`/`ALLOW_PRIVATE` cannot be revived or made
  permanent once the policy is tightened; such rows are warned about at startup. Labels are
  limited to 64 characters with control characters stripped. Request bodies over 16 KB and
  chunked uploads are rejected. Templates auto-escape.
- **Container.** Multi-stage build on `python:3.14-slim` with the latest Debian
  patches, no pip at runtime, non-root user `10001`, works with `read_only: true`,
  `cap_drop: ALL` and `no-new-privileges`. Dependencies are pinned with hashes
  (`requirements.txt`), CI runs `pip-audit` and a Trivy image scan on every push and
  weekly; Dependabot keeps base image, packages and actions current.
- **Audit log.** Logins, lockouts and every add / extend / remove go to stdout as
  JSON lines with the client address.

Put the whitelister itself **behind BunkerWeb** with `USE_WHITELIST=no` on its own
service, so the whitelist can never bypass the checks in front of the page that edits it,
and add a request limit on `/login` (see the compose example).

## Quick start

```bash
cp .env.example .env         # set WHITELISTER_PASSWORD, BW_API_*, TRUSTED_PROXIES
docker compose -f docker-compose.example.yml up -d whitelister
```

BunkerWeb side (global settings):

```
USE_WHITELIST=yes
WHITELIST_IP_URLS=http://whitelister:8080/ips.txt
```

API side: an API user for the whitelister (`API_ACL_BOOTSTRAP_FILE`) or the admin
credentials, and `API_WHITELIST_IPS` covering the whitelister's network.

`docker-compose.example.yml` shows the whole arrangement including the hardening
options and the BunkerWeb labels that publish the page.

### Make a password hash

```bash
docker run --rm -it ghcr.io/jake-double-one/bunkerweb-whitelister:0.1.0 python -m whitelister.hashpw
```

## Configuration

All variables may be given as `NAME_FILE` (path to a secret) instead.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WHITELISTER_PASSWORD` | | Login password, 12+ characters. Or: |
| `WHITELISTER_PASSWORD_HASH` | | PBKDF2 hash from `python -m whitelister.hashpw` |
| `SESSION_SECRET` | generated | 32+ characters; stored under `/data/session.key` when unset |
| `SESSION_HOURS` | `12` | Session lifetime |
| `LOGIN_MAX_FAILURES` / `LOGIN_LOCK_SECONDS` | `3` / `30` | Throttling |
| `TRUSTED_PROXIES` | required | Networks whose forwarding headers are trusted, or `none` |
| `CLIENT_IP_HEADER` | `X-Forwarded-For` | Header carrying the client address |
| `COOKIE_SECURE` | `yes` | `Secure` cookies with `__Host-` prefix (needs HTTPS) |
| `HSTS` | `no` | Send `Strict-Transport-Security` |
| `LIST_ALLOWED_NETWORKS` | RFC 1918, loopback, ULA | Who may fetch `/ips.txt` directly |
| `LIST_TOKEN` | | Secret required as `?token=` on `/ips.txt` (recommended; empty = none) |
| `DURATION_PRESETS` | `1 7 14 30` | Day chips shown in the forms |
| `MAX_DAYS` | `3650` | Longest allowed duration |
| `EXPIRED_RETENTION_DAYS` | `7` | How long expired entries stay listed before deletion |
| `MIN_PREFIX_V4` / `MIN_PREFIX_V6` | `16` / `48` | Widest allowed network |
| `ALLOW_PRIVATE` | `yes` | Allow RFC 1918 / ULA entries |
| `BW_API_URL` | | e.g. `http://bw-api:8888`; unset = no API, list only |
| `BW_API_USERNAME` / `BW_API_PASSWORD` | | Basic auth for the API, or: |
| `BW_API_TOKEN` | | Bearer token (`API_TOKEN`, break-glass only) |
| `BW_API_VERIFY_TLS` | `yes` | Verify the API's certificate |
| `WHITELIST_URL` | | Exactly the URL in `WHITELIST_IP_URLS` (names the cache file) |
| `SYNC_DEBOUNCE_SECONDS` | `3` | Collect quick successive changes before one refresh |
| `SYNC_TIMEOUT_SECONDS` | `10` | API request timeout |
| `WHITELISTER_LANG` | `en` | `en`, `de`, or any `locales/<code>.json` |
| `WHITELISTER_SKIN` | `auto` | `auto`, `dark`, `amoled`, `sunset`, `light`, `mint`, `mango` |
| `TZ` | `UTC` | Time zone for display and date inputs |
| `DATA_DIR` | `/data` | SQLite file and generated session key |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8080` | |
| `LOG_LEVEL` | `info` | |

## Translations

`whitelister/locales/en.json` holds every string; `de.json` overrides what differs.
Add `fr.json` with the keys you want to translate and set `WHITELISTER_LANG=fr`;
missing keys fall back to English. Plurals use `key.one` / `key.other`.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt && pip install pytest ruff
ruff check . && ruff format --check . && pytest
WHITELISTER_PASSWORD=local-dev-password COOKIE_SECURE=no TRUSTED_PROXIES=none DATA_DIR=./data python -m whitelister
```

Re-pin dependencies to the newest releases with `scripts/compile-requirements.sh`.

## Endpoints

| Path | Who | What |
| --- | --- | --- |
| `GET /login`, `POST /login` | everyone | Password form |
| `GET /` | session | The page |
| `POST /entries`, `/entries/{id}/extend`, `/entries/{id}/delete` | session + CSRF | Changes |
| `POST /logout` | session + CSRF | |
| `GET /ips.txt` | direct requests from `LIST_ALLOWED_NETWORKS` | The list for BunkerWeb |
| `GET /healthz` | everyone | `{"status":"ok"}`, 503 when the background loop has stopped |

## Security audit

A full audit with the Cloudflare `security-audit` skill (profile standard: reconnaissance,
three hunter waves, coverage critics, independent validation and record verification, all
target execution in an OS sandbox) was run on v0.1.0 before the fixes in this version. The
reports are under `docs/security-audit/run-1/`: two confirmed low findings (both fixed here,
with regression tests) and three leads that need owner-observed BunkerWeb or deployment facts.

## License

MIT
