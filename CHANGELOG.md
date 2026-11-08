# Changelog

All notable changes to bunkerweb-whitelister. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Container images are published as
`ghcr.io/jake-double-one/bunkerweb-whitelister:<version>`.

## [Unreleased]

## [0.4.0] - 2026-11-08

### Added
- **Invitations**: shareable links for people whose address you do not know. A link carries a
  name, the access period per address, its own validity and a budget of distinct addresses
  (IPv6 per /64). The recipient opens it and presses one button; opening it again from a known
  address only restarts that address's period. Links are shown once (only a hash is stored),
  can be revoked, are throttled against guessing, and GET never changes anything. New card
  **Invitations** on the page, redemptions in the history, `PUBLIC_URL` for the link origin.
  The redeem path `/i/<token>` must be reachable without a login (see README).

## [0.3.0] - 2026-10-30

### Added
- One-click **"Extend my address"** in the header when the visitor's own address is on the list.
- **Pre-filled links**: `/?add=me&days=7&label=Laptop` opens the form with address, preset and
  label set; nothing is saved until confirmed. The login keeps a local `next` path, so the link
  survives the whitelister's own login and a login proxy in front.
- **Label suggestion**: the last label used in this browser, else "Browser · System".
- **Search, filters and sorting** on the list from three entries on (client-side view only).
- **Recently**: the last five actions (added, extended, removed, expired, imported) under the list.
- **Fetch confirmation**: `GET /ips.txt` records when BunkerWeb last fetched the list. The list
  header shows that time and every entry (and the visitor's own address) carries ✓ or … depending
  on whether its last change predates that fetch.
- **Backup and restore**: `GET /export` downloads all entries as JSON, `POST /import` restores
  them with the usual validation (expired entries skipped, policy violations stop the import).

### Changed
- Entries store a precise `updated_at`; new `events` and `meta` tables are created on first start.
  Existing databases are migrated in place and stay readable by 0.2.0.
- Request bodies for `POST /import` may be 256 KB; every other route keeps the 16 KB limit.

## [0.2.0] - 2026-10-30

### Added
- **Installable app** (PWA): web app manifest, SVG/PNG icons, a service worker served from the
  root and a public `/offline` page. The worker caches only the static shell and `/offline` in a
  cache named after the release; pages, the session and `/ips.txt` are never cached.
- The `theme-color` of the browser chrome follows the chosen skin.

### Changed
- CSP gains `manifest-src`, `worker-src` and `connect-src` for `'self'`.
- Static assets are referenced with a version query so updates propagate immediately.

## [0.1.2] - 2026-10-29

### Fixed
- Entry rows: the expiry text no longer wraps at its separator, the rail matches the time column
  and the extend and remove chips share one axis. Below 750 px the time line takes its own row.

### Added
- CI checks that a release tag matches `whitelister.__version__`.

## [0.1.1] - 2026-10-29

### Fixed
- **Non-admin API users got HTTP 401** on every refresh. The client now exchanges
  `BW_API_USERNAME` / `BW_API_PASSWORD` for a Biscuit token at `POST /auth`, sends it as Bearer
  and re-authenticates once when a call is refused. `BW_API_TOKEN` keeps working as the admin
  override. A 403 now names the missing permissions (`cache_read`, `cache_delete`, `job_run`).
- README named the job permission `job_execute`; it is `job_run`.

## [0.1.0] - 2026-10-29

First release.

### Added
- Password-protected page (no username) in the Feierabend design with six skins, English default
  and German translation via locale files.
- Shows the visitor's external address and proposes it; entries with a duration in days, an end
  date or forever; extension of existing entries; expiry rails and due-soon stats.
- `GET /ips.txt` for `WHITELIST_IP_URLS`, restricted to direct requests from
  `LIST_ALLOWED_NETWORKS` plus an optional `LIST_TOKEN`.
- Immediate BunkerWeb refresh after every change by deleting the whitelist cache file through
  the API, with a job run as fallback and a debounced background retry.
- Security model: PBKDF2 or plain password compare, per-client and global login throttling,
  server-side revocable sessions, CSRF tokens plus Sec-Fetch-Site/Origin checks, mandatory
  `TRUSTED_PROXIES`, strict CSP with nonces, body limits, JSON audit log, non-root hardened image.
- Hash-pinned dependencies, CI with tests, lint, pip-audit, Trivy image scan and GHCR publishing;
  Dependabot for pip, Docker and Actions.
- Security audit (Cloudflare security-audit skill, standard profile) with all confirmed findings
  fixed; reports under `docs/security-audit/run-1/`.

[Unreleased]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Jake-double-one/bunkerweb-whitelister/releases/tag/v0.1.0
