# Changelog

All notable changes to bunkerweb-whitelister. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Container images are published as
`ghcr.io/jake-double-one/bunkerweb-whitelister:<version>`.

## [Unreleased]

## [0.4.6] - 2026-11-12

### Changed
- The countdown after a redeemed invitation link now runs 30 seconds by default instead of 60
  (`INVITE_WAIT_SECONDS`, unchanged if you set it yourself).

### Fixed
- The countdown no longer asks the guest to stay on the page. The unlock happens on the server
  and does not depend on the page; the text now says the page may be closed and the protected
  site should simply be opened after the time shown.

## [0.4.5] - 2026-11-12

Maintenance release: everything on the newest versions, and guards so it stays that way.

### Changed
- Base image and CI moved from Python 3.14 to **Python 3.15** (`python:3.15-slim`). The image
  tag is written out in the Dockerfile's `FROM` lines so Dependabot sees it and proposes the
  next release line by itself.
- Dependencies re-pinned to the newest releases (FastAPI 0.162.5, annotated-doc 0.0.6); the
  other 19 pins already were the newest. `pip-audit` reports no known vulnerabilities.
- Dependabot now checks Python packages, the Docker base image and GitHub Actions daily
  instead of weekly.
- `docker-compose.example.yml` and the README name the current image tag (they still said
  `0.1.0`). A test now fails when the package version, `pyproject.toml`, the changelog and
  those example tags disagree, so they cannot drift apart again.

## [0.4.4] - 2026-11-08

### Added
- "Check my address again" under the big address on the operator page. It asks the server
  (`GET /whoami`, login required, never cached) which address the current request arrives from;
  when it differs from the page the page reloads, otherwise it says so and explains that the
  browser may still be using the old connection after a network change. Without JavaScript the
  button simply reloads the page.

### Notes
- The whitelister itself never caches the shown address: it is resolved from each request's
  headers, the page is sent with `Cache-Control: no-store`, and the service worker never caches
  pages. If the address stays stale after a VPN change, the old value comes from the connection
  or a proxy in front (a kept-alive HTTP/2 or migrated HTTP/3 connection keeps the peer address
  it was opened with).

## [0.4.3] - 2026-11-08

Follow-up to the second security audit (`docs/security-audit/run-2/`, run on 0.4.2). All five
confirmed findings were rated low; all are fixed here with regression tests.

### Fixed
- A redeemed invitation never shortens, relabels or re-attributes an entry the operator made:
  an existing entry for the guest's network is left alone (permanent or longer periods stay,
  the operator's label and origin stay) and is only lengthened when the link's period ends
  later. The guest page says "already unlocked" for such addresses.
- Renewing from a known address is a no-op unless it gains at least an hour; a no-op writes no
  history row and does not ask BunkerWeb to refresh, so a guest can no longer flood the history
  or the BunkerWeb API by pressing the button repeatedly.
- Removing an invite-added entry on the operator page now sticks: the link remembers the
  address as removed, the guest page says so, the slot stays spent and the button refuses
  (HTTP 409) instead of quietly re-adding the address as a "renewal". Listing the address by
  hand again lifts that block; an entry that merely ran out may still be renewed through the
  link, as documented.
- An address that is on the list because the operator added it is new to a link all the same:
  a spent link cannot lengthen it, and the guest page does not reveal that it is listed.
- When an address cannot be stored (entry cap reached, entry removed a moment ago) the guest
  page says so (HTTP 503) instead of showing the "address could not be determined" text.
- Unknown invitation tokens are still throttled per address, but no longer share a process-wide
  budget: a handful of strangers guessing tokens could lock every legitimate link holder out
  for a minute. A 192-bit token cannot be guessed, so the per-address lock is enough.
- A prefill link with a label over 64 characters or a `days` value made of non-ASCII digits
  (`²`) crashed the index page with a bare 500 without the security headers; such values are now
  dropped and the form renders. An over-long invitation name turns into a flash message instead
  of a 500.

### Changed
- `docker-compose.example.yml` was already correct; the README quick start now shows the same
  `WHITELIST_IP_URLS` with `?token=` so that following it with the example `.env` does not make
  every BunkerWeb fetch a 403.
- Dependencies re-pinned to the newest releases (FastAPI 0.162.2, pydantic 2.14.3, anyio 4.16.0,
  click 8.5.1).

## [0.4.2] - 2026-11-08

### Added
- Messenger previews for invitation links: the page carries Open Graph and Twitter card tags
  ("Access invitation: <name>", a short description) and a preview image served at `/i/og.png`,
  so the same exemption that admits guests admits link crawlers. The page is marked `noindex`.
- After a link is redeemed the page runs a purely visual countdown (`INVITE_WAIT_SECONDS`,
  default 60, CSS only) before saying "you can go ahead now", so people do not hit the protected
  site before BunkerWeb has picked the change up.

## [0.4.1] - 2026-11-08

Supersedes 0.4.0, whose release was withdrawn: its invitation page rendered unstyled behind
a login proxy. Everything below is new since 0.3.0.

### Added
- **Invitations**: shareable links for people whose address you do not know. A link carries a
  name, the access period per address, its own validity (7/14/30 days) and a budget of distinct
  addresses (IPv6 counted per /64, 0 = unlimited). The recipient opens it, sees a plain page in
  the app's language and presses one button; the address they connect from goes on the list
  under the link's name. Opening the link again from a known address only restarts that
  address's period and costs nothing; colleagues can share one link, each new address uses one
  slot. Links can be revoked at any time (addresses already listed stay until they expire).
- New card **Invitations** on the page: create links, see open ones with their remaining budget
  and redeemed addresses, revoke them. Creations, redemptions, renewals and revocations appear
  in the history and the audit log.
- `PUBLIC_URL` setting: the origin used in generated links (derived from the request when unset).

### Security
- Only a SHA-256 of an invitation token is stored, so a link is shown exactly once.
- `GET /i/<token>` never changes anything; mail scanners and link previews cannot redeem a
  link. The button is a same-origin POST. Unknown or closed tokens are throttled like wrong
  passwords, and the page never says why a link failed. Closed links are purged after 30 days.
- The invitation page carries its stylesheet inline under the request's CSP nonce and loads no
  script, so only `/i/` has to be reachable for guests. Fonts fall back to system fonts when
  `/static/` is blocked for them.

### Changed
- Dependencies: python-multipart 0.0.33; GitHub Actions checkout v7, build-push-action v7,
  metadata-action v6.

### Deployment notes
- The redeem path `/i/<token>` must be reachable without a login: exclude `^/i/.*` in a login
  proxy such as Authentik, and if BunkerWeb admits only whitelisted clients to the whitelister's
  host, add `WHITELIST_URI=^/i/` (or `GREYLIST_URI=^/i/`) on that service.
- Set `PUBLIC_URL` to the address people reach the whitelister at.
- New tables `invites` and `invite_addresses` are created on first start; 0.3.0 databases are
  migrated in place.

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

[Unreleased]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.4.6...HEAD
[0.4.6]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.3.0...v0.4.1
[0.3.0]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Jake-double-one/bunkerweb-whitelister/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Jake-double-one/bunkerweb-whitelister/releases/tag/v0.1.0
