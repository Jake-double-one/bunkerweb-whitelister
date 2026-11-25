# Security audit report: bunkerweb-whitelister (run-3)

## 1. Run facts

- Profile: **standard** (full workflow: reconnaissance, 1 coverage-led hunter wave with its post-wave critic, a separate final-clean critic, independent candidate validation, structured output, independent record verification, this report).
- Scope: the whole repository at `/home/user/bunkerweb-whitelister`, source ref `0e90ff486613c47f5951ccb13c239da522e6c1b9` (v0.4.6, clean worktree). Priority on everything changed since run-2: invitation state logic (`invite_status`, `removed_at`, renewal gain, per-address-only throttle), `GET /whoami`, the QR code on the invitation page (new dependency segno), countdown default, Python 3.15 image, re-pinned requirements, daily Dependabot.
- Budget: none set. Agents spent: 16 hunters, 20 verifiers (candidate validation and final record verification), 2 coverage critics, plus 4 reconnaissance agents.
- Execution policy: sandboxed-source-and-local-only. Every target-controlled check ran inside an OS-enforced sandbox (user+mount+network namespaces, no external network, loopback only, read-only target and toolchain, empty allow-listed environment, scratch-only writes, CPU/memory/process/file/wall-clock limits); evidence files were promoted by trusted parent-side code with the no-follow, bounded-size procedure. No deployed endpoint, no real BunkerWeb and no network service was contacted.
- Prior runs: run-1 at `033b4ce` and run-2 at `4ce6e0d` (standard). The relevant source changed since run-2 (0.4.3 to 0.4.6), so no record was carried and nothing was excluded by fingerprint. The five run-2 confirmed records were re-examined as changed-source revalidation work: four are closed in the current source, the prefill one survives in a narrower form (same fingerprint). The two run-2 needs_validation leads were re-established by current units and stay open (section 4).
- Deferred coverage: none. Out of scope by design: 1 unit (BunkerWeb's own access logging of the invite URI; a deployment fact, see section 4). Ledger status: {'candidate': 12, 'covered': 40, 'out_of_scope': 1}.
- Not source-verifiable in this run: BunkerWeb 1.6.17 itself (proxy headers it adds, HSTS, cache and job semantics), Docker's DNS answer on a two-network stack, the Docker image build, GitHub repository settings (allowed actions, token defaults, tag protection), and the owner's real network topology.

## 2. Security posture

At v0.4.6 the boundaries that matter most hold against anonymous clients and link holders: password check, sessions, CSRF, proxy-header resolution, `/ips.txt` gating, SQL/HTML/log/CSS/SVG injection, invitation tokens, hash-pinned dependencies, non-root image and gated publishing were all re-examined on the current source with no boundary violation that changes who can put an address on the whitelist. Four of the five run-2 findings are closed in source and stayed closed under revalidation (operator entries are no longer rewritten by a link, the invitation throttle no longer shares a global lock, free renewals no longer fire refreshes, a removed address is no longer silently re-added). The features added since (the `/whoami` endpoint, the QR code, the `removed` state) introduced no injection or disclosure path: `/whoami` needs a session and is never cached, the QR code is only drawn for the caller's own valid link and costs at most about 0.12 s of CPU for a 2.3 kB Host value.

Six records are confirmed, none above **low**. Two concern the operator login: the shared failure budget of the login throttle lets about 31 wrong posts per minute from anywhere keep the login closed for everyone (existing sessions keep working), and a password change does not end sessions that were opened with the old password. Three sit on the invitation lifecycle: a link with an unlimited budget can fill the shared 5000-entry list and so block the operator's own adds and every other link; the `removed` block of one link is lifted when another link re-adds the same address; and addresses removed before the upgrade to 0.4.3 carry no removal mark, so an old open link can still re-add them. The sixth is informational: a `days` value of more than 4300 digits in the prefill link still raises a bare 500 for the logged-in operator's own request. Four leads need facts the repository cannot show (section 4).

## 3. Confirmed findings

| Severity | Title | Affected boundary | Observed result |
|---|---|---|---|
| low | Operator sessions stay valid after the shared password is changed | whitelister/app.py → whitelister/app.py | Independent sandbox run: the second build loaded the same generated signing secret. The old password was refused (401), yet the pre-change cookie returned the operator page (200, with CSRF form) and POST /entries answere… |
| low | An unlimited invitation link can fill the shared 5000-entry list and block the operator's adds and every other link | whitelister/app.py → whitelister/entries.py | With the stand-in cap of 6 (source value 5000): the 8 redemptions returned 200 six times, then 503 twice; 6 entries were stored, the unlimited link showed used=6 and the mocked bw-api received 6 cache DELETE calls. The o… |
| low | A link blocked by the operator's removal can lengthen the address again once another link re-adds it | whitelister/app.py → whitelister/app.py | In the sandboxed in-process run: after the operator's delete, link A returned 409 and no entry existed. Link B returned 200 and created the entry ending 2026-11-26 (1 day). Link A then returned 200 and the same entry's e… |
| low | Addresses the operator removed before the upgrade to 0.4.3+ can still be re-added through the same open invitation link | whitelister/app.py → whitelister/app.py | Sandbox run (verifier v3-9, hand-built 0.4.2-schema database): after opening, removed_at exists and is NULL, invite_address_state = 'known', no entry. GET 200 with no change; POST 200 and entries now holds 198.51.100.50,… |
| low | Anonymous clients can close the operator login for everyone through the shared failure budget | whitelister/app.py → whitelister/app.py | The 33 wrong posts returned 401 thirty-one times, then 429 twice. The correct password from 198.51.100.20 returned 429 without a session cookie; the control instance returned 303 with a session cookie. The session opened… |
| informational | Prefill link still raises an unhandled ValueError for a days value longer than 4300 digits | whitelister/app.py → whitelister/app.py | Python 3.13.17, limit 4300. Anonymous: 303 to /login, and the login page has no next field. Logged in: days=7 gives 200 with the duration selected; 4300 digits gives 200 with CSP and Cache-Control: no-store and no durati… |

### LOW: Operator sessions stay valid after the shared password is changed

Fingerprint: `whitelister/app.py:current_session:session-survives-password-change`

**Source location.** Session validity is decided only by the cookie signature and a row in the persistent sessions table (current_session, session_valid). No credential generation is stored with the session or checked at start-up, so changing the configured password neither purges nor invalidates existing rows.

**Lower-trust principal.** A holder of a session cookie that was issued before the operator changed the shared password.

**Bounded reproduction (target-native).**
1. Build the app in-process with a file-backed store in an empty DATA_DIR, no SESSION_SECRET (key generated into DATA_DIR/session.key), COOKIE_SECURE=no and dummy password A; log in and keep the cookie and the page's CSRF token.
2. Close the store and build the app again on the same DATA_DIR with a different dummy password B.
3. POST /login with password A and observe the status.
4. Send GET / and then POST /entries with the kept cookie and token and read the entries table.
5. Delete DATA_DIR/session.key, build the app once more and repeat GET / with the kept cookie.

Payloads:
- `Cookie: wl_session=<cookie issued under the old password>`
- `POST /entries  network=192.0.2.55&label=after-rotation&duration=forever&_csrf=<token from the page fetched with that cookie>`

**Conditions.**
- authentication_level: The actor already holds a valid session cookie obtained with the previous password (a former co-operator, or someone who used a leaked password before it was changed).
- system_configuration: The password is changed without also changing SESSION_SECRET or deleting DATA_DIR/session.key, and DATA_DIR is kept across the restart (the documented volume setup).
- timing_dependency: The session is used before its own lifetime ends: SESSION_HOURS after login, 12 h by default, up to 30 days if configured.

**Actual result.** Independent sandbox run: the second build loaded the same generated signing secret. The old password was refused (401), yet the pre-change cookie returned the operator page (200, with CSRF form) and POST /entries answered 303 to / and the entries table held 192.0.2.55 labelled after-rotation with expires_at NULL. Only after session.key was also removed did the cookie get 303 to /login.

**Impact.** Operator authority over the whitelist continues for the rest of the session lifetime after access was meant to be withdrawn; entries added then have no expiry and stay after the session ends. Observed: one permanent dummy entry written.

**Priority rationale.** Likelihood low: Needs a session obtained with the old password and use within the remaining session lifetime; the operator must change the password without rotating the session secret, which is the natural way to do it. Impact medium. Overall low. Confidence high: Every trace and evidence line was checked against the source, and the result was reproduced independently in the sandbox with a file-backed data directory; removing the generated key was shown to be a separate manual step.

**Smallest source fix.** Tie stored sessions to the configured credential: keep a keyed fingerprint of the current password or password hash in the meta table and drop all session rows at start-up when it differs. Regression test: log in, rebuild the app on the same data directory with another password, and assert the old cookie is redirected to /login. Also state in the README that a password change ends all sessions.

### LOW: An unlimited invitation link can fill the shared 5000-entry list and block the operator's adds and every other link

Fingerprint: `whitelister/app.py:invite_redeem/EntryStore.upsert:unlimited-link-fills-shared-entry-cap`

**Source location.** The per-link budget is the only limit on new addresses and 0 disables it: Invite.remaining is None, so the check `seen is None and invite.remaining == 0` in invite_status never fires. EntryStore.upsert checks one COUNT(*) over all rows before any insert or update, so one link's entries use up the capacity the operator and other links depend on. invite_throttle counts only failed token lookups, and invite redemptions call refresh_after_change directly instead of the debounced Syncer.

**Lower-trust principal.** Holder of an unlimited invitation link, not logged in, sending POST /i/{token} from different /64 networks.

**Bounded reproduction (target-native).**
1. Build the app in-process (ASGI transport, in-memory store, mocked BunkerWeb API, TRUSTED_PROXIES=10.0.0.0/8) and set whitelister.entries._MAX_ENTRIES to 6 in the harness process as a stand-in for 5000.
2. Log in as the operator and create one link with max_addresses=0 and a second link with max_addresses=3.
3. Send the redemption POST for the unlimited link from 8 different /64 networks.
4. Send one redemption POST for the second link from 198.51.100.7.
5. As the operator, POST /entries for the new address 192.0.2.10 and for one network that is already listed, and load the page after each.
6. Revoke the unlimited link, delete one of its entries and repeat the add for 192.0.2.10.

Payloads:
- `POST /i/<token> with headers Host: wl.example, Origin: http://wl.example, Sec-Fetch-Site: same-origin, X-Forwarded-For: 2001:db8:77:<n>::1 for n = 0..7, sent through the trusted proxy peer 10.0.0.5`

**Conditions.**
- system_configuration: The operator has created a link with 'unlimited' addresses (or several open links whose budgets together reach the cap; the handler accepts budgets up to 1000 and the store allows up to its open-link maximum).
- authentication_level: The requester holds that link's URL; no login is needed.
- network_routing: The requester can originate requests from about 5000 distinct addresses as resolved by the app (distinct IPv4 hosts or IPv6 /64s, for example a routed /48), and the front proxy does not rate-limit or block POST /i/ requests. That proxy behaviour is not visible in the repository.
- data_state: IPv6 /64 entries must pass the entry policy; the default MIN_PREFIX_V6=48 accepts them.

**Actual result.** With the stand-in cap of 6 (source value 5000): the 8 redemptions returned 200 six times, then 503 twice; 6 entries were stored, the unlimited link showed used=6 and the mocked bw-api received 6 cache DELETE calls. The other link's guest got 503. The operator's add for 192.0.2.10 returned 303 with the flash 'The list is full' and was not stored; the operator's update of an already listed network was refused with the same flash. After revoking the link and deleting one entry the operator's add succeeded.

**Impact.** Availability of list management only: new adds, updates through the add form, imports and other guests' redemptions fail until the operator revokes the link and deletes entries; existing entries, extensions and the served list are unaffected. Each inserted entry is also a whitelisted network of the holder's own, which the link grants by design. Observed with a stand-in cap of 6.

**Priority rationale.** Likelihood low: Needs an operator-issued unlimited link (not the default choice), a holder or someone who obtained the URL willing to abuse it, and thousands of distinct source networks reaching the app through the front proxy. Impact low. Overall low. Confidence medium: The path and the shared cap are plain in source and the effect was reproduced locally with a reduced cap; the full 5000 case and any limiting by the BunkerWeb front proxy were not observed.

**Smallest source fix.** Give every link a finite ceiling and keep capacity for the operator: treat 'unlimited' as a fixed maximum (for example 100 addresses), count a link's live entries against a per-link share of the cap, and reserve headroom so invite redemptions are refused before the operator's own adds are. Add a per-link rate limit for new addresses (a few per minute) and route invite-driven refreshes through the debounced Syncer instead of one bw-api call each. Let upsert skip the cap check when the network already exists, and give the operator a way to remove all entries a link added. Regression case: an unlimited link redeemed from more addresses than its ceiling returns 409, and an operator add still succeeds.

### LOW: A link blocked by the operator's removal can lengthen the address again once another link re-adds it

Fingerprint: `whitelister/app.py:invite_status:removed-tombstone-lifted-by-any-active-entry`

**Source location.** invite_status returns 'removed' only for `seen == "removed" and not active`, and `active` is true for any unexpired entry of the network, whoever created it. The removal mark is stored per link and network and is set only on links that had already seen the address, so another link can supply the active entry; the redeem path then lengthens it with set_expiry.

**Lower-trust principal.** A guest who holds two open invitation links and whose address the operator removed from the list.

**Bounded reproduction (target-native).**
1. In the in-process test app, create link A (14 days per address) and redeem it from 198.51.100.5.
2. As operator, delete the entry for 198.51.100.5 and confirm that a POST with link A from that address returns 409.
3. Create link B (1 day per address, budget 1) and POST it from 198.51.100.5.
4. POST link A again from 198.51.100.5 and read the entry's expiry from the store.

Payloads:
- `POST /i/<token of link B> from the removed address`
- `POST /i/<token of link A> from the removed address`

**Conditions.**
- authentication_level: The guest holds two open invitation links for the same installation; no login is needed.
- data_state: The operator removed the guest's address after the first link added it and left both links open; the second link has not seen that address and has budget left; the first link's access period is at least one hour longer than what remains on the entry the second link created.
- network_routing: The guest still connects from the removed address (same IPv4 address or IPv6 /64).

**Actual result.** In the sandboxed in-process run: after the operator's delete, link A returned 409 and no entry existed. Link B returned 200 and created the entry ending 2026-11-26 (1 day). Link A then returned 200 and the same entry's end moved to 2026-12-09 (14 days), while link A's removal mark stayed set. After the entry's end was set to the past, link A returned 409 again.

**Impact.** Only the guest's own address stays listed for the first link's period instead of the second link's shorter one; no other address or data is affected, and the second link alone already re-admits the address.

**Priority rationale.** Likelihood low: Needs a guest with two open links whose access periods differ, after an operator removal that left both links open. Impact low. Overall low. Confidence high: Every trace line was checked in source, and an independent sandboxed in-process run showed the 409, the re-add through the second link, and the extension through the blocked link.

**Smallest source fix.** Make the removal mark authoritative for the link: return 'removed' whenever the link's row for the network has removed_at set, and clear removed_at only when the operator lists the address by hand (the /entries add path and import). Add a regression test in which a second link re-adds a removed address and the first link still gets 409, and one in which a hand-made entry lifts the block.

### LOW: Addresses the operator removed before the upgrade to 0.4.3+ can still be re-added through the same open invitation link

Fingerprint: `whitelister/entries.py:EntryStore.__init__:removed_at-migration-no-backfill`

**Source location.** EntryStore.__init__ migrates with a bare ALTER TABLE invite_addresses ADD COLUMN removed_at and leaves every existing row at NULL; invite_address_state maps NULL to 'known', and invite_status returns 'ready' for 'known' with no active entry (the state meant for an entry that ran out). The older schema recorded nothing in invite_addresses on deletion, so the migration default classifies pre-upgrade operator deletions as expired entries, even though the events table may still hold the 'delete' row.

**Lower-trust principal.** Invitation-link holder whose address the operator removed from the whitelist before upgrading from 0.4.2.

**Bounded reproduction (target-native).**
1. Create the legacy SQLite file with dummy data as described in the payload.
2. Open it with the current EntryStore and build the app in-process (ASGI transport, no network, BunkerWeb client mocked).
3. Send GET, then POST /i/<token> as the guest from 198.51.100.50 and read the entries table.
4. Control: delete the re-created entry with the current EntryStore.delete and repeat the POST.

Payloads:
- `SQLite file with the 0.4.2 schema (invite_addresses without removed_at): one open invite (access_days 14, max_addresses 1), one invite_addresses row for 198.51.100.50, no entries row, one events row action='delete' for 198.51.100.50`
- `POST /i/<token> with X-Forwarded-For: 198.51.100.50 through the trusted proxy peer, Host wl.example, Origin http://wl.example, Sec-Fetch-Site: same-origin`

**Conditions.**
- authentication_level: The requester holds the invitation link (bearer capability) and comes from the address (IPv4 host or IPv6 /64) that this link had added earlier.
- data_state: The database was created by 0.4.1 or 0.4.2, the operator deleted a link-added entry on that version, did not revoke the link, and the link is still within its validity after the upgrade.
- timing_dependency: The exposure ends when the link expires or is revoked, at the latest 30 days after the link was created.

**Actual result.** Sandbox run (verifier v3-9, hand-built 0.4.2-schema database): after opening, removed_at exists and is NULL, invite_address_state = 'known', no entry. GET 200 with no change; POST 200 and entries now holds 198.51.100.50, label 'Legacy', created_by 'invite:Legacy', expiry 14.0 days ahead, while the link still counts 1 of 1 addresses. Control after EntryStore.delete on the current version: state 'removed', POST 409, no entry.

**Impact.** One address the operator had explicitly removed is whitelisted again for the link's access period. It is the guest's own address, shown in the history, and the operator can delete it again (which then sticks) or revoke the link. No other address, no budget bypass for new addresses.

**Priority rationale.** Likelihood low: Needs a deletion of a link-added entry on 0.4.1/0.4.2 without revoking the link, an upgrade while that link is still open (links live at most 30 days; 0.4.1 to 0.4.3 carry the same changelog date), and the guest pressing the button again from the same address. Impact low. Overall low. Confidence high: Complete source trace with all line references checked, old schema compared against commit 4ce6e0d, and an independent in-sandbox reproduction with a control for the current deletion path. The legacy database was built by hand to that schema, not produced by running 0.4.2.

**Smallest source fix.** Backfill once when the column is added: mark as removed every legacy invite_addresses row that has no entry row and whose latest history event for that network is 'delete'. The history keeps only 200 rows, so this is best effort; a stricter fail-closed variant marks every legacy row without an entry row (the operator lifts it by listing the address by hand, at the cost of also blocking renewal of entries that merely ran out). Add a regression test that opens a 0.4.2-schema database and expects 409. Additionally or alternatively, state in the 0.4.3 upgrade notes that links whose addresses were removed earlier should be revoked.

### LOW: Anonymous clients can close the operator login for everyone through the shared failure budget

Fingerprint: `whitelister/security.py:LoginThrottle.global-budget-locks-all-clients`

**Source location.** LoginThrottle.record_failure sets one _global_until for the whole process when the per-minute failure count from all keys exceeds global_budget, and retry_after applies that value to every key before the password is looked at. Nothing distinguishes the clients that caused the failures from an uninvolved client, and nothing lets a correct password or a previously successful browser pass.

**Lower-trust principal.** Anonymous internet client with several source addresses, no password and no invitation link.

**Bounded reproduction (target-native).**
1. Build the app in-process with default throttle settings, a dummy plain password, TRUSTED_PROXIES=none and an empty data directory; drive it through an in-process ASGI transport with a chosen peer address per client. Build a second, untouched instance as a control.
2. Log in once with the correct password from 198.51.100.10 and keep the session cookie.
3. Send three wrong-password posts from each of eleven peers in different /64s.
4. Send one post with the correct password from 198.51.100.20, which was not used before, and the same post to the control instance.
5. Request / with the session cookie from the second step.
6. Step LoginThrottle(3, 30) with a synthetic clock: 31 failures from 31 keys, then ask retry_after for an unused key shortly after and 60.1 seconds after the last failure.

Payloads:
- `POST /login with form body password=wrong-N-J, three times from each of 2001:db8:0:0::1 ... 2001:db8:0:a::1`
- `POST /login with the correct password from 198.51.100.20`

**Conditions.**
- authentication_level: None: any client that can reach POST /login.
- network_routing: Requests must arrive under several throttle keys: about eleven per cycle at the default LOGIN_MAX_FAILURES=3 (IPv4 addresses, or /64s of one IPv6 prefix), and mostly fresh keys for each further cycle.
- environmental_dependency: A fronting BunkerWeb request limit or bad-behaviour ban acts per address and may slow the client; it is outside this repository and was not observed.
- data_state: The operator has no valid session at that moment; existing sessions are not affected.
- timing_dependency: Each lock lasts 60 seconds and cannot be extended while active; the login is open between cycles for as long as the client needs to record 31 new failures.

**Actual result.** The 33 wrong posts returned 401 thirty-one times, then 429 twice. The correct password from 198.51.100.20 returned 429 without a session cookie; the control instance returned 303 with a session cookie. The session opened beforehand still got 200 on /. With the synthetic clock an unused key had retry_after 60 right after the 31st failure and 0 at 60.1 seconds after it; 30 failures in one window left an unused key at 0.

**Impact.** Only new operator logins are refused; existing sessions, the list download and invitation links continue, no data is exposed or changed, each lock ends after 60 seconds without further action, and the login reopens briefly between cycles.

**Priority rationale.** Likelihood medium: Unauthenticated and cheap (31 small requests per cycle), but it needs several source addresses or a routed IPv6 prefix and a reason to target a single-operator tool; a fronting WAF may slow it. Impact low. Overall low. Confidence high: Reproduced in-process in the sandbox against the current source with default settings and a control instance; the behaviour is also stated in the README and the class docstring. The effect of a fronting BunkerWeb was not observed.

**Smallest source fix.** Keep the per-address lock and the two-slot hashing cap as the CPU bound, and stop the shared budget from refusing clients that did not contribute to it. Preferred: set a signed long-lived 'this browser has logged in before' cookie on a successful login and let requests carrying it bypass only the shared lock (their own per-address lock still applies). Alternative: when the budget is exceeded, refuse only keys that already have a recorded failure; note that this lets a client with many fresh keys keep guessing at one attempt per key, bounded by the hashing cap rather than by the budget. Add a regression test in which 31 failures from other addresses are followed by a successful login with the correct password from the exempted client.

### INFORMATIONAL: Prefill link still raises an unhandled ValueError for a days value longer than 4300 digits

Fingerprint: `whitelister/app.py/prefill_from_query/unhandled-ValidationError-ValueError`

**Source location.** prefill_from_query converts the days query value with int() after checking only isascii() and isdecimal(). The interpreter's integer string conversion limit (default 4300 digits, not changed by the application or the Dockerfile) makes int() raise ValueError for longer all-digit strings, including values that are mostly leading zeros. Neither prefill_from_query nor index catches it, and the app registers no exception handler, so the exception passes through SecurityHeadersMiddleware.dispatch before the headers are set.

**Lower-trust principal.** A logged-in operator session requesting the list page with a prefill link whose days value is an over-long digit string.

**Bounded reproduction (target-native).**
1. Build the application in-process with dummy settings, an in-memory store and a mock bw-api transport, and drive it through httpx.ASGITransport as a trusted proxy peer.
2. Without a session, request /?add=me&days= followed by 4301 digits and follow the redirect to the login page.
3. Log in with the dummy password, then request /?add=me&days=7 and the same path with 4300 digits as controls.
4. Request the path with 4301 digits and with 4300 zeros followed by 7; record status, body and headers, then request / again and read the entry count.
5. Repeat the 4301-digit request with application exceptions re-raised to capture the exception type and frames.

Payloads:
- `GET /?add=me&days=<the digit 7 repeated 4301 times>`
- `GET /?add=me&days=<4300 zeros followed by 7>`

**Conditions.**
- authentication_level: The request must carry a valid operator session; without one GET / only redirects to /login, and the over-long next value is dropped there.
- user_interaction: The operator has to request the URL within their own session (typed, pasted or followed from the app's origin); the session cookie is SameSite=Strict according to the architecture summary, which was not re-tested here.
- environmental_dependency: The interpreter keeps the default integer string conversion limit of 4300 digits. Observed on the local Python 3.13 environment; the image's Python 3.15 was not run, and the Dockerfile sets no PYTHONINTMAXSTRDIGITS.

**Actual result.** Python 3.13.17, limit 4300. Anonymous: 303 to /login, and the login page has no next field. Logged in: days=7 gives 200 with the duration selected; 4300 digits gives 200 with CSP and Cache-Control: no-store and no duration selected; 4301 digits and 4300 zeros plus 7 each give 500 'Internal Server Error' with no Content-Security-Policy and no Cache-Control header. The following GET / is 200 with headers, and the entry count is 0. With exceptions re-raised: ValueError 'Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits' through app.py:89 dispatch, app.py:535 index, app.py:270 prefill_from_query.

**Impact.** Only the requesting session's own page view fails with a static plain-text 500 and a logged traceback; no data, stored state or other principal is affected, and the next request works.

**Priority rationale.** Likelihood low: Needs a valid operator session and the operator requesting a crafted URL themselves; the anonymous login-redirect route drops the over-long value. Impact informational. Overall informational. Confidence high: Every trace and evidence line was re-read in the current source and the result was reproduced independently in the sandbox with boundary controls (4300 vs 4301 digits) and the raising frames captured. Not run on the image's Python 3.15 or over a real socket.

**Smallest source fix.** Bound the length of the days value before converting it (a preset never needs more than a few digits) or compare the string with the presets rendered as text, and add a long digit string to the existing regression test. A catch-all exception handler that keeps the security headers on error responses would cover future cases of the same kind.

## 4. Needs validation

These are source-grounded leads whose decisive fact lies outside the repository. They carry no severity and are not confirmed vulnerabilities.

| Lead | Repository trace | Exact blocker | Bounded local next step | Owner-observed deployment check |
|---|---|---|---|---|
| Image job gives a packages:write token to tag-pinned actions on every event; the main/tag condition guards only the publish steps | .github/workflows/ci.yml:70 → .github/dependabot.yml:12 → .github/workflows/ci.yml:7 → .github/workflows/ci.yml:43 → .github/workflows/ci.yml:103 | The scenario requires a malicious or compromised upstream action release or a moved action tag; this cannot and must not be produced locally, and no sandbox execution of workflow code is possible offline. | Source reading only: confirm in .github/workflows/ci.yml that `packages: write` is at job level (line 45), that the ref condition is only on lines 92, 100 and 109, and that no `uses:` value ends in a … | Repository owner, read-only: (1) open the latest CI run on main and the latest Dependabot-triggered run, expand `Set up job` of the image job and read the `GITHUB_TOKEN Permissions` block for `Package… |
| Example compose leaves a second, untrusted path from BunkerWeb to the whitelister (bw-universe) | docker-compose.example.yml:39 → docker-compose.example.yml:20 → docker-compose.example.yml:51 → .env.example:15 → whitelister/security.py:256 → whitelister/app.py:476 → whitelister/app.py:789 | Not source-visible and not observable locally (no Docker in the sandbox): which address or addresses Docker's embedded DNS returns to the bunkerweb and bw-scheduler containers for `whitelister` when they share two networks with it, and whether the order is sta | The app-side half is settled in-process (harness.py in the verifier scratch, TRUSTED_PROXIES=10.20.30.2/32, LIST_ALLOWED_NETWORKS=10.20.30.0/24, dummy password and list token, no BW_API_URL): requests… | Read-only owner check on the running stack: `docker exec bunkerweb getent hosts whitelister` (same for bw-scheduler); in the whitelister's JSON audit lines on stdout look for client addresses in 10.20… |
| Trailing-slash redirect answers with an absolute http:// URL that repeats the invitation token path | whitelister/app.py:754 → whitelister/__main__.py:29 → whitelister/app.py:152 | Whether the deployed BunkerWeb adds Strict-Transport-Security to this 307 (or the host is already known as HSTS to the client) is a deployment fact outside this repository; with it, browsers upgrade the redirect and nothing goes out in cleartext. | In-process with httpx.ASGITransport, base URL scheme http (as uvicorn reports it), default settings and dummy secrets: GET /i/<any 32 characters>/ and POST /login/, do not follow redirects, read statu… | The owner sends, from their own machine and with a non-browser client that does not follow redirects, GET https://<own host>/i/x/ and GET https://<own host>/login/ through BunkerWeb (x is a dummy, no … |
| /ips.txt direct-request gate ignores TRUSTED_PROXIES and the configured CLIENT_IP_HEADER | whitelister/app.py:447 → whitelister/app.py:450 → whitelister/security.py:278 → whitelister/app.py:453 → whitelister/app.py:458 | The request headers the deployed reverse proxy adds are not source-visible. The path is live only if the proxy relays a request without X-Forwarded-For, Forwarded, X-Real-IP, X-Forwarded-Host and X-Forwarded-Proto. BunkerWeb 1.6.17's generated reverse-proxy co | Done by v3-8 in the sandbox (scratch check-v38-cf.json, check-v38-default.json, check-v38-token.json; not promoted, re-run to reproduce): create_app(load_settings()) with dummy secrets, TRUSTED_PROXIE… | Owner only, on their own stack, read-only: (1) check whether LIST_TOKEN is non-empty in the running container; if it is, the path is closed. (2) From outside, request https://<public host>/ips.txt wit… |

Full text of every lead: `NEEDS-VALIDATION.md`.

### Owner-observed notes (not findings, not units)

Recorded by the coverage critics; each depends on BunkerWeb or proxy behaviour that the repository cannot show.

- **Invitation token in reverse-proxy logs (out-of-scope unit)**: Whether BunkerWeb writes the request URI of `/i/<token>` to its access log is a deployment fact. The app itself runs uvicorn with the access log off. An owner can check the BunkerWeb log format; anyone who can read those logs holds the links.

- **QR code shows the link as an image**: By design the invitation page draws its own link as a QR code on wide screens while the link has a slot left. The same URL is in the address bar, but a screen share or a photo of the screen hands the link on more easily. `INVITE_QR=no` turns it off; the code is hidden in print and on narrow screens.

- **QR generation on the event loop**: `qr_code` runs synchronously and has no explicit length cap; with `PUBLIC_URL` unset a link holder can send a Host header of about 2.3 kB and cost about 0.12 s of CPU per request (measured, linear, bounded by the QR capacity). Not a finding; capping the text length and setting `PUBLIC_URL` remove it.

## 5. Hardening notes

Non-findings recorded by the hunters (no reachable boundary violation; worth doing, not security defects). Grouped by file.

**README.md**
- README.md:253-256: of the two options offered for a restricted host, prefer GREYLIST_URI=^/i/. WHITELIST_URI needs USE_WHITELIST=yes on the whitelister's own service, which contradicts the compose label USE_WHITELIST=no and lets every listed address (including addresses added through a link) skip BunkerWeb's /login limit and bad-behaviour checks; only the app's own throttle remains.

**docker-compose.example.yml**
- docker-compose.example.yml: attach the whitelister to bunkerweb through one network only, or pin both of bunkerweb's addresses and list both in TRUSTED_PROXIES; also consider ALLOW_PRIVATE=no in .env.example so an invitation cannot list a proxy or bridge address when the client address is resolved wrongly.
- docker-compose.example.yml:82-93: other containers on bw-services or bw-universe can open whitelister:8080 directly and so bypass BunkerWeb's /login rate limit (the app throttle still applies). Containers keep CAP_NET_RAW by default, so a compromised neighbour on bw-services could in principle impersonate 10.20.30.2 at layer 2; keep untrusted workloads off that bridge.

**general**
- Any account with push rights can publish release tags by pushing a v* tag from any commit, and can overwrite an existing image tag; a tag ruleset and immutable release tags would bind releases to main.
- CI test job installs pip, pytest, ruff and pip-audit unpinned; it holds only contents:read and no secrets, so this affects only the gate's reliability. A hashed dev requirements file would close it.
- Pin every action to a full commit SHA with the version as a comment; Dependabot keeps SHA pins current.
- Pin python:3.15-slim and the docker/dockerfile frontend by digest (Dependabot's docker ecosystem updates digests); add `--only-binary :all:` to the Dockerfile pip install so a missing cp315 wheel cannot fall back to an sdist build with unpinned build requirements.
- Push the image that was smoke-tested and scanned (build once, push by digest) instead of rebuilding from context in the Push step.
- Split publishing into its own job (needs: image, `if:` main or v* tag, optionally a protected environment) that alone holds packages:write; give the build/scan job contents:read and security-events:write only.
- pyproject.toml dependencies omit segno and are unpinned; add segno and a test that requirements.in equals the pyproject dependency list. scripts/compile-requirements.sh installs pip-tools unpinned and uses the developer's ambient pip configuration.
- requirements.txt is compiled with Python 3.13 while the image runs 3.15; --require-hashes fails closed on a missing pin, but compiling under the image's Python line avoids marker drift.
- .env.example:51 / config.py: the placeholder check covers LIST_TOKEN but not the copy of the token inside WHITELIST_URL; harmless (the cache name would simply not match), but a hint in the error text would save a debugging round.
- Dockerfile:24-33: `... && pip uninstall -y pip setuptools wheel 2>/dev/null || true && rm ...` — because && and || have equal precedence, `|| true` also swallows a failure of apt-get update/upgrade earlier in the chain; the build then continues without the Debian security patches and without an error. Group the uninstall as `(pip uninstall ... || true)` so apt failures fail the build.
- A CLIENT_IP_HEADER other than X-Forwarded-For is taken verbatim from a trusted peer (whitelister/security.py:273). If the trusted proxy passes the header through instead of overwriting it (for example BunkerWeb behind a CDN but also reachable directly), clients choose their own identity for throttling and invitation redemption. The README could state that the trusted proxy must set or strip this header itself.
- An empty LIST_TOKEN_FILE (or one holding only whitespace) is read as 'no token' (whitelister/config.py:214), so a botched secret file silently reduces /ips.txt to the network gate; failing start-up when a *_FILE variable is set but empty would make this visible.
- In docker-compose.example.yml whitelister, bunkerweb and bw-scheduler share both bw-services and bw-universe, so the name 'whitelister' can resolve to the bw-universe address. The scheduler would then fetch from 10.20.40.x (outside the example LIST_ALLOWED_NETWORKS, 403) and the ingress would arrive from an unpinned address outside TRUSTED_PROXIES (all clients seen as one private address). Both fail closed; pinning addresses or giving the whitelister a per-network alias removes the ambiguity. The ingress leg belongs to the peer-owned whitelister compose unit.
- LIST_ALLOWED_NETWORKS defaults to every private, loopback and ULA range and LIST_TOKEN is optional. Where the container port is published through a NAT that rewrites the source to a private gateway address (the CI smoke test relies on this), /ips.txt is open to whoever reaches the port. A narrower default or a start-up warning when no token is set would help.
- ips_txt could refuse any peer inside TRUSTED_PROXIES unless it is explicitly listed for the list fetch, and treat the configured CLIENT_IP_HEADER (plus Via) as a forwarding header; this closes the candidate without relying on what the ingress adds.
- resolve_client_ip returns the proxy's own address when a trusted peer sends no client header (whitelister/security.py:260-261); returning no client (as for an unparsable chain) would avoid attributing logins and redemptions to the proxy address.
- Dependency CVE status could not be checked offline (pip-audit is out of bounds here); pins are exact and hash-locked, CI runs pip-audit.
- POST routes parse the form before the session check (FastAPI parameters), so /import accepts up to 256 KiB of multipart from anyone before answering; reading the upload only after require_post would keep the pre-login limit at 16 KiB.
- Pass redirect_slashes=False to FastAPI(...) in whitelister/app.py so that slash variants are a plain 404 instead of an absolute http:// redirect (see candidate).
- SecurityHeadersMiddleware (app.py:83) uses str.isdigit() before int(); a superscript digit would raise. h11 rejects such a Content-Length first, so it is unreachable today; isascii() and isdecimal() as in prefill_from_query would make it independent of the server.
- SessionCodec.check_csrf (security.py:115-118) raises TypeError on a non-ASCII token; compare bytes (token.encode()) or reject non-ASCII first so the request ends as the normal CSRF refusal instead of a 500.
- expiry_from_date (entries.py:81) and _parse_import_expiry (app.py:922) can raise OverflowError near year 9999 / year 1 with an offset; catch it as error.date_invalid. Operator-only, nothing is written.
- GET /whoami returns `note` (hero text) and `listed`, which static/app.js never reads; trimming the response to `ip` would keep the endpoint to what its only consumer needs.
- The unhandled ValueError in prefill_from_query writes a traceback to the server log for each such request; the length bound proposed for the candidate also removes that noise.
- GET /export includes rows that have expired but are not yet purged, and the import skips them; harmless, but filtering expired rows at export would keep the backup equal to the active list.
- POST /import is not all-or-nothing once validation passes: the row cap is checked per upsert (entries.py:242), so when the store fills mid-import the earlier rows stay, the handler returns at app.py:895 without audit_event('import') and without refresh_after_change. Observed with 4999 rows + 3 new networks: 1 added, in the list, no bw-api call, no audit line. Operator-only and the on-page history row is written, so this is not a boundary failure; fix by checking store.count() + new networks against the cap before writing, or by writing all rows in one transaction, and by emitting the audit line and refresh for whatever was written.
- POST /import runs every upsert and event_add synchronously on the event loop in autocommit mode (three statements and commits per item). Items that name an existing network do not count against the 5000 cap, so a 256 KiB file can carry roughly 11000 items; 4000 items took about 3 s in the sandbox, during which /ips.txt, /healthz and the invitation page wait. Only a logged-in operator with a CSRF token can send it. Cap len(items) at 5000 before the loop, dedupe by network, and wrap the writes in one transaction (or run them in a thread).
- The 'confirmed' / 'BunkerWeb last picked the list up at' indicators treat any successful /ips.txt request as BunkerWeb's fetch. Any host inside LIST_ALLOWED_NETWORKS (default: all private ranges and loopback) that requests the list flips the indicator although BunkerWeb may not have the entry yet. Display only. Setting LIST_TOKEN or narrowing LIST_ALLOWED_NETWORKS to the scheduler address makes the indicator mean what it says.
- _parse_import_expiry (app.py:913-925) catches ValueError only: an ISO string near datetime.min/max with a UTC offset ('0001-01-01T00:00:00+23:59', '9999-12-31T23:59:59-23:59') raises OverflowError in astimezone and the request ends in a 500 instead of the 'date invalid' message. Nothing is written. Catch OverflowError alongside ValueError.
- A valid link resets that address's invite failure counter (open_invite record_success); harmless with 192-bit tokens, and owned by the invite throttle unit.
- Deleting an operator-made entry also tombstones every link that merely redeemed over it; this is conservative, but the guest then sees 'removed' for an address the link never added.
- Removing an address does not stop the link holder from returning under a new address while the link has budget; the removal flash could remind the operator to revoke the link.
- same_origin accepts a POST that carries neither Sec-Fetch-Site nor Origin; requiring one of them on POST /i/{token} would close the legacy-browser gap at the cost of non-browser clients.
- The QR code renders the bearer token as a scannable image on wide screens in states ready/known/done. That is the documented purpose and the same URL is in the address bar, but a screen share or screenshot of the confirmation page now leaks a usable link while slots remain; operators who do not want this have INVITE_QR=no. The README could say so explicitly.
- public_origin falls back to the unvalidated Host header when PUBLIC_URL is unset. On the invite page this only reflects into the requester's own no-store response (og:url, og:image, QR). Requiring PUBLIC_URL, or checking Host against an allowlist, would remove the request-derived origin for the QR and OG tags as well as for the operator's invite link (the latter is owned by the peer unit on POST /invites).
- The app version is readable without login (/sw.js, page header, asset query strings). It only matters as a fingerprint for known-version issues.
- safe_next (whitelister/app.py:251) accepts tab, CR, LF and NUL after the leading slash; an off-origin redirect is prevented only because Starlette's RedirectResponse percent-encodes the Location. Refusing any character below 0x20 (and 0x7f) in safe_next would keep the guarantee if the response type ever changes.
- An IPv4-mapped client address (::ffff:a.b.c.d) from the proxy ends in 'address could not be determined' (400) instead of being treated as its IPv4 self as in_networks does for peers; fail-closed, usability only.
- The fixed /64 for IPv6 redemptions is wider than one subscriber for transition prefixes such as Teredo (2001:0:<server>::/64 covers all clients of one relay server); consider listing the /128 for 2001::/32.
- The tombstone is permanent per (link, address): after the operator lists the address by hand again and that entry later runs out, the link is refused again (fail-closed, stricter than the README sentence 'lifts the block'). Document or clear removed_at on a manual re-add.
- invite_redeem (whitelister/app.py:783) uses the access_days stored at creation without min(..., settings.max_days): after MAX_DAYS is lowered, open links still grant the old period (observed 365 d under MAX_DAYS=30). Cap at redemption or log open links above the limit at startup, as is done for entries.
- parse_network's ALLOW_PRIVATE=no check relies on ipaddress.is_private, which does not cover 100.64.0.0/10 (shared address space); a redemption from 100.64.1.1 was accepted with ALLOW_PRIVATE=no. Use 'not is_global' if only public addresses are meant.
- redeemer_network (whitelister/app.py:286-289) drops an IPv6 zone id by converting to a network before parse_network sees it: a resolved client 'fe80::1%eth0' lists fe80::/64 when ALLOW_PRIVATE=yes, while parse_network refuses scoped input for operators. Refuse addresses with scope_id (and link-local) for redemptions.
- EntryStore.upsert applies the 5000-row cap before the conflict check, so at the cap an existing entry cannot be updated via POST /entries (fail-closed usability defect; extend still works).
- Operator-only unhandled exceptions (HTTP 500, no state change, session+CSRF required): duration=date with until=9999-12-31 raises OverflowError in expiry_from_date (whitelister/entries.py:81) on POST /entries and /entries/{id}/extend; a path id above 2^63-1 raises OverflowError in sqlite binding for extend and delete. Catch OverflowError as error.date_invalid and bound entry_id (e.g. Path(ge=1, le=2**63-1)).
- Rows that violate a tightened policy keep being served by /ips.txt (a 'forever' row indefinitely); this is documented and logged once at startup only. Consider flagging such rows in the entry list so the operator sees them without reading container logs.
- int() parsing of duration accepts surrounding whitespace, a sign, underscores and non-ASCII digits (e.g. U+0667); values stay bounded to 1..MAX_DAYS, so this is cosmetic. raw.isascii() and raw.isdecimal() as in prefill_from_query would align the paths.
- parse_network accepts IPv4-mapped IPv6 (::ffff:8.8.8.8, and ::ffff:0.0.0.0/96 which satisfies MIN_PREFIX_V6 while denoting all of IPv4) and, with ALLOW_PRIVATE=no, still accepts 100.64.0.0/10 (CGNAT) addresses and supernets only partly private. Operator-authored only, effect in BunkerWeb not source-visible; consider rejecting ipv4_mapped networks and using 'not is_global' / overlap tests for the private check.
- A new login does not remove the row of a session cookie the browser already presents (whitelister/app.py:497-499), and logout ends only the current session; there is no operator action to end all sessions short of rotating the session secret. Same principal, so not a finding by itself.
- POST /login has no token and relies on same_origin plus SameSite; a client that sends neither Sec-Fetch-Site nor Origin is accepted. Login CSRF has no cross-principal effect here because there is one shared operator account.
- POST /logout (whitelister/app.py:504-512) relies on the CSRF token alone and does not call same_origin like the other posts; the token is sufficient, the extra check would only make the routes uniform.
- SessionCodec.check_csrf (whitelister/security.py:118) passes the submitted token as str to hmac.compare_digest; a non-ASCII _csrf value raises TypeError and the request ends in a 500 instead of the normal CSRF redirect. It fails closed (no write, observed in check-csrf.json); comparing encoded bytes would avoid the unhandled exception.
- EntryStore.upsert applies the 5000 cap before checking whether the network already exists, so at the cap the operator cannot re-add (update) an existing entry through POST /entries either.
- Prior fingerprint whitelister/app.py:invite_redeem/refresh_after_change:unthrottled-known-address-renewal is not reproducible at 0e90ff4: a known address changes its entry (and triggers a refresh) at most once per hour of gained validity.
- The on-page history keeps 200 events for all actors; 200 invite redemptions push the operator's own actions out of it (the stdout audit log keeps them).
- refresh_after_change calls bw-api once per changed redemption with no coalescing; N queued redemptions make N cache deletes and hold the operator's change behind them in the lock queue (5 x 0.2 s delayed an operator add to 1.24 s). Route invite-driven refreshes through Syncer.request_refresh so they are debounced.
- POST /import: FastAPI parses the multipart body (up to 256 KiB) before require_post checks the session, so an anonymous client gets the larger body limit; checking the session cookie in the middleware before granting the /import limit would keep anonymous bodies at 16 KiB.
- login.locked and busy-slot refusals are written or rendered per request with no cap; audit log volume under a request flood depends on the log collector.
- uvicorn starts its keep-alive timer only after a first completed response, so connections that never send a request hold limit_concurrency slots without a deadline; relevant only for peers that reach port 8080 directly (the example compose publishes no port). A front proxy or a header-read deadline closes it.

**static/app.js**
- static/app.js keeps the last entry label in localStorage (`whitelister.label`) across logout; it is only the operator's own label on that browser, but clearing it on logout would avoid leaving it on a shared device.

**whitelister/app.py**
- whitelister/app.py qr_code runs segno synchronously on the single event loop with no cap on page_url length. With PUBLIC_URL unset, a holder of an open invite link can send a Host header of about 2.3 kB and make each GET /i/{token} cost about 0.11-0.12 s of loop time instead of about 5 ms (measured, linear, bounded by QR version 40). Not reported as a finding: it needs a valid link, sustained request volume, and a front proxy that forwards an arbitrary long Host. Cheap fixes: skip the QR when len(page_url) exceeds about 200, or cache the code per invite, or build it with asyncio.to_thread.
- whitelister/app.py invite_view: the closed (404) page still renders og:url from Host and the request path. It is escaped and the response is no-store; emitting the OG tags only for a valid invite would avoid reflecting unauthenticated input at all.
- whitelister/app.py open_invite: record_success clears the address's failure count, so a holder of one valid link can interleave it with unknown tokens and never reach the lock (observed 404,404,200 repeated). Harmless against 192-bit tokens; noted only because the comment says unknown tokens cost like wrong passwords.
- whitelister/app.py open_invite: the per-address lock is checked before the token, so a guest with a valid link is refused (429) while someone behind the same public address (CGNAT, office NAT, or all clients when TRUSTED_PROXIES does not match the proxy) keeps sending unknown tokens; the lock doubles up to 1 h. This is the accepted cost of per-address throttling; letting a valid open token pass a locked key would remove it without helping guessing.
- whitelister/app.py public_origin: without PUBLIC_URL the invitation link (and og:url) takes the Host of the request as sent, without an allowlist. Only the operator's own authenticated request reaches create_invite, so this is not exploitable from source; setting PUBLIC_URL (as the README advises) or refusing invite creation without it would make the link origin independent of proxy Host handling.

**whitelister/bunkerweb.py**
- whitelister/bunkerweb.py BunkerWebClient.__init__: httpx timeout=SYNC_TIMEOUT_SECONDS is per phase (connect, write, read, pool), not a total deadline; a slow-dripping upstream can hold the refresh lock longer than the configured value. Wrap _trigger in asyncio.timeout for a total bound.
- whitelister/bunkerweb.py Syncer._run: retries after a failure run at a fixed 30 s interval with no backoff; with bw-api answering 401 persistently each attempt includes one POST /auth. Bounded, but exponential backoff with a cap would avoid tripping bw-api's own /auth rate limit during a long misconfiguration.

**whitelister/config.py**
- whitelister/config.py:199-205: an empty TRUSTED_PROXIES env value is a configuration error, but an empty file behind TRUSTED_PROXIES_FILE is silently read as 'no trusted proxy'. Behind BunkerWeb that makes the proxy the client for everyone (same effect as the bw-universe lead). Treat an empty file like the unset variable.
- whitelister/config.py _load_or_create_secret: when session.key already exists but is shorter than 32 bytes it is rewritten in place and keeps its old mode (0644 stayed 0644 locally); os.open follows a symlink at that path. Only whoever controls DATA_DIR can set this up. Add os.fchmod(fd, 0o600) and O_NOFOLLOW, or write a temp file and rename.
- whitelister/config.py load_settings: BW_API_URL accepts userinfo (http://user:pass@host). httpx logs the full request URL at INFO, so such a password would appear in the container log on every call (observed with a dummy URL in check-1.json). Not documented as a supported form; reject a BW_API_URL that carries userinfo, or set the httpx logger to WARNING.
- whitelister/config.py load_settings: BW_API_URL may be plain http and .env.example uses http://bw-api:8888, so the Basic credentials and the Biscuit token cross the compose network unencrypted. Acceptable on a dedicated internal network; consider a startup warning for http:// towards a non-loopback host.
- whitelister/config.py load_settings: SESSION_SECRET is only length-checked; a low-entropy 32-character value is accepted. LIST_TOKEN is not cross-checked against the token inside WHITELIST_URL, so a mismatch shows only as the API error after the second 404.

**whitelister/security.py**
- whitelister/security.py LoginThrottle._prune: when 10000 keys are tracked and none is prunable, the whole state is cleared, which also drops every active lock (observed: a locked key's wait went from 30 s to 0 after 10000 other failing keys). For the invite throttle this only relaxes guessing against a 192-bit token; evicting the oldest unlocked entries instead would keep locks intact.

**whitelister/static/sw.js**
- whitelister/static/sw.js caches /static/ responses cache-first for the lifetime of a version with distinct query strings as distinct keys, so a controlled page can add entries without bound (same-origin script only; CSP script-src 'self' leaves no attacker script). Restricting cache.put to the PRECACHE list would remove the growth.

### Positive source patterns

- Invitation tokens: 24 random bytes, only the SHA-256 hash stored, length-gated lookup, one 404 page for unknown, closed and revoked links, GET free of side effects, POST same-origin only.
- A link only ever adds: operator entries keep label, origin and period; renewals need at least one hour of gain before anything is written or BunkerWeb is asked to refresh.
- The invitation throttle is per address only, so strangers cannot lock other people's links.
- `/whoami` requires a valid session, answers `no-store`, sets no CORS header and returns nothing an operator page does not already show; the client code uses `textContent` and a reload, no HTML sink.
- The QR code is drawn server-side as one autoescaped SVG path (digits and `M h v z` only), only for a valid open link with a slot left, with no script, no image request and no new route; overflow input yields no code.
- Password check off the event loop with two slots, constant-time compares, per-address lock; sessions signed and server-side; CSRF token per session plus Fetch-Metadata/Origin checks.
- Every SQL statement parameterised; Jinja autoescape with StrictUndefined; strict CSP with per-response nonce; service worker caches static files only.
- Hash-pinned requirements installed with `--require-hashes`; non-root uid 10001; read-only, cap-dropped compose example; registry push only on main and version tags; tag must equal the package version; a test keeps version, changelog and example tags in step.

## 6. Coverage summary

- Ledger units: 53 (candidate: 12, covered: 40, out_of_scope: 1). Every covered or candidate unit has an owner, reviewed paths and at least one recorded check; 'candidate' units are those whose fingerprints went through independent validation (see findings.json for the outcome).
- Waves: 1 hunter waves (16 hunters). Critic `c1-post-wave1` (post-wave, after wave 1) accepted 0 missing unit(s) and 0 reassignment(s). Critic `c2-final-clean` (final-clean, after wave 1) accepted 0 missing unit(s) and 0 reassignment(s). Coverage was declared complete only after a final-clean critic returned no accepted work.
- Run-2 records, as established by current units and both critics:
  - `whitelister/app.py:invite_redeem:upsert-overwrites-operator-entry`: closed in source (upsert only when no entry exists; `set_expiry` only lengthens finite entries).
  - `whitelister/app.py:invite_redeem/refresh_after_change:unthrottled-known-address-renewal`: closed in source (renewal gain of one hour; refresh only when something changed).
  - `whitelister/app.py:open_invite/invite_throttle:global-budget-shared-lockout`: closed for the invitation throttle (`global_budget=None`); the same mechanism on the login throttle is this run's record `whitelister/security.py:LoginThrottle.global-budget-locks-all-clients`.
  - `whitelister/entries.py:EntryStore.delete:invite_addresses-stale-known-readd`: closed for removals made on 0.4.3 or later; two residual forms are this run's records (tombstone lifted by another link, no backfill for older removals).
  - `whitelister/app.py/prefill_from_query/unhandled-ValidationError-ValueError`: the two reported inputs are fixed; a narrower form (more than 4300 digits) is confirmed again under the same fingerprint, now informational.
  - `whitelister/app.py:invite_redeem:access_days-not-capped-by-current-max_days` (rejected in run-2): re-checked, still not a boundary crossing.
  - The two needs_validation leads (bw-universe leg, `/ips.txt` direct gate) are re-established and stay open.
- Companion exclusions (with reasons in each ledger unit): federated identity, MFA/passkey, API-key/mTLS, request framing and cache classes (no such code or source); IAM/Kubernetes/serverless/object-storage classes; updater/plugin classes; AI/LLM, memory-safety, protocol/RPC, desktop/mobile domains; tenant/owner isolation (single shared operator password).
- Validation: 10 candidates validated by fresh verifiers (6 confirmed, 4 needs_validation, 0 rejected); 0 malformed verifier output(s) were discarded unread and re-run with fresh verifiers per the skill. Phase 5 independent record verification: 10 of 10 confirmed/needs_validation records verified (rejected records are not Phase-5 subjects).
