# Findings detail (confirmed, medium or higher)

No confirmed finding is rated medium or higher in this run. The 6 confirmed findings are rated low; their complete traces follow for completeness.

## Operator sessions stay valid after the shared password is changed

Fingerprint `whitelister/app.py:current_session:session-survives-password-change` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:471` (entrypoint, create_app.login): POST /login with the old password succeeds and reaches session creation.
2. `whitelister/app.py:499` (propagation, create_app.login): The new session id is written to the persistent sessions table with an expiry of SESSION_HOURS; nothing about the password it was issued under is stored.
3. `whitelister/config.py:178` (propagation, load_settings): On restart with a new password the signing secret is re-read unchanged from DATA_DIR/session.key (or from SESSION_SECRET, line 172); the password values read at lines 160-161 play no part in it.
4. `whitelister/entries.py:144` (propagation, EntryStore.__init__): The sessions table is created only if missing; existing rows survive the restart.
5. `whitelister/app.py:178` (sink, create_app.current_session): The pre-change cookie verifies and its row is still present, so the request is treated as a logged-in operator on every route, including require_post mutations.

### Evidence
- `whitelister/app.py:176`: current_session checks only the signed cookie and store.session_valid.
- `whitelister/entries.py:446`: session_valid looks up sid and expires_at only.
- `whitelister/app.py:119`: PasswordChecker is built from the settings independently of the session codec (line 117) and the store; no code compares the current credential with the one sessions were issued under.
- `whitelister/config.py:222`: SESSION_HOURS defaults to 12 and may be set up to 720 (30 days), which bounds the window.
- `README.md:60`: Documentation states that logging out ends a session and that rotating SESSION_SECRET logs everyone out; a password change is not mentioned as needing it.

### Dummy attacker and affected resource
A holder of a session cookie that was issued before the operator changed the shared password.

### Native input and bounded instructions
- `Cookie: wl_session=<cookie issued under the old password>`
- `POST /entries  network=192.0.2.55&label=after-rotation&duration=forever&_csrf=<token from the page fetched with that cookie>`

1. Build the app in-process with a file-backed store in an empty DATA_DIR, no SESSION_SECRET (key generated into DATA_DIR/session.key), COOKIE_SECURE=no and dummy password A; log in and keep the cookie and the page's CSRF token.
2. Close the store and build the app again on the same DATA_DIR with a different dummy password B.
3. POST /login with password A and observe the status.
4. Send GET / and then POST /entries with the kept cookie and token and read the entries table.
5. Delete DATA_DIR/session.key, build the app once more and repeat GET / with the kept cookie.

### Observed output and the invariant it proves
Independent sandbox run: the second build loaded the same generated signing secret. The old password was refused (401), yet the pre-change cookie returned the operator page (200, with CSRF form) and POST /entries answered 303 to / and the entries table held 192.0.2.55 labelled after-rotation with expires_at NULL. Only after session.key was also removed did the cookie get 303 to /login.

Intended behaviour: After the operator password is changed, sessions established with the previous password are no longer accepted; the holder has to log in with the new password.

### Conditions and containment
- authentication_level: The actor already holds a valid session cookie obtained with the previous password (a former co-operator, or someone who used a leaked password before it was changed).
- system_configuration: The password is changed without also changing SESSION_SECRET or deleting DATA_DIR/session.key, and DATA_DIR is kept across the restart (the documented volume setup).
- timing_dependency: The session is used before its own lifetime ends: SESSION_HOURS after login, 12 h by default, up to 30 days if configured.

### Remediation and regression case
Tie stored sessions to the configured credential: keep a keyed fingerprint of the current password or password hash in the meta table and drop all session rows at start-up when it differs. Regression test: log in, rebuild the app on the same data directory with another password, and assert the old cookie is redirected to /login. Also state in the README that a password change ends all sessions.

`whitelister/app.py`:

```python
import hmac  # next to the existing `import hashlib`

    # in create_app, after `codec = SessionCodec(...)`
    credential = (settings.password_hash or settings.password or "").encode("utf-8")
    credential_tag = hmac.new(settings.session_secret, b"credential:" + credential, hashlib.sha256).hexdigest()
    if store.meta_get("credential_tag") != credential_tag:
        store.sessions_clear()  # the password changed (or first start): nobody stays logged in
        store.meta_set("credential_tag", credential_tag)

```

`whitelister/entries.py`:

```python
    def sessions_clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions")

```

## An unlimited invitation link can fill the shared 5000-entry list and block the operator's adds and every other link

Fingerprint `whitelister/app.py:invite_redeem/EntryStore.upsert:unlimited-link-fills-shared-entry-cap` · severity **low** · confidence medium

### Ordered trace
1. `whitelister/app.py:768` (entrypoint, invite_redeem): POST /i/{token} from a link holder without login; only same_origin and a valid open token (open_invite) are required.
2. `whitelister/app.py:308` (propagation, invite_status): The budget check compares invite.remaining with 0; for max_addresses=0 remaining is None, so an address new to the link is always 'ready'.
3. `whitelister/app.py:789` (propagation, invite_redeem): An address with no existing entry is inserted with store.upsert; nothing limits how many or how fast per link.
4. `whitelister/app.py:814` (propagation, invite_redeem): Each changed redemption awaits refresh_after_change, which calls client.trigger_refresh once per request (app.py:349-358), not debounced.
5. `whitelister/entries.py:242` (sink, EntryStore.upsert): The global COUNT(*) >= _MAX_ENTRIES (5000) check raises too_many_entries for every caller once the table is full, including the operator's add at app.py:592, import at app.py:893 and other links' redemptions.

### Evidence
- `whitelister/entries.py:127`: Invite.remaining returns None when max_addresses is 0.
- `whitelister/templates/index.html:208`: The create-link form offers 0 as 'unlimited' (INVITE_ADDRESS_CHOICES, app.py:67); the default selection is 3.
- `whitelister/app.py:123`: invite_throttle is the only throttle on the invite path; open_invite records a failure only for unknown or closed tokens (app.py:738-742).
- `whitelister/entries.py:242`: The entry cap is one global count taken before the insert-or-update, so it also refuses an update of an existing network.
- `whitelister/app.py:592`: The operator's add uses the same upsert and shows the cap error as a flash.
- `whitelister/entries.py:20`: _MAX_ENTRIES = 5000 is a module constant with no per-link or per-source share.

### Dummy attacker and affected resource
Holder of an unlimited invitation link, not logged in, sending POST /i/{token} from different /64 networks.

### Native input and bounded instructions
- `POST /i/<token> with headers Host: wl.example, Origin: http://wl.example, Sec-Fetch-Site: same-origin, X-Forwarded-For: 2001:db8:77:<n>::1 for n = 0..7, sent through the trusted proxy peer 10.0.0.5`

1. Build the app in-process (ASGI transport, in-memory store, mocked BunkerWeb API, TRUSTED_PROXIES=10.0.0.0/8) and set whitelister.entries._MAX_ENTRIES to 6 in the harness process as a stand-in for 5000.
2. Log in as the operator and create one link with max_addresses=0 and a second link with max_addresses=3.
3. Send the redemption POST for the unlimited link from 8 different /64 networks.
4. Send one redemption POST for the second link from 198.51.100.7.
5. As the operator, POST /entries for the new address 192.0.2.10 and for one network that is already listed, and load the page after each.
6. Revoke the unlimited link, delete one of its entries and repeat the add for 192.0.2.10.

### Observed output and the invariant it proves
With the stand-in cap of 6 (source value 5000): the 8 redemptions returned 200 six times, then 503 twice; 6 entries were stored, the unlimited link showed used=6 and the mocked bw-api received 6 cache DELETE calls. The other link's guest got 503. The operator's add for 192.0.2.10 returned 303 with the flash 'The list is full' and was not stored; the operator's update of an already listed network was refused with the same flash. After revoking the link and deleting one entry the operator's add succeeded.

Intended behaviour: A single invitation link, including an unlimited one, should not be able to take list capacity away from the operator or from other links, and should not be able to trigger an unbounded number of BunkerWeb refreshes in a short time.

### Conditions and containment
- system_configuration: The operator has created a link with 'unlimited' addresses (or several open links whose budgets together reach the cap; the handler accepts budgets up to 1000 and the store allows up to its open-link maximum).
- authentication_level: The requester holds that link's URL; no login is needed.
- network_routing: The requester can originate requests from about 5000 distinct addresses as resolved by the app (distinct IPv4 hosts or IPv6 /64s, for example a routed /48), and the front proxy does not rate-limit or block POST /i/ requests. That proxy behaviour is not visible in the repository.
- data_state: IPv6 /64 entries must pass the entry policy; the default MIN_PREFIX_V6=48 accepts them.

### Remediation and regression case
Give every link a finite ceiling and keep capacity for the operator: treat 'unlimited' as a fixed maximum (for example 100 addresses), count a link's live entries against a per-link share of the cap, and reserve headroom so invite redemptions are refused before the operator's own adds are. Add a per-link rate limit for new addresses (a few per minute) and route invite-driven refreshes through the debounced Syncer instead of one bw-api call each. Let upsert skip the cap check when the network already exists, and give the operator a way to remove all entries a link added. Regression case: an unlimited link redeemed from more addresses than its ceiling returns 409, and an operator add still succeeds.

## A link blocked by the operator's removal can lengthen the address again once another link re-adds it

Fingerprint `whitelister/app.py:invite_status:removed-tombstone-lifted-by-any-active-entry` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:769` (entrypoint, invite_redeem): POST /i/{token} from the removed address with the blocked link, after a second link added the address again.
2. `whitelister/entries.py:407` (propagation, EntryStore.invite_address_state): Returns 'removed' for this link and network because removed_at is set.
3. `whitelister/app.py:306` (propagation, invite_status): The 'removed' result is skipped because an unexpired entry exists; the function falls through to 'ready'.
4. `whitelister/app.py:792` (sink, invite_redeem): set_expiry lengthens the entry to now plus the blocked link's access_days.

### Evidence
- `whitelister/app.py:306`: The removed state requires that no unexpired entry exists; who created that entry is not considered.
- `whitelister/entries.py:279`: Deletion stamps removed_at only on links that already saw the network, so a link that has not seen it can still add it.
- `README.md:232`: Documented rule: listing the address by hand again is what lifts the block.
- `tests/test_app.py:1228`: The existing test covers only a single link; no test has a second link re-adding the removed address.

### Dummy attacker and affected resource
A guest who holds two open invitation links and whose address the operator removed from the list.

### Native input and bounded instructions
- `POST /i/<token of link B> from the removed address`
- `POST /i/<token of link A> from the removed address`

1. In the in-process test app, create link A (14 days per address) and redeem it from 198.51.100.5.
2. As operator, delete the entry for 198.51.100.5 and confirm that a POST with link A from that address returns 409.
3. Create link B (1 day per address, budget 1) and POST it from 198.51.100.5.
4. POST link A again from 198.51.100.5 and read the entry's expiry from the store.

### Observed output and the invariant it proves
In the sandboxed in-process run: after the operator's delete, link A returned 409 and no entry existed. Link B returned 200 and created the entry ending 2026-11-26 (1 day). Link A then returned 200 and the same entry's end moved to 2026-12-09 (14 days), while link A's removal mark stayed set. After the entry's end was set to the past, link A returned 409 again.

Intended behaviour: After the operator removes an address a link had added, that link must not add or lengthen the address again unless the operator lists it by hand (README.md: 'the link remembers that ... listing the address by hand again lifts the block').

### Conditions and containment
- authentication_level: The guest holds two open invitation links for the same installation; no login is needed.
- data_state: The operator removed the guest's address after the first link added it and left both links open; the second link has not seen that address and has budget left; the first link's access period is at least one hour longer than what remains on the entry the second link created.
- network_routing: The guest still connects from the removed address (same IPv4 address or IPv6 /64).

### Remediation and regression case
Make the removal mark authoritative for the link: return 'removed' whenever the link's row for the network has removed_at set, and clear removed_at only when the operator lists the address by hand (the /entries add path and import). Add a regression test in which a second link re-adds a removed address and the first link still gets 409, and one in which a hand-made entry lifts the block.

`whitelister/app.py`:

```python
        # invite_status
        if seen == "removed":
            return "removed", existing

        # add_entry (and the import path), after store.upsert(text, ...):
        store.invite_clear_removed(text)
```

`whitelister/entries.py`:

```python
    def invite_clear_removed(self, network: str) -> None:
        """The operator listed the address by hand again: links may renew it."""
        with self._lock:
            self._conn.execute("UPDATE invite_addresses SET removed_at = NULL WHERE network = ?", (network,))
```

## Addresses the operator removed before the upgrade to 0.4.3+ can still be re-added through the same open invitation link

Fingerprint `whitelister/entries.py:EntryStore.__init__:removed_at-migration-no-backfill` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:768` (entrypoint, invite_redeem): POST /i/{token} from the holder of a still-open link, arriving (via the trusted proxy) from the address the operator had removed before the upgrade; open_invite and same_origin pass for a legitimate holder.
2. `whitelister/entries.py:201` (propagation, EntryStore.__init__): On first start of the new version the column removed_at is added; existing invite_addresses rows keep NULL, with no backfill from the events table or from missing entries.
3. `whitelister/entries.py:416` (propagation, EntryStore.invite_address_state): A NULL removed_at is reported as 'known'.
4. `whitelister/app.py:312` (propagation, invite_status): seen == 'known' with no active entry falls through to 'ready'; the budget check at line 308 applies only when the address is new to the link.
5. `whitelister/app.py:789` (sink, invite_redeem): store.upsert re-creates the whitelist entry for now + access_days as invite:<name>; the list refresh is then requested.

### Evidence
- `whitelister/entries.py:200`: Migration: column added only when missing, no UPDATE of existing rows (the updated_at migration at lines 158-160 does backfill).
- `whitelister/entries.py:279`: Only deletions executed by the current code stamp removed_at; the 0.4.2 schema (commit 4ce6e0d, entries.py:191-197) had no such column.
- `whitelister/app.py:306`: The refusal branch requires seen == 'removed'; legacy rows never reach it.
- `README.md:230`: Stated contract: a removed address is remembered by the link and not put back.
- `CHANGELOG.md:75`: 0.4.3 states that removing an invite-added entry now sticks (HTTP 409); no upgrade note about links opened on earlier versions.

### Dummy attacker and affected resource
Invitation-link holder whose address the operator removed from the whitelist before upgrading from 0.4.2.

### Native input and bounded instructions
- `SQLite file with the 0.4.2 schema (invite_addresses without removed_at): one open invite (access_days 14, max_addresses 1), one invite_addresses row for 198.51.100.50, no entries row, one events row action='delete' for 198.51.100.50`
- `POST /i/<token> with X-Forwarded-For: 198.51.100.50 through the trusted proxy peer, Host wl.example, Origin http://wl.example, Sec-Fetch-Site: same-origin`

1. Create the legacy SQLite file with dummy data as described in the payload.
2. Open it with the current EntryStore and build the app in-process (ASGI transport, no network, BunkerWeb client mocked).
3. Send GET, then POST /i/<token> as the guest from 198.51.100.50 and read the entries table.
4. Control: delete the re-created entry with the current EntryStore.delete and repeat the POST.

### Observed output and the invariant it proves
Sandbox run (verifier v3-9, hand-built 0.4.2-schema database): after opening, removed_at exists and is NULL, invite_address_state = 'known', no entry. GET 200 with no change; POST 200 and entries now holds 198.51.100.50, label 'Legacy', created_by 'invite:Legacy', expiry 14.0 days ahead, while the link still counts 1 of 1 addresses. Control after EntryStore.delete on the current version: state 'removed', POST 409, no entry.

Intended behaviour: README (invitation section) and CHANGELOG 0.4.3: if the operator removes an address a link had added, the link remembers that, the slot stays spent and the button refuses (HTTP 409) until the operator lists the address by hand again. For links still open at upgrade time this should also hold for removals made before the upgrade, or the upgrade notes should tell the operator to revoke such links.

### Conditions and containment
- authentication_level: The requester holds the invitation link (bearer capability) and comes from the address (IPv4 host or IPv6 /64) that this link had added earlier.
- data_state: The database was created by 0.4.1 or 0.4.2, the operator deleted a link-added entry on that version, did not revoke the link, and the link is still within its validity after the upgrade.
- timing_dependency: The exposure ends when the link expires or is revoked, at the latest 30 days after the link was created.

### Remediation and regression case
Backfill once when the column is added: mark as removed every legacy invite_addresses row that has no entry row and whose latest history event for that network is 'delete'. The history keeps only 200 rows, so this is best effort; a stricter fail-closed variant marks every legacy row without an entry row (the operator lifts it by listing the address by hand, at the cost of also blocking renewal of entries that merely ran out). Add a regression test that opens a 0.4.2-schema database and expects 409. Additionally or alternatively, state in the 0.4.3 upgrade notes that links whose addresses were removed earlier should be revoked.

`whitelister/entries.py`:

```python
        if "removed_at" not in {r["name"] for r in self._conn.execute("PRAGMA table_info(invite_addresses)")}:
            self._conn.execute("ALTER TABLE invite_addresses ADD COLUMN removed_at TEXT")
            # Removals made before this column existed left no mark: take them from the history, so a link
            # that is still open cannot bring back an address the operator deleted on the older version.
            self._conn.execute(
                """
                UPDATE invite_addresses SET removed_at = (
                    SELECT e.at FROM events e WHERE e.network = invite_addresses.network ORDER BY e.id DESC LIMIT 1
                )
                WHERE removed_at IS NULL
                  AND NOT EXISTS (SELECT 1 FROM entries x WHERE x.network = invite_addresses.network)
                  AND (SELECT e.action FROM events e WHERE e.network = invite_addresses.network ORDER BY e.id DESC LIMIT 1) = 'delete'
                """
            )

```

## Anonymous clients can close the operator login for everyone through the shared failure budget

Fingerprint `whitelister/security.py:LoginThrottle.global-budget-locks-all-clients` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:470` (entrypoint, create_app.login): Anonymous POST /login with a wrong password; it passes same_origin (no Origin or Sec-Fetch-Site header needed) and gets a per-address throttle key at line 476.
2. `whitelister/app.py:491` (propagation, create_app.login): Each wrong password calls throttle.record_failure(key).
3. `whitelister/security.py:189` (propagation, LoginThrottle.record_failure): When the window count from all keys exceeds global_budget (30), _global_until is set to now + 60 for the whole process.
4. `whitelister/security.py:164` (propagation, LoginThrottle.retry_after): retry_after starts from the global lock and takes the maximum with the caller's own lock, so every key gets a non-zero wait.
5. `whitelister/app.py:482` (sink, create_app.login): A non-zero wait returns 429 before the password is checked: the operator's correct password is refused and no session is created.

### Evidence
- `whitelister/security.py:186`: Process-wide one-minute failure window (lines 186-188) and the global lock it sets (189-191).
- `whitelister/security.py:160`: retry_after applies the global lock to every key.
- `whitelister/app.py:120`: The login throttle is built with the default global_budget of 30; line 123 builds the invitation throttle with global_budget=None, with a comment that a shared lock would let strangers lock every guest out.
- `whitelister/app.py:480`: The lock is checked before the password, and a refused attempt returns before record_failure, so a correct password does not pass and refused attempts do not extend the lock.
- `whitelister/config.py:223`: Defaults: LOGIN_MAX_FAILURES 3, LOGIN_LOCK_SECONDS 30; the shared budget of 30 has no setting.
- `README.md:52`: The shared budget is documented as closing the login for a minute for all clients (lines 52-54).

### Dummy attacker and affected resource
Anonymous internet client with several source addresses, no password and no invitation link.

### Native input and bounded instructions
- `POST /login with form body password=wrong-N-J, three times from each of 2001:db8:0:0::1 ... 2001:db8:0:a::1`
- `POST /login with the correct password from 198.51.100.20`

1. Build the app in-process with default throttle settings, a dummy plain password, TRUSTED_PROXIES=none and an empty data directory; drive it through an in-process ASGI transport with a chosen peer address per client. Build a second, untouched instance as a control.
2. Log in once with the correct password from 198.51.100.10 and keep the session cookie.
3. Send three wrong-password posts from each of eleven peers in different /64s.
4. Send one post with the correct password from 198.51.100.20, which was not used before, and the same post to the control instance.
5. Request / with the session cookie from the second step.
6. Step LoginThrottle(3, 30) with a synthetic clock: 31 failures from 31 keys, then ask retry_after for an unused key shortly after and 60.1 seconds after the last failure.

### Observed output and the invariant it proves
The 33 wrong posts returned 401 thirty-one times, then 429 twice. The correct password from 198.51.100.20 returned 429 without a session cookie; the control instance returned 303 with a session cookie. The session opened beforehand still got 200 on /. With the synthetic clock an unused key had retry_after 60 right after the 31st failure and 0 at 60.1 seconds after it; 30 failures in one window left an unused key at 0.

Intended behaviour: Failed attempts by one client should limit that client and bound the server's hashing work without removing the operator's ability to log in with the correct password from another address.

### Conditions and containment
- authentication_level: None: any client that can reach POST /login.
- network_routing: Requests must arrive under several throttle keys: about eleven per cycle at the default LOGIN_MAX_FAILURES=3 (IPv4 addresses, or /64s of one IPv6 prefix), and mostly fresh keys for each further cycle.
- environmental_dependency: A fronting BunkerWeb request limit or bad-behaviour ban acts per address and may slow the client; it is outside this repository and was not observed.
- data_state: The operator has no valid session at that moment; existing sessions are not affected.
- timing_dependency: Each lock lasts 60 seconds and cannot be extended while active; the login is open between cycles for as long as the client needs to record 31 new failures.

### Remediation and regression case
Keep the per-address lock and the two-slot hashing cap as the CPU bound, and stop the shared budget from refusing clients that did not contribute to it. Preferred: set a signed long-lived 'this browser has logged in before' cookie on a successful login and let requests carrying it bypass only the shared lock (their own per-address lock still applies). Alternative: when the budget is exceeded, refuse only keys that already have a recorded failure; note that this lets a client with many fresh keys keep guessing at one attempt per key, bounded by the hashing cap rather than by the budget. Add a regression test in which 31 failures from other addresses are followed by a successful login with the correct password from the exempted client.

## Prefill link still raises an unhandled ValueError for a days value longer than 4300 digits

Fingerprint `whitelister/app.py/prefill_from_query/unhandled-ValidationError-ValueError` · severity **informational** · confidence high

### Ordered trace
1. `whitelister/app.py:515` (entrypoint, create_app.index): GET / with a valid operator session; the handler reads the request's query string. Without a session the handler returns a 303 to /login at line 521 and never reaches the prefill code.
2. `whitelister/app.py:535` (propagation, create_app.index): prefill_from_query(request, ip) is evaluated inside the template context dict with no exception handling.
3. `whitelister/app.py:270` (sink, create_app.prefill_from_query): int(raw_days) runs for any ASCII decimal string and raises ValueError when it has more than 4300 digits; the exception leaves the handler and the middleware and becomes a bare 500.

### Evidence
- `whitelister/app.py:270`: The guard is raw_days.isascii() and raw_days.isdecimal() with no length bound before int(raw_days).
- `whitelister/app.py:274`: The sibling label conversion catches ValidationError so the page still renders; the days conversion has no equivalent handling.
- `whitelister/app.py:89`: SecurityHeadersMiddleware.dispatch awaits call_next before adding any header, so an exception from the handler yields a response without CSP, nosniff, frame or no-store headers.
- `whitelister/app.py:253`: safe_next rejects next values longer than 512 characters, so the anonymous login redirect cannot carry a 4301-digit days value to the post-login page.
- `whitelister/__main__.py:36`: The HTTP parser accepts request heads up to 16 KiB, so a query value of 4301 digits is within the server's limit (read from source; not exercised over a socket).
- `tests/test_app.py:1281`: The regression test covers a 65-character label and two non-ASCII digit values but no long ASCII digit string.

### Dummy attacker and affected resource
A logged-in operator session requesting the list page with a prefill link whose days value is an over-long digit string.

### Native input and bounded instructions
- `GET /?add=me&days=<the digit 7 repeated 4301 times>`
- `GET /?add=me&days=<4300 zeros followed by 7>`

1. Build the application in-process with dummy settings, an in-memory store and a mock bw-api transport, and drive it through httpx.ASGITransport as a trusted proxy peer.
2. Without a session, request /?add=me&days= followed by 4301 digits and follow the redirect to the login page.
3. Log in with the dummy password, then request /?add=me&days=7 and the same path with 4300 digits as controls.
4. Request the path with 4301 digits and with 4300 zeros followed by 7; record status, body and headers, then request / again and read the entry count.
5. Repeat the 4301-digit request with application exceptions re-raised to capture the exception type and frames.

### Observed output and the invariant it proves
Python 3.13.17, limit 4300. Anonymous: 303 to /login, and the login page has no next field. Logged in: days=7 gives 200 with the duration selected; 4300 digits gives 200 with CSP and Cache-Control: no-store and no duration selected; 4301 digits and 4300 zeros plus 7 each give 500 'Internal Server Error' with no Content-Security-Policy and no Cache-Control header. The following GET / is 200 with headers, and the entry count is 0. With exceptions re-raised: ValueError 'Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits' through app.py:89 dispatch, app.py:535 index, app.py:270 prefill_from_query.

Intended behaviour: A malformed or oversized value in a prefill link is dropped and the page renders with an unfilled duration, as the label handling and the test test_prefill_and_invite_name_with_bad_values_do_not_crash establish for the other bad values.

### Conditions and containment
- authentication_level: The request must carry a valid operator session; without one GET / only redirects to /login, and the over-long next value is dropped there.
- user_interaction: The operator has to request the URL within their own session (typed, pasted or followed from the app's origin); the session cookie is SameSite=Strict according to the architecture summary, which was not re-tested here.
- environmental_dependency: The interpreter keeps the default integer string conversion limit of 4300 digits. Observed on the local Python 3.13 environment; the image's Python 3.15 was not run, and the Dockerfile sets no PYTHONINTMAXSTRDIGITS.

### Remediation and regression case
Bound the length of the days value before converting it (a preset never needs more than a few digits) or compare the string with the presets rendered as text, and add a long digit string to the existing regression test. A catch-all exception handler that keeps the security headers on error responses would cover future cases of the same kind.

`whitelister/app.py`:

```python
        days = None
        raw_days = q.get("days", "")
        if len(raw_days) <= 4 and raw_days.isascii() and raw_days.isdecimal() and int(raw_days) in settings.duration_presets:
            days = int(raw_days)

```
