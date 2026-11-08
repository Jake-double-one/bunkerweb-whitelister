# Findings detail (confirmed, medium or higher)

No confirmed finding is rated medium or higher in this run. The 5 confirmed findings are rated low; their complete traces follow for completeness.

## Prefill query values (over-long label, non-decimal Unicode digit days) raise unhandled exceptions out of GET /, producing a header-less 500 that an anonymous next-link can make the operator's post-login landing page

Fingerprint `whitelister/app.py/prefill_from_query/unhandled-ValidationError-ValueError` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:472` (entrypoint, index (GET /)): Anonymous GET / with any query string: lines 474-478 answer 303 to '/login?next=' + quote('/?' + request.url.query), carrying attacker-chosen label/days values unchanged.
2. `whitelister/app.py:247` (propagation, safe_next): Accepts any local path (starts with '/', not '//', no backslash, length <= 512); the crafted query survives, and login.html:12 echoes it as the hidden next field.
3. `whitelister/app.py:457` (propagation, login (POST /login)): After a correct password the operator is redirected (303) to safe_next(next_url), i.e. to the crafted /?add=me&label=... or /?add=me&days=... URL.
4. `whitelister/app.py:492` (propagation, index (GET /, logged in)): 'prefill': prefill_from_query(request, ip) is evaluated inside the context dict with no try/except.
5. `whitelister/app.py:265` (propagation, prefill_from_query): q.get('days', '').isdigit() is True for U+00B2 (isdecimal() is False) but int(q['days']) raises ValueError.
6. `whitelister/app.py:267` (propagation, prefill_from_query): normalize_label(q.get('label', '')) is called in the return expression, outside the try that protects parse_network.
7. `whitelister/entries.py:35` (propagation, normalize_label): Raises ValidationError('error.label_too_long', max=64) when the NFC/whitespace/control-normalised text is longer than 64 characters.
8. `whitelister/app.py:87` (sink, SecurityHeadersMiddleware.dispatch): The exception leaves 'response = await call_next(request)' before any header is set; no app exception handler exists, so Starlette's ServerErrorMiddleware returns a bare 500 'Internal Server Error' without CSP, X-Frame-Options, X-Content-Type-Options or Cache-Control: no-store, and re-raises for the server log.

### Evidence
- `whitelister/app.py:260`: try/except ValidationError covers only network_text(parse_network(...)) (lines 260-263); the days and label handling below it is unprotected.
- `whitelister/app.py:265`: if q.get('days', '').isdigit() and int(q['days']) in settings.duration_presets: isdigit() accepts Unicode digit characters (U+00B2, U+00B3, U+2460...) that int() rejects.
- `whitelister/app.py:267`: return {..., 'label': normalize_label(q.get('label', ''))} with no exception handling.
- `whitelister/app.py:492`: 'prefill': prefill_from_query(request, ip) inside index() with no try/except.
- `whitelister/app.py:477`: Anonymous branch of index forwards the whole query string into /login?next=quote('/?' + query).
- `whitelister/app.py:457`: login() redirects to safe_next(next_url) after a correct password, so the crafted path becomes the post-login landing page.
- `whitelister/app.py:635`: create_invite: clean_name = normalize_label(name) runs before the try block at 638, so a >64-char name raises out of the handler (operator-only, behind require_post).
- `whitelister/entries.py:35`: normalize_label raises ValidationError('error.label_too_long') when len(text) > MAX_LABEL (64); ValidationError subclasses ValueError.
- `whitelister/app.py:148`: FastAPI app is created here; no app.exception_handler / add_exception_handler appears anywhere under whitelister/ (grep), so ValueError/ValidationError become a bare 500.
- `whitelister/templates/index.html:49`: The label input has maxlength=64 (invite name at line 191 likewise), so the over-length branch is reachable only via a crafted URL or request, not the rendered form.
- `whitelister/templates/login.html:12`: The login form carries the next value as a hidden input, so the crafted destination survives the login round-trip.
- `tests/test_app.py:745`: test_prefill_link_survives_login_and_only_prefills exercises only days=7, label=Laptop and a policy-violating add value; no over-long label or non-decimal digit days case.

### Dummy attacker and affected resource
An anonymous party who can get the operator to click a link to the whitelister (e.g. in a message asking for an address to be listed) can make the operator's post-login landing page a bare 500 instead of the prefilled form; the operator recovers by visiting / again. The operator can also trigger it themselves with a hand-edited URL or a crafted POST /invites.

### Native input and bounded instructions
- `GET /?add=me&label=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  (65 x 'a')`
- `GET /?add=me&days=%C2%B2  (U+00B2 SUPERSCRIPT TWO)`
- `GET /login?next=%2F%3Fadd%3Dme%26label%3Daaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  (what the anonymous 303 produces; the operator logs in from here)`
- `POST /invites  name=<65 x 'n'>&access_days=14&link_days=14&max_addresses=3&_csrf=<valid>  (operator-only variant)`

1. Build the app in-process as tests/conftest.py does: load_settings() with dummy env (WHITELISTER_PASSWORD, SESSION_SECRET, DATA_DIR in a writable scratch dir, COOKIE_SECURE=no, TRUSTED_PROXIES=10.0.0.0/8, BW_API_URL/USERNAME/PASSWORD, WHITELIST_URL, SYNC_DEBOUNCE_SECONDS=0, TZ=UTC), EntryStore(':memory:'), BunkerWebClient whose _client uses an httpx.MockTransport fake bw-api, and httpx.AsyncClient over httpx.ASGITransport(app, client=('10.0.0.5', 40000), raise_app_exceptions=False) with header X-Forwarded-For: 203.0.113.9.
2. POST /login with the dummy password (303 to /); GET /?add=me&days=7&label=Laptop and record status 200 and the Content-Security-Policy, X-Frame-Options, Cache-Control and X-Content-Type-Options headers (baseline); GET /?add=me&label=<64 x 'a'> as the boundary control (expect 200).
3. In the same logged-in client GET /?add=me&label=<65 x 'a'> and GET /?add=me&days=%C2%B2; record status and which of the four headers are present. GET /?add=me&days=%D9%A7 (U+0667) as a control (expect 200 with dur-7 checked).
4. Repeat the two failing GETs with raise_app_exceptions=True to capture the exception type and the whitelister frames of the traceback.
5. Anonymous chain on a fresh app: without a session GET /?add=me&label=<65 x 'a'> (expect 303 to /login?next=...), GET that login page and confirm the hidden next field echoes the path, POST /login with password and next=<crafted path> (expect 303 to the crafted path), then GET that location.
6. Operator variant: GET / for a CSRF token, POST /invites (Origin/Sec-Fetch-Site same-origin) with name of 65 characters and otherwise valid fields; then with 64 characters as the boundary control.
7. Confirm GET / afterwards is 200 with headers and store.count() == 0 (no state effect); check safe_next with a 512- and a 513-character next to confirm the length gate.

### Observed output and the invariant it proves
Primitives: normalize_label('a'*65) raised ValidationError key=error.label_too_long params={'max': 64} (isinstance ValueError True); normalize_label('a'*64) accepted; '\u00b2'.isdigit()=True, isdecimal()=False, int('\u00b2') -> ValueError "invalid literal for int() with base 10: '²'"; '\u0667'.isdigit()=True and int()=7; duration_presets=(1, 7, 14, 30). Logged in: GET /?add=me&days=7&label=Laptop -> 200 with all four headers, value="203.0.113.9", dur-7 checked, value="Laptop". GET /?add=me&label=<64 a> -> 200 with headers. GET /?add=me&label=<65 a> -> 500 body 'Internal Server Error', all four headers absent. GET /?add=me&days=%C2%B2 -> 500, headers absent. GET /?add=me&days=%D9%A7 -> 200 with headers, dur-7 checked. GET / afterwards -> 200 with headers, store.count()=0. With raise_app_exceptions=True: whitelister.entries.ValidationError: error.label_too_long with frames app.py:87 dispatch -> app.py:492 index -> app.py:267 prefill_from_query -> entries.py:35 normalize_label; builtins.ValueError invalid literal for int() with frames app.py:87 dispatch -> app.py:492 index -> app.py:265 prefill_from_query. Anonymous chain on a fresh app: anon GET crafted -> 303 Location /login?next=%2F%3Fadd%3Dme%26label%3Daaa... (headers present); login page echoes next; POST /login with next -> 303 to the crafted path; GET that location -> 500 'Internal Server Error' without the four headers; GET / afterwards 200, store.count()=0; an anonymous GET of either crafted URL without a session is only the 303 (no pre-auth 500). Operator variant: POST /invites name=<65 n> with valid CSRF -> 500 without headers, invites_open=0; name=<64 n> -> 303 to /, invites_open=1. safe_next: a 512-char next is returned verbatim, 513 chars falls back to '/'.

Intended behaviour: Prefill is best-effort and must never fail the page: an invalid or over-long value should fall back to the default (as the add value already does at lines 262-263) or be reported through the flash mechanism, and the index page must always render through SecurityHeadersMiddleware with its headers. Operator form validation errors in create_invite should become a flash via redirect_with_flash, as add_entry does for ValidationError.

### Conditions and containment
- authentication_level: The failing render happens in an operator session (logged in). The crafted URL can be produced and delivered by an anonymous party; an unauthenticated GET of it only yields the 303 to /login?next=... (verified: the 303 carries the security headers).
- user_interaction: The operator must open the crafted link (and log in from it if not yet logged in) or hand-edit the URL / invite POST themselves; the rendered form cannot produce the input because of maxlength=64.
- data_state: No stored state is required or changed; the effect is one failed response per crafted request and the app keeps serving.

### Remediation and regression case
Make prefill best-effort for all three values so prefill_from_query can never raise: guard the days parse with str.isdecimal()/isascii() (or try/except ValueError) and fall back to None, and catch ValidationError from normalize_label (fall back to an empty label). Move create_invite's normalize_label into a try and flash the ValidationError via redirect_with_flash like add_entry does. Optionally register a catch-all exception handler so that any future unhandled error still passes through SecurityHeadersMiddleware. Add regression tests for a 65-character label, days=%C2%B2 and a 65-character invite name expecting 200/303 with the security headers.

`whitelister/app.py`:

```python
    def prefill_from_query(request: Request, ip: str | None) -> dict[str, Any] | None:
        """``/?add=me&days=7&label=…`` pre-fills the form; nothing is saved until the person confirms."""
        q = request.query_params
        if "add" not in q:
            return None
        wanted = q.get("add", "")
        network = ip if wanted == "me" else wanted
        try:
            network = network_text(parse_network(network or "", settings))
        except ValidationError:
            network = ip or ""
        days = None
        raw_days = q.get("days", "")
        if raw_days.isascii() and raw_days.isdecimal() and int(raw_days) in settings.duration_presets:
            days = int(raw_days)
        try:
            label = normalize_label(q.get("label", ""))
        except ValidationError:
            label = ""  # an over-long label in a link is dropped; the page still renders
        return {"network": network, "days": days, "label": label}

```

`whitelister/app.py`:

```python
        # create_invite, replacing the bare `clean_name = normalize_label(name)`
        try:
            clean_name = normalize_label(name)
        except ValidationError as exc:
            return redirect_with_flash("/", "alert", t(exc.key, **exc.params))
        if not clean_name:
            return redirect_with_flash("/", "alert", t("invite.name_missing"))

```

## Unlimited free invite renewals let a link holder trigger one BunkerWeb cache-delete/refresh per request and wipe the operator's on-page history

Fingerprint `whitelister/app.py:invite_redeem/refresh_after_change:unthrottled-known-address-renewal` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:724` (entrypoint, invite_redeem): POST /i/{token} is reachable without a session; same_origin (221-232) accepts clients that send neither Origin nor Sec-Fetch-Site.
2. `whitelister/app.py:695` (propagation, open_invite): A valid, open token calls invite_throttle.record_success; only unknown/closed tokens count as failures (692), so successful POSTs are unlimited.
3. `whitelister/app.py:736` (propagation, invite_redeem): known = address already in invite_addresses: the budget check at 737-738 is skipped and the renewal costs nothing.
4. `whitelister/app.py:746` (propagation, invite_redeem): store.event_add('invite_refresh', ...) on every renewal; entries.py:307 deletes all rows beyond the newest 200, evicting operator history.
5. `whitelister/app.py:747` (propagation, invite_redeem): refresh_after_change is awaited unconditionally, even though the active network set is unchanged.
6. `whitelister/app.py:321` (propagation, refresh_after_change): client.trigger_refresh() is called directly; the debounce (bunkerweb.py:224-225, SYNC_DEBOUNCE_SECONDS) exists only in Syncer._run.
7. `whitelister/bunkerweb.py:134` (sink, BunkerWebClient._trigger): DELETE /cache/global/whitelist/whitelist-download/<sha1>.list per request (POST /jobs/run on 404): per the module docstring (lines 3-8) each one makes the scheduler re-download the list, regenerate the configuration and reload the instances.

### Evidence
- `whitelister/app.py:688`: retry_after only blocks after recorded failures (security.py:158-167 reads locks set by record_failure); no limiter covers successful redemptions.
- `whitelister/app.py:737`: 'if not known and invite.remaining == 0' - a known address never consumes budget, so renewals are unlimited.
- `whitelister/app.py:747`: 'sync_error = await refresh_after_change(request)' runs for renewals that change nothing in the published list.
- `whitelister/entries.py:307`: event_add trims the events table to the newest 200 rows (_MAX_EVENTS, line 18), so 200 renewals remove every operator row.
- `whitelister/bunkerweb.py:224`: The only sleep(sync_debounce_seconds) is in Syncer._run; trigger_refresh (115-130) called from the request path has none.
- `README.md:170`: SYNC_DEBOUNCE_SECONDS is documented as 'Collect quick successive changes before one refresh', which the direct path does not honour.
- `docker-compose.example.yml:73`: The example bw-api deployment sets 'API_RATE_LIMIT_RULES=DELETE /cache* 30r/m', which bounds the downstream cost in that deployment (excess deletes become errors shown in the operator header).
- `tests/test_app.py:909`: The only renewal test performs a single second click; repeated renewals and their outbound call count are untested.

### Dummy attacker and affected resource
Anyone holding an invitation link, after one normal redemption, repeats POST /i/<token> from the same address with a plain HTTP client (no cookies, no Origin or Sec-Fetch-Site headers).

### Native input and bounded instructions
- `POST /i/<token> HTTP/1.1 (no body, no cookies, no Origin/Sec-Fetch-Site) repeated 250 times from an address that already redeemed the link`
- `check_renewals.py (sandbox): operator login -> 3 entries -> POST /invites name=Tax advisor access_days=7 link_days=14 max_addresses=3 -> guest 203.0.113.77 POST /i/<token> once, then 250 more times`

1. Build the app in-process as tests/conftest.py does: EntryStore(':memory:'), BunkerWebClient whose httpx client is an httpx.MockTransport that records calls and answers 200 to DELETE /cache/..., with env WHITELISTER_PASSWORD, SESSION_SECRET (40 chars), TRUSTED_PROXIES=10.0.0.0/8, COOKIE_SECURE=no, BW_API_URL=http://bw-api:8888, BW_API_USERNAME/BW_API_PASSWORD dummies, WHITELIST_URL=http://whitelister:8080/ips.txt, SYNC_DEBOUNCE_SECONDS=3, TZ=UTC.
2. As the operator (ASGI peer 10.0.0.5, X-Forwarded-For 203.0.113.1) log in, add three entries (POST /entries with duration=7), create an invite (POST /invites) and read the token from the link shown on the page.
3. As a guest (peer 10.0.0.5, X-Forwarded-For 203.0.113.77, no Origin/Sec-Fetch-Site) POST /i/<token> once, then 250 more times; record each status.
4. Count fake bw-api calls recorded during the 250 renewals by method/path, compare store.active_networks before and after, read the events table and store.events_recent(5), and the invite's used/max_addresses.

### Observed output and the invariant it proves
Sandbox run (v3-7, SYNC_DEBOUNCE_SECONDS=3): operator setup produced 4 history rows (3 add, 1 invite_create) and 4 bw-api calls; first guest redemption HTTP 200 and added 203.0.113.77 to the active list; the 250 renewals returned {200: 250} (no 429, no 403) and caused exactly 250 outbound DELETE /cache/global/whitelist/whitelist-download/<sha1>.list calls (one per request, no coalescing); the active network set never changed during the renewals; the events table held 200 rows, all invite_refresh, 0 of the operator's 4 rows survived and events_recent(5) showed five guest renewals; invite budget used stayed 1 of 3; client.status last_error=None.

Intended behaviour: Renewals from a known address should be a cheap, bounded operation: the operator-owned integration (bw-api calls, BunkerWeb reloads) and the on-page history should be touched only when the published list actually changes, and a lower-trust link holder should not be able to drive them at request rate.

### Conditions and containment
- authentication_level: Possession of an open invitation link (no password or session); the first POST from the address consumes one budget slot, every later one from that address is free.
- system_configuration: BW_API_URL and WHITELIST_URL configured (otherwise refresh_after_change / trigger_refresh return early and only the history eviction remains).
- third_party_dependency: The cost on the BunkerWeb side (job re-run, configuration regeneration, instance reload per cache delete) is taken from the client's own documentation and was not observed locally; the compose example's 'DELETE /cache* 30r/m' limit would turn the excess into non-2xx responses surfaced as an API error to the operator.

### Remediation and regression case
Make renewals cheap and bounded: when the address's entry is already active, do not call refresh_after_change or event_add (the content of /ips.txt is unchanged); route any invite-caused refresh through the debounced Syncer (syncer.request_refresh()) instead of the immediate client call; and enforce a minimum interval between renewals of the same address using invite_addresses.last_at (a new setting, e.g. INVITE_RENEW_MINUTES, or a fixed constant) or count successful redemptions against a small per-key limiter in addition to the failure throttle. Regression tests: redeem twice from one address and assert at most one bw-api DELETE and one history event per actual list change; renew 50 times and assert the operator's history rows survive and the fake bw-api saw no additional DELETE.

`whitelister/app.py`:

```python
        existing = store.find(net)
        already_active = existing is not None and not existing.is_expired(now)
        last = next((a["last_at"] for a in store.invite_addresses(invite.id) if a["network"] == net), None)
        if already_active and last is not None and now - last < timedelta(minutes=INVITE_RENEW_MINUTES):  # new constant/setting
            return invite_view(request, invite, now, "known", until=existing.expires_at)  # too soon: nothing to do
        entry = store.upsert(net, invite.name, expires, now, created_by=f"invite:{invite.name}")
        is_new = store.invite_touch_address(invite.id, net, now)
        audit_event(request, "invite.redeem", invite=invite.id, name=invite.name, network=net, new_address=is_new, expires_at=_iso(expires))
        if not already_active:
            store.event_add("invite_redeem" if is_new else "invite_refresh", net, invite.name, ip or "", now)
            syncer.request_refresh()  # debounced background refresh; the published list changed

```

## Invite redemption silently shortens and re-attributes an operator-managed whitelist entry for the same network

Fingerprint `whitelister/app.py:invite_redeem:upsert-overwrites-operator-entry` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:725` (entrypoint, invite_redeem): POST /i/{token} from an unauthenticated link holder; passes same_origin (726) and open_invite (728) with a valid open token.
2. `whitelister/app.py:733` (propagation, invite_redeem -> redeemer_network): The redeemer network is derived from the resolved client address (bare IPv4 or the IPv6 /64) via network_text(parse_network(...)) (app.py:275-284), the same textual form POST /entries stores, so it collides with an operator entry for the same network.
3. `whitelister/app.py:736` (propagation, invite_redeem): known is computed only from this invite's invite_addresses; an operator-created entry for the same network does not make the address known and no store.find(net) lookup happens.
4. `whitelister/app.py:741` (propagation, invite_redeem): store.upsert(net, invite.name, now + access_days, now, created_by='invite:<name>') is called regardless of an existing row for net.
5. `whitelister/entries.py:246` (sink, EntryStore.upsert): ON CONFLICT(network) DO UPDATE replaces label (invite name is always non-empty), expires_at (shortening forever/long grants to access_days) and created_by of the operator's entry.

### Evidence
- `whitelister/app.py:739`: expires = now + timedelta(days=invite.access_days): the invite period is applied even when a longer or endless grant exists for the network.
- `whitelister/app.py:741`: entry = store.upsert(net, invite.name, expires, now, created_by=f"invite:{invite.name}") with no lookup of an existing entry for net.
- `whitelister/entries.py:248`: expires_at = excluded.expires_at: the stored expiry is overwritten unconditionally on conflict.
- `whitelister/entries.py:247`: label = CASE WHEN excluded.label = '' THEN entries.label ELSE excluded.label END: the operator label is replaced because invite names are required (app.py:636-637).
- `whitelister/entries.py:249`: created_by = excluded.created_by: the operator's attribution is replaced by 'invite:<name>'.
- `whitelister/app.py:722`: GET /i/{token} renders 'known' (with the existing expiry) only when the address is in invite_addresses; an already-whitelisted operator network is shown as 'ready' with no warning.
- `README.md:219`: Documented semantics: opening the link again from a known address 'only restarts that address's period'; nothing states that an operator's existing grant for the network is replaced.
- `tests/test_app.py:881`: The invite tests only redeem onto networks with no prior entry (store.count() == 0 before the first POST); no test covers redemption over a pre-existing operator entry.

### Dummy attacker and affected resource
A link holder (or the operator testing a link) connects from an address the operator has already whitelisted permanently, opens the link (page says 'Press the button and this connection is unlocked for 14 days', not 'already unlocked') and presses the button. The permanent grant becomes a 14-day grant labelled with the invite name and attributed to 'invite:<name>'; when it lapses, the whole network loses its whitelisting.

### Native input and bounded instructions
- `operator state: POST /entries network=198.51.100.77 label='Office NAT (forever)' duration=forever (also 198.51.100.78 label='Branch (365 d)' duration=365 and 2001:db8:1:2::/64 label='Office v6 (forever)' duration=forever)`
- `operator state: POST /invites name='Tax advisor' access_days=14 link_days=14 max_addresses=0 -> link http://wl.example/i/<token> shown once on GET /`
- `guest request from 198.51.100.77 (X-Forwarded-For via trusted proxy peer 10.0.0.5): GET /i/<token>, then POST /i/<token> with headers Origin: http://wl.example, Sec-Fetch-Site: same-origin, empty body`

1. Build the app in-process (create_app(load_settings(), store=EntryStore(':memory:')) with BW_API_URL unset, TRUSTED_PROXIES=10.0.0.0/8, COOKIE_SECURE=no, a dummy WHITELISTER_PASSWORD and SESSION_SECRET) and drive it through httpx.ASGITransport clients whose TCP peer is 10.0.0.5.
2. As the operator (X-Forwarded-For 203.0.113.9): POST /login, read the _csrf value from GET /, POST /entries for 198.51.100.77 (duration=forever), 198.51.100.78 (duration=365) and 2001:db8:1:2::/64 (duration=forever), then POST /invites (access 14 days, max_addresses 0) and read the token from the once-shown link on GET /.
3. Record store.find(<network>) (label, expires_at, created_by) for each seeded network.
4. As a guest (X-Forwarded-For 198.51.100.77, then 198.51.100.78, then 2001:db8:1:2:abcd::1): GET /i/<token> and note the state text, then POST /i/<token> with Origin http://wl.example and Sec-Fetch-Site same-origin.
5. Read store.find(<network>) again and compare; list invite_addresses for the invite and the events table.

### Observed output and the invariant it proves
check-1.txt (sandbox, 2026-11-08): all three GETs returned 200 in state 'ready' (not 'known'); all three POSTs returned 200 'done'. 198.51.100.77: before label='Office NAT (forever)' expires_at=None created_by='203.0.113.9'; after label='Tax advisor' expires_at=2026-11-22 14:48:09+00:00 created_by='invite:Tax advisor'. 198.51.100.78: expires_at 2027-11-08 -> 2026-11-22, label and created_by replaced. 2001:db8:1:2::/64 (guest 2001:db8:1:2:abcd::1): expires_at None -> 2026-11-22, label and created_by replaced. The entries table holds only the rewritten rows; invite_addresses lists all three networks; the events table holds the operator's three 'add' events (original labels, no expiry) followed by three 'invite_redeem' events. No outbound call was made (bw-api client disabled).

Intended behaviour: Per README.md:215-221 and locales/en.json invite.admin_text, a link lets a person 'put their own address on the list for the access period' and opening it from a known address 'only restarts that address's period'. An existing, longer or endless operator grant for the same network should be left intact (or at most extended) with its label and attribution preserved, and the page should present such an address as already unlocked.

### Conditions and containment
- authentication_level: The lower-trust principal holds an open invitation link (anyone the operator sent it to, or anyone it was forwarded to); no login is needed.
- data_state: The whitelist already contains an operator-managed entry whose network text equals the redeemer's mapped network (bare IPv4 address, or exactly the /64 for IPv6), e.g. an office NAT address listed 'forever' or for 365 days.
- network_routing: The link holder connects from that network, e.g. the operator testing their own link from the whitelisted office, or a colleague/contractor opening a shared link from an already whitelisted site.

### Remediation and regression case
Before writing, look up the existing entry for the redeemer's network. If one exists, is not expired and its expiry is later than (or endless compared to) now + access_days, keep it: record the touch so the address counts as known for this link, do not change expires_at, label or created_by, and render the 'known' state with the existing expiry. Only extend when the invite period ends later than the existing grant, and keep the existing label in that case. Mirror the same store.find lookup in invite_page so such an address is shown as already unlocked. Add a regression test: seed a forever operator entry for the guest's address, redeem, assert expires_at is still None and label/created_by unchanged; repeat with a 365-day entry and an IPv6 /64.

`whitelister/app.py`:

```python
        expires = now + timedelta(days=invite.access_days)
        existing = store.find(net)
        if existing is not None and not existing.is_expired(now) and (existing.expires_at is None or existing.expires_at >= expires):
            # an operator grant (or an earlier, longer redemption) for this network already covers the period:
            # count the address for this link, but never shorten, relabel or re-attribute the existing entry
            is_new = store.invite_touch_address(invite.id, net, now)
            audit_event(request, "invite.redeem", invite=invite.id, name=invite.name, network=net, new_address=is_new, kept_existing=True)
            invite = store.invite_get(invite.id) or invite
            return invite_view(request, invite, now, "known", until=existing.expires_at)
        label = existing.label if existing is not None and existing.label else invite.name
        try:
            entry = store.upsert(net, label, expires, now, created_by=f"invite:{invite.name}")
        except ValidationError as exc:
            return redirect_with_flash("/", "alert", t(exc.key, **exc.params))
```

## Anonymous unknown-token requests from a handful of addresses lock every invitation link for all holders (shared process-wide throttle budget on /i/{token})

Fingerprint `whitelister/app.py:open_invite/invite_throttle:global-budget-shared-lockout` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:708` (entrypoint, invite_page (GET /i/{token})): Unauthenticated request with any token string; also reached by invite_redeem (POST, line 725) through the same open_invite call.
2. `whitelister/app.py:685` (propagation, open_invite): Throttle key derived from the resolved client address (IPv4 address or IPv6 /64) via throttle_key.
3. `whitelister/app.py:692` (propagation, open_invite): Unknown or closed token -> invite_throttle.record_failure(key).
4. `whitelister/security.py:187` (propagation, LoginThrottle.record_failure): Window counter across all keys exceeds global_budget (30) -> _global_until = now + 60 for the whole process.
5. `whitelister/security.py:164` (propagation, LoginThrottle.retry_after): until = max(_global_until, own_until): a fresh, never-failing key inherits the global lock.
6. `whitelister/app.py:689` (sink, open_invite): 429 'too many attempts, try again later' returned to every client, so legitimate holders cannot view (GET) or redeem (POST) valid links while the lock is renewed.

### Evidence
- `whitelister/app.py:119`: invite_throttle built with the login limits and the implicit default global_budget=30; comment 'unknown tokens cost like wrong passwords'.
- `whitelister/security.py:148`: global_budget defaults to 30 failures per minute, process-wide.
- `whitelister/security.py:188`: _global_until = max(_global_until, now + 60) once the shared window exceeds the budget.
- `whitelister/app.py:688`: retry_after(key) consulted before the token lookup; non-zero -> 429 for GET and POST alike.
- `whitelister/app.py:728`: invite_redeem uses the same open_invite, so redemption is denied as well.
- `README.md:234`: 'The redeem path must be reachable without a login': /i/ is intentionally exposed to anonymous clients.

### Dummy attacker and affected resource
Anonymous internet client with ~11 source addresses (or one IPv6 /56) and no credentials or link.

### Native input and bounded instructions
- `GET /i/<34-char unknown token> repeated 3 times from each of 11 distinct source addresses (33 requests) within one minute`
- `GET /i/<valid token> and same-origin POST /i/<valid token> from an untouched address immediately after`

1. Run the app in-process (httpx.ASGITransport, TRUSTED_PROXIES=10.0.0.0/8, trusted-proxy peer 10.0.0.5, X-Forwarded-For selects the client address; no BW_API_URL).
2. Log in as the operator and create one invitation; keep the link's token.
3. From an untouched address (198.51.100.90) GET /i/<token>: expect 200.
4. From each of 11 distinct source addresses (192.0.2.1 .. 192.0.2.11) send three GET /i/<unknown 34-char token> requests (33 total) within one minute.
5. From the untouched IPv4 address and from an untouched IPv6 address GET /i/<token> and POST /i/<token>: observe the status and whether a whitelist entry for that address was created.

### Observed output and the invariant it proves
I reproduced this in the sandbox. Statuses for the 33 attacker requests: 31x404 then 2x429 (the 31st failure trips the shared budget; the 32nd and 33rd are refused with 429 before any lookup). The untouched legitimate holder 198.51.100.90 afterwards got GET=429 (body 'too many attempts, try again later') and POST=429, and no whitelist entry was created for it. An untouched IPv6 holder (2001:db8:ffff::1) got GET=429. Operator /login from a fresh address still returned 303 (separate LoginThrottle instance). A pure LoginThrottle model with the same inputs gave retry_after(fresh key)=61 s right after the 33 failures from 11 keys and 0 s at +61 s, matching automatic 60 s recovery.

Intended behaviour: A client guessing invite tokens should exhaust only its own allowance (per-address / per-/64 exponential lockout); holders of valid links from other addresses should keep being able to open and redeem them.

### Conditions and containment
- network_routing: Attacker controls at least 11 distinct throttle keys per minute (IPv4 addresses, or IPv6 /64s - a single /56 gives 256) reaching /i/ directly or through the trusted proxy; sustained lockout needs fresh keys as per-key locks escalate (roughly 190 keys per hour).
- system_configuration: Default LOGIN_MAX_FAILURES=3 and hard-coded global budget 30/min; /i/ reachable without authentication as the README requires; single uvicorn process so the budget is service-wide.
- data_state: At least one open invitation whose holder tries to open or redeem it during the lock.

### Remediation and regression case
Do not apply the process-wide failure budget to invitation lookups: the budget protects password-hash CPU, which the token path does not spend (SHA-256 + indexed lookup), and token entropy (192 bits) already makes guessing infeasible. Make global_budget optional in LoginThrottle and build invite_throttle without it, keeping the per-address / per-/64 exponential lockout. Regression test: 33 unknown-token requests from 11 addresses must leave GET/POST /i/<valid> from a twelfth address at 200.

`whitelister/security.py`:

```python
    def __init__(self, max_failures: int, lock_seconds: int, global_budget: int | None = 30) -> None:
        ...
        self.global_budget = global_budget  # None = no process-wide lock

    def record_failure(self, key: str, now: float | None = None) -> int:
        ...
            self._state[key] = (failures, now + lock, now)
            if self.global_budget is not None:
                if now - self._window_start > 60:
                    self._window_start, self._window_failures = now, 0
                self._window_failures += 1
                if self._window_failures > self.global_budget:
                    self._global_until = max(self._global_until, now + 60)
                    lock = max(lock, 60.0)
            return int(lock)
```

`whitelister/app.py`:

```python
    # unknown tokens are locked per address like wrong passwords, but without the process-wide budget:
    # the lookup costs no CPU worth protecting and a shared lock would let a few addresses close every link
    invite_throttle = LoginThrottle(settings.login_max_failures, settings.login_lock_seconds, global_budget=None)
```

## Operator removal of an invite-created entry does not stick: the stale invite_addresses row lets the removed redeemer re-list itself past an exhausted budget, logged as a renewal

Fingerprint `whitelister/entries.py:EntryStore.delete:invite_addresses-stale-known-readd` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:608` (entrypoint, delete_entry): Operator POST /entries/{entry_id}/delete passes require_post (session row, CSRF HMAC, same_origin).
2. `whitelister/app.py:613` (propagation, delete_entry): store.delete(entry_id) removes only the entries row; nothing touches invite_addresses for entry.network.
3. `whitelister/entries.py:270` (propagation, EntryStore.delete): DELETE FROM entries WHERE id = ?; the (invite_id, network) redemption row written at entries.py:400-403 survives.
4. `whitelister/app.py:728` (propagation, invite_redeem): The removed redeemer POSTs /i/{token} again (same_origin passed at 726); open_invite only checks throttle and that the link is open (not revoked, valid_until in the future).
5. `whitelister/app.py:736` (propagation, invite_redeem): known = any(a['network'] == net for a in store.invite_addresses(invite.id)) is True because of the stale row; whether the entry still exists is never consulted.
6. `whitelister/app.py:737` (propagation, invite_redeem): 'if not known and invite.remaining == 0' is skipped: the budget gate is bypassed even for an exhausted link.
7. `whitelister/app.py:741` (propagation, invite_redeem): store.upsert(net, invite.name, now + access_days, ...) re-creates the deleted entry (new id) for the full access period.
8. `whitelister/entries.py:396` (propagation, EntryStore.invite_touch_address): UPDATE invite_addresses SET last_at ... hits the stale row (rowcount 1), so the method returns False: the re-add is classified as a refresh, not a new address.
9. `whitelister/app.py:746` (sink, invite_redeem): audit 'invite.redeem' with new_address=false (line 745) and history event 'invite_refresh'; the network is back in active_networks, the bw-api cache drop is issued and /ips.txt serves it again.

### Evidence
- `whitelister/entries.py:268`: EntryStore.delete removes only the entries row by primary key; no invite_addresses handling.
- `whitelister/entries.py:392`: invite_touch_address docstring: True only when the address is new to this invite 'and counts against its budget'; with a stale row the re-add never counts and is reported as a refresh.
- `whitelister/app.py:736`: The known/budget decision in invite_redeem reads only invite_addresses, never whether the entry still exists.
- `whitelister/app.py:721`: invite_page computes existing = store.find(net) only for display; with the entry deleted the 'known' page renders 'already unlocked until ' with an empty date (observed).
- `whitelister/app.py:494`: The index lists each open invite with store.invite_addresses(i.id); after the delete the removed address is still shown under the invite and counted in 'used'.
- `README.md:220`: Documented semantics of the free re-redemption: 'is free and only restarts that address's period'.
- `whitelister/locales/en.json:157`: Revoke dialog: 'Addresses already on the list stay until they expire', i.e. per-address removal is meant to go through the entry list's Remove action, which this gap undoes.

### Dummy attacker and affected resource
A guest who was unlocked via a shared invitation link and whose address the operator then removed from the whitelist; the guest still has the link and simply opens it again from the same connection.

### Native input and bounded instructions
- `GET /i/<token> from the removed address (198.51.100.77 in the local check)`
- `POST /i/<token> with headers Origin: <app origin>, Sec-Fetch-Site: same-origin and an empty body, from the removed address`

1. Operator: log in, create an invitation (name 'Tax advisor', access 14 days, link 14 days, addresses 1) and copy the /i/<token> link shown once.
2. Guest A (198.51.100.77): POST /i/<token> with same-origin headers -> 200; an entry for 198.51.100.77 exists with created_by 'invite:Tax advisor' and a 14-day expiry.
3. Guest B (198.51.100.78): POST /i/<token> -> 409 (budget exhausted), no entry.
4. Operator: POST /entries/<id of A>/delete with the page CSRF token -> 303 and the 'was removed' flash; store.find(198.51.100.77) is None, but GET / still shows '1 of 1 addresses used' with 198.51.100.77 listed under the invite.
5. Guest A: GET /i/<token> -> 200 with lead 'This connection is already unlocked until . Press the button to start the period again.' and button 'Renew my access'; then POST /i/<token> -> 200 'valid until ...'.
6. Observe: entry for 198.51.100.77 exists again (new id) with a fresh 14-day expiry, a bw-api cache drop is issued and /ips.txt serves the address; history shows 'invite_refresh' after 'delete'; the audit event has new_address=false; the invite stays 1/1 (remaining 0); Guest B's POST still gets 409.

### Observed output and the invariant it proves
Sandboxed ASGITransport run (fake bw-api via httpx.MockTransport, in-memory store, scratch file check-1-v3-8-delete-readd.txt): 'A POST: 200 | entry: (1, invite:Tax advisor, 14.0)'; 'B POST (budget 1 exhausted): 409 | entry B: None'; 'operator delete: 303 | was removed flash: True | store.find A: None'; 'index after delete shows 1 of 1 addresses used: True | .77 still listed under invite: True'; 'invite_addresses rows after delete: [{invite_id: 1, network: 198.51.100.77}]'; 'active list after delete: []'; 'A GET after delete: 200 | lead: This connection is already unlocked until . Press the button to start the period again. | button: True'; 'A POST after delete: 200 | valid until in page: True'; 'entry re-created: (2, invite:Tax advisor, 14.0)'; 'bw cache drop issued on re-add: [(DELETE, /cache/global/whitelist/whitelist-download/b563f953e7c6fe56e62dd212cad4d10b4449d80f.list)]'; 'active list after re-add: [198.51.100.77]'; 'history newest-first: [(invite_refresh, 198.51.100.77), (delete, 198.51.100.77), (invite_redeem, 198.51.100.77), (invite_create, )]'; 'invite used/max after re-add: 1 / 1 remaining: 0'; 'B POST after A re-add: 409 | entry B: None'; '/ips.txt: 200 # bunkerweb-whitelister\n198.51.100.77\n'; audit lines: invite.redeem new_address=true, entry.delete network=198.51.100.77, invite.redeem new_address=false.

Intended behaviour: README.md:218-220 and whitelister/locales/en.json:139 define the free re-redemption as 'opening it again from a known address is free and only restarts that address's period' / 'only refreshes that address', i.e. a renewal of an existing listing. An entry the operator removed through 'Remove {network} from the whitelist?' (en.json:69) has no period to restart: a later redemption from that address is either a new unlock that must pass the budget gate and be audited as new_address=true, or it is refused while the operator's removal stands. The operator-facing usage count should also not keep attributing a slot to an address that is no longer listed.

### Conditions and containment
- data_state: An invitation link that is still open (not revoked, valid_until in the future) and an entry created through it that the operator has deleted via POST /entries/{id}/delete.
- network_routing: The removed visitor connects again from the same IPv4 address or the same IPv6 /64 (redeemer_network), i.e. the identity the operator just removed, as seen by the app through its trusted proxy.
- authentication_level: No login: the actor is the anonymous holder of the (possibly shared) link, a lower-trust principal than the operator who performed the removal.

### Remediation and regression case
Make the redemption history agree with the entry lifecycle. When the operator deletes an entry, mark (do not delete, so the slot stays consumed) the matching invite_addresses rows as removed, and have invite_page/invite_redeem refuse a removed address while the removal stands (or, if re-admission is wanted, treat it as a new unlock: run the budget gate and make invite_touch_address report it as new). Do not derive `known` from invite_addresses alone: require store.find(net) to exist as well, otherwise the normal budget path and new_address=true audit apply. Note that only checking store.find is insufficient on its own because invite_touch_address's UPDATE would still hit the stale row and return False. Regression test: invite with max_addresses=1, redeem, operator delete, second GET from the same address must not render the 'already unlocked' state with an empty date, and a second POST must not re-create the entry (or must be counted and logged as a new unlock).

`whitelister/entries.py`:

```python
# in EntryStore.__init__, after creating invite_addresses:
if "removed_at" not in {r["name"] for r in self._conn.execute("PRAGMA table_info(invite_addresses)")}:
    self._conn.execute("ALTER TABLE invite_addresses ADD COLUMN removed_at TEXT")

def invite_addresses_removed(self, network: str, now: datetime) -> int:
    """The operator took this network off the list: its redemptions may not renew it."""
    with self._lock:
        return self._conn.execute(
            "UPDATE invite_addresses SET removed_at = ? WHERE network = ? AND removed_at IS NULL", (_iso(now), network)
        ).rowcount

# invite_addresses(): also SELECT removed_at and return it in each dict ("removed_at": _dt(r["removed_at"])).
```

`whitelister/app.py`:

```python
# delete_entry, right after a successful store.delete(entry_id):
store.invite_addresses_removed(entry.network, datetime.now(UTC))

# invite_page and invite_redeem, replacing the `known` computation:
recorded = next((a for a in store.invite_addresses(invite.id) if a["network"] == net), None)
if recorded is not None and recorded["removed_at"] is not None:
    return invite_view(request, invite, now, "closed", status_code=403)  # removed by the operator; a new link is needed
known = recorded is not None and store.find(net) is not None
```
