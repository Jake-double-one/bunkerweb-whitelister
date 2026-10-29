# Findings detail (confirmed, medium or higher)

No confirmed finding is rated medium or higher in this run. The two confirmed findings are rated low; their complete traces follow for completeness.

## Entry policy tightening is not applied to stored rows: a password holder keeps, revives and makes permanent networks the current MIN_PREFIX_*/ALLOW_PRIVATE policy forbids

Fingerprint `whitelister/app.py:extend_entry:stored-network-not-revalidated` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:429` (entrypoint, extend_entry route POST /entries/{entry_id}/extend): Logged-in operator (session + same_origin + CSRF via require_post at line 437) submits duration and optional until for an existing entry id.
2. `whitelister/app.py:440` (propagation, extend_entry): entry = store.get(entry_id): the stored network string is loaded but never passed to parse_network, so MIN_PREFIX_*/ALLOW_PRIVATE and the non-routable checks are not applied to it.
3. `whitelister/app.py:445` (propagation, extend_entry): duration == 'forever' sets new_end = None with no MAX_DAYS cap and no policy check.
4. `whitelister/app.py:531` (propagation, _extend_from): An expired row (expires_at <= now) counts from now, so an expired-but-retained row is revived by any day-based extension.
5. `whitelister/app.py:461` (propagation, extend_entry): store.set_expiry(entry_id, new_end) persists the new (or NULL) expiry for the un-revalidated network.
6. `whitelister/entries.py:182` (propagation, EntryStore.set_expiry): UPDATE entries SET expires_at = ? WHERE id = ?: the row becomes active again or permanent (NULL expiry is never selected by purge_expired, entries.py:205-208).
7. `whitelister/app.py:302` (sink, ips_txt): render_list(store.active_networks(now)) serves every non-expired stored network string to the BunkerWeb scheduler; active_networks (entries.py:214) filters by expiry only.

### Evidence
- `whitelister/entries.py:36`: parse_network is the sole implementation of the entry policy: min prefix (45-47), non-routable (48-49), private (50-51).
- `whitelister/app.py:410`: The only call site of parse_network in the package is add_entry (POST /entries); grep over whitelister/ finds no other (tests import it directly).
- `whitelister/app.py:440`: extend_entry loads the row and proceeds to duration handling (445-458) and set_expiry (461) without any network validation.
- `whitelister/app.py:270`: listed_entry is the only reader that re-parses a stored network, and only with ipaddress.ip_network for display matching, not with parse_network/settings.
- `whitelister/entries.py:117`: EntryStore.__init__ only creates tables (CREATE TABLE IF NOT EXISTS); no migration or re-validation of existing rows on open.
- `whitelister/config.py:217`: min_prefix_v4, min_prefix_v6 (218) and allow_private (219) are read from the environment at each process start, so a tightening is an ordinary restart with changed variables.
- `whitelister/entries.py:214`: active_networks selects by 'expires_at IS NULL OR expires_at > ?' only, so a NULL-expiry row is served forever.
- `whitelister/bunkerweb.py:164`: Syncer._run purges only rows with expires_at <= now - EXPIRED_RETENTION_DAYS via purge_expired (entries.py:202-209); active and NULL-expiry rows are never purged and the policy is not consulted.
- `README.md:72`: Documented policy: networks wider than MIN_PREFIX_V4 / MIN_PREFIX_V6 are refused; README.md:133-134 call these the 'Widest allowed network' and ALLOW_PRIVATE 'Allow RFC 1918 / ULA entries'.

### Dummy attacker and affected resource
A password holder notices that the operator tightened the entry rules (adding 10.0.0.0/8 or a private range is now refused) but that previously added rows are still listed on the page. Using the extend control on those rows they keep them active, bring an expired one back, or set them to forever, so the whitelist keeps networks the operator intended to no longer allow.

### Native input and bounded instructions
- `POST /entries  network=10.0.0.0/8  label=dummy  duration=30  _csrf=<token>   (phase A, ALLOW_PRIVATE=yes MIN_PREFIX_V4=8)`
- `POST /entries  network=192.168.50.0/24  label=dummy  duration=1  _csrf=<token>   (phase A; then its expires_at moved 2 h into the past to make it expired-but-retained)`
- `POST /entries  network=10.0.0.0/8  duration=7  _csrf=<token>   (phase B, ALLOW_PRIVATE=no MIN_PREFIX_V4=16: refused)`
- `POST /entries  network=192.168.50.0/24  duration=7  _csrf=<token>   (phase B: refused)`
- `POST /entries/2/extend  duration=14  _csrf=<token>   (phase B: revives the expired private /24)`
- `POST /entries/1/extend  duration=forever  _csrf=<token>   (phase B: makes the /8 permanent)`
- `POST /entries/2/extend  duration=forever  _csrf=<token>   (phase B: makes the /24 permanent)`
- `GET /ips.txt  from TCP peer 10.0.0.2 with no forwarding headers`

1. Run the app in-process with httpx.ASGITransport(app, client=('10.0.0.2', 12345)) against a file-backed SQLite store in a scratch DATA_DIR, with WHITELISTER_PASSWORD, SESSION_SECRET, COOKIE_SECURE=no, TRUSTED_PROXIES=none, LIST_ALLOWED_NETWORKS=10.0.0.0/8, TZ=UTC and no BW_API_URL (API disabled, refresh_after_change is a no-op).
2. Phase A: load_settings + create_app with ALLOW_PRIVATE=yes MIN_PREFIX_V4=8; POST /login, read the _csrf token from GET /, POST /entries for 10.0.0.0/8 (30 days) and 192.168.50.0/24 (1 day); after the lifespan closes, reopen EntryStore on the same file and set the /24 row's expires_at to two hours ago via set_expiry (an expired-but-retained row).
3. Phase B: new load_settings + create_app on the same DATA_DIR with ALLOW_PRIVATE=no MIN_PREFIX_V4=16; GET /ips.txt; log in; POST /entries for 10.0.0.0/8, 192.168.50.0/24 and 192.168.50.1 and decode the wl_flash cookie of each 303 (itsdangerous URLSafeTimedSerializer, salt 'whitelister.flash').
4. POST /entries/<id of /24>/extend duration=14, POST /entries/<id of /8>/extend duration=forever, POST /entries/<id of /24>/extend duration=forever; decode the flash after each and read the rows' expires_at; control: POST /entries/999/extend; GET /ips.txt again; call store.purge_expired(now + 20 years).
5. Compare: the add path refuses both networks, the extend path accepts them, /ips.txt serves both, purge removes nothing.

### Observed output and the invariant it proves
Verifier run (sandbox, python 3.13.17, 2026-10-29 13:24 UTC). Phase A (allow_private=True min_prefix_v4=8): POST /entries 10.0.0.0/8 -> 303 'info: 10.0.0.0/8 is allowed until 2026-11-28 13:24.' (id=1); 192.168.50.0/24 -> 303 'info: ... allowed until 2026-10-30 13:24.' (id=2, then set expires_at=2026-10-29 11:24:33 UTC). Phase B (allow_private=False min_prefix_v4=16, same SQLite file): GET /ips.txt -> 200 '# bunkerweb-whitelister\n10.0.0.0/8\n'. POST /entries 10.0.0.0/8 -> 303 flash 'alert: Networks must be /16 or smaller.'; 192.168.50.0/24 and 192.168.50.1 -> 'alert: Private addresses are not allowed here.'. POST /entries/2/extend duration=14 -> 303 'info: 192.168.50.0/24 now runs until 2026-11-12 13:24.' (expires_at 2026-11-12 13:24:33 UTC, revived from expired). POST /entries/1/extend duration=forever -> 303 'info: 10.0.0.0/8 now never expires.' expires_at=None. POST /entries/2/extend duration=forever -> 303 'info: 192.168.50.0/24 now never expires.' expires_at=None. Control POST /entries/999/extend -> 'alert: That entry no longer exists.'. GET /ips.txt -> 200 '# bunkerweb-whitelister\n10.0.0.0/8\n192.168.50.0/24\n'. purge_expired(now+20y) removed [] ; active_networks = ['10.0.0.0/8', '192.168.50.0/24']. Transcript: scratch/check-1-v3-7-repro.txt (not promoted by the verifier).

Intended behaviour: MIN_PREFIX_V4/V6 and ALLOW_PRIVATE (README.md:71-73, 133-134) describe the widest and the kind of networks allowed on the whitelist. README.md:32-33 states that expired entries stay visible, marked red and extendable until EXPIRED_RETENTION_DAYS, but does not say that extending bypasses the current entry policy. Any operation that makes or keeps a stored network active, in particular extend (including forever) and the list served to BunkerWeb, should re-apply the current policy; a row that fails it should not be extendable (and should be flagged or excluded from /ips.txt) until the container operator re-permits it or deletes it.

### Conditions and containment
- authentication_level: Attacker is a logged-in operator (holder of the single shared password) with a valid session and CSRF token; this principal is bounded by, but cannot change, the container operator's entry policy.
- system_configuration: The container operator tightened MIN_PREFIX_V4/V6 or set ALLOW_PRIVATE=no (or otherwise tightened parse_network) after rows had been accepted under the earlier permissive settings, and did not manually delete those rows.
- data_state: A row for the now-forbidden network exists in the SQLite entries table: active (extendable / forever) or expired within EXPIRED_RETENTION_DAYS (default 7) so it has not yet been purged and can be revived.

### Remediation and regression case
Re-apply the current entry policy to the stored network on every path that keeps or makes a row active. Required: in extend_entry call parse_network(entry.network, settings) inside the existing try block so a row that fails the current policy is refused with the same alert flash as the add form (the operator must delete it or the container operator must re-permit it); this closes the demonstrated extend/revive/forever path. Recommended in addition, because an already-active forbidden row is still served until it expires: add EntryStore.policy_violations(settings), log a warning for each at startup in the lifespan, and either exclude those rows from active_networks (so /ips.txt matches the policy immediately) or surface them in the UI for deletion. Regression test: create 10.0.0.0/8 with MIN_PREFIX_V4=8 on a file-backed store, rebuild the app on the same DATA_DIR with MIN_PREFIX_V4=16, POST /entries/{id}/extend with duration=14 and duration=forever, and assert the 303 carries the prefix_too_wide alert and expires_at is unchanged (the two apps must not share one EntryStore object: the first lifespan closes it).

`whitelister/app.py`:

```python
        entry = store.get(entry_id)
        if entry is None:
            return redirect_with_flash("/", "alert", t("error.not_found"))
        now = datetime.now(UTC)
        try:
            parse_network(entry.network, settings)  # the stored row must still satisfy the current policy
            if duration == "forever":
                new_end = None
            elif duration == "date":
                new_end = expiry_from_date(until, now, settings, tz)
            else:
                try:
                    days = int(duration)
                except ValueError as exc:
                    raise ValidationError("error.duration_missing") from exc
                if not 1 <= days <= settings.max_days:
                    raise ValidationError("error.days_out_of_range", max=settings.max_days)
                new_end = _extend_from(entry, now) + timedelta(days=days)
                if new_end > now + timedelta(days=settings.max_days):
                    raise ValidationError("error.days_out_of_range", max=settings.max_days)
        except ValidationError as exc:
            return redirect_with_flash("/", "alert", t(exc.key, **exc.params))

```

`whitelister/entries.py`:

```python
    def active_networks(self, now: datetime) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT network FROM entries WHERE expires_at IS NULL OR expires_at > ? ORDER BY network",
                (_iso(now),),
            ).fetchall()
        return [r["network"] for r in rows]

    def policy_violations(self, settings: Settings) -> list[Entry]:
        """Stored rows that no longer pass the current entry policy (for a startup warning / exclusion)."""
        bad = []
        for e in self.list():
            try:
                parse_network(e.network, settings)
            except ValidationError:
                bad.append(e)
        return bad

```

`tests/test_app.py`:

```python
def test_extend_reapplies_current_policy(env):
    from whitelister.app import create_app

    # file-backed store in DATA_DIR (tmp_path) so a second app can reopen the same rows; no API
    env(ALLOW_PRIVATE="yes", MIN_PREFIX_V4="8", BW_API_URL=None)
    app = create_app(load_settings())

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            r = await c.post("/entries", data={"network": "10.0.0.0/8", "duration": "7", "_csrf": token})
            assert r.status_code == 303
            return app.state.store.find("10.0.0.0/8")

    entry = run(go())
    assert entry is not None

    env(ALLOW_PRIVATE="no", MIN_PREFIX_V4="16", BW_API_URL=None)
    app2 = create_app(load_settings())  # same whitelist.sqlite3, tightened policy

    async def go2():
        async with app2.router.lifespan_context(app2), await _client(app2) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            for data in ({"duration": "14"}, {"duration": "forever"}):
                r = await c.post(f"/entries/{entry.id}/extend", data={**data, "_csrf": token})
                assert r.status_code == 303
                assert "/16 or smaller" in (await c.get("/")).text  # alert flash rendered
                assert app2.state.store.get(entry.id).expires_at == entry.expires_at

    run(go2())

```

## IPv6 scope id with an embedded newline passes parse_network and is written verbatim to /ips.txt, letting a logged-in operator list addresses the entry policy refuses

Fingerprint `whitelister/entries.py:network_text:ipv6-scope-id-newline-into-ips-list` · severity **low** · confidence high

### Ordered trace
1. `whitelister/app.py:396` (entrypoint, add_entry (POST /entries)): Logged-in operator submits the urlencoded `network` form field; a %0A in the body decodes to a literal newline inside the value.
2. `whitelister/app.py:410` (propagation, add_entry): parse_network(network, settings) is the only validation applied to the value; line 411 then calls network_text(net).
3. `whitelister/entries.py:42` (propagation, parse_network): ipaddress.ip_network(text, strict=False) accepts '2a00::1%x\n127.0.0.1' as host 2a00::1 with scope id 'x\n127.0.0.1'; lines 45-51 check prefix, routability and privacy on the parsed object only (2a00::1 is routable), never on the scope text.
4. `whitelister/entries.py:58` (propagation, network_text): For num_addresses == 1 returns str(net.network_address), which IPv6Address.__str__ renders as address + '%' + scope id verbatim, i.e. '2a00::1%x\n127.0.0.1'.
5. `whitelister/app.py:418` (propagation, add_entry): store.upsert(text, ...) writes the multi-line string into the UNIQUE `network` column via a parameterised INSERT.
6. `whitelister/entries.py:214` (propagation, EntryStore.active_networks): SELECT network ... returns the stored column verbatim for every unexpired entry.
7. `whitelister/app.py:302` (propagation, ips_txt (GET /ips.txt)): After the peer / forwarding-header / token gate, render_list(store.active_networks(now)) is served as text/plain to the BunkerWeb scheduler.
8. `whitelister/entries.py:248` (sink, render_list): '\n'.join(['# bunkerweb-whitelister', *networks]) emits the raw stored strings; the embedded newline turns the scope text into additional list lines with no re-validation.

### Evidence
- `whitelister/entries.py:42`: Sandbox probe on the pinned interpreter (3.13.17): ipaddress.ip_network('2a00::1%x\n127.0.0.1', strict=False) succeeds, prefixlen 128, network_address.scope_id == 'x\n127.0.0.1', is_loopback False; '2a00::1%x%y' and '2a00::1%' raise ValueError (only a second '%' or an empty scope is refused).
- `whitelister/entries.py:48`: The routability/private checks run on the parsed object: parse_network('127.0.0.1') raises error.ip_not_routable while parse_network('2a00::1%x\n127.0.0.1') returns a network and network_text() of it is the two-line string '2a00::1%x\n127.0.0.1'.
- `whitelister/entries.py:58`: network_text keeps the scope id: observed stored values '2a00::1%x\n127.0.0.1', '2a00::1%x\n# injected\n224.0.0.1' (3 lines) and 'fe80::1%eth0'; '2a00::%x\n10.0.0.0/8' is refused with error.prefix_too_wide because '/8' becomes the IPv6 prefix.
- `whitelister/entries.py:248`: render_list performs no per-line validation; sandbox GET /ips.txt returned 200 with body '# bunkerweb-whitelister\n2a00::1%x\n127.0.0.1\n' after the injected POST (check-1-repro.txt).
- `README.md:71`: Security model states loopback, multicast, unspecified and reserved ranges are refused; the sandbox run shows 127.0.0.1 served as a list line under default settings and 10.0.0.1 served under ALLOW_PRIVATE=no although both are refused when posted directly.

### Dummy attacker and affected resource
A person holding the whitelister password (any logged-in operator) wants to whitelist a host that the deployment's entry policy refuses, e.g. a loopback host or, under ALLOW_PRIVATE=no, a private host, or wants to append arbitrary lines to the list BunkerWeb downloads.

### Native input and bounded instructions
- `network=2a00::1%25x%0A127.0.0.1&label=probe&duration=7&_csrf=<token>`
- `network=2a00::1%25x%0A10.0.0.1&label=probe&duration=7&_csrf=<token>  (deployment with ALLOW_PRIVATE=no)`
- `network=2a00::1%25x%0A%23%20injected%0A224.0.0.1&label=probe&duration=7&_csrf=<token>`

1. Run the app with default entry settings (TRUSTED_PROXIES=10.0.0.0/8, COOKIE_SECURE=no, SESSION_SECRET of >= 32 chars, WHITELISTER_PASSWORD of >= 12 chars, a fake BunkerWeb API or no BW_API_URL) and send requests from a peer inside LIST_ALLOWED_NETWORKS, e.g. 10.0.0.2.
2. POST /login with the password; GET / and read the hidden _csrf value from the form.
3. Control: POST /entries with network=127.0.0.1, duration=7 and the token; confirm no entry row exists and GET /ips.txt (no forwarding headers) returns only '# bunkerweb-whitelister'.
4. POST /entries with network='2a00::1%x' + newline + '127.0.0.1' (urlencoded 2a00::1%25x%0A127.0.0.1), duration=7 and the token.
5. GET /ips.txt from the allowed peer without forwarding headers and split the body on newline; repeat the control and injection with network=10.0.0.1 / '2a00::1%x\n10.0.0.1' in a deployment started with ALLOW_PRIVATE=no.

### Observed output and the invariant it proves
Sandboxed in-process run (httpx.ASGITransport, in-memory EntryStore, MockTransport fake BunkerWeb API, Python 3.13.17, httpx 0.28.1, peer 10.0.0.2): control POST /entries network=127.0.0.1 -> 303, stored rows [], GET /ips.txt -> 200 '# bunkerweb-whitelister\n'. Injection POST /entries network='2a00::1%x\n127.0.0.1' -> 303, stored rows [{'id': 1, 'network': '2a00::1%x\n127.0.0.1', 'label': 'probe'}], GET /ips.txt -> 200 with lines ['# bunkerweb-whitelister', '2a00::1%x', '127.0.0.1']. With ALLOW_PRIVATE=no: direct 10.0.0.1 -> stored rows [], list unchanged; '2a00::1%x\n10.0.0.1' -> 303, one row, /ips.txt lines ['# bunkerweb-whitelister', '2a00::1%x', '10.0.0.1']. The audit line JSON-escapes the newline ('"network": "2a00::1%x\\n127.0.0.1"'). Unit level: parse_network+network_text of '2a00::1%x\n# injected\n224.0.0.1' yields a three-line stored string; '2a00::%x\n10.0.0.0/8' is refused (prefix_too_wide).

Intended behaviour: Every line of /ips.txt after the header is exactly one address or CIDR that passed parse_network's prefix, routability and private-address policy (README.md security model: loopback, multicast, unspecified and reserved ranges are refused; ALLOW_PRIVATE=no refuses private ranges).

### Conditions and containment
- authentication_level: Requires a logged-in operator session (knowledge of the shared password) plus the session's CSRF token and a same-origin request; what is bypassed is the configured entry policy, not authentication or CSRF.
- system_configuration: Under the default MIN_PREFIX_V6=48 only single hosts, comment/arbitrary text lines and IPv6 CIDRs with prefix >= 48 can be injected, because a trailing '/n' is applied to the carrier IPv6 address; injecting IPv4 CIDRs such as 10.0.0.0/8 would additionally require MIN_PREFIX_V6 <= 8 (prefix >= MIN_PREFIX_V6).
- third_party_dependency: Whether BunkerWeb actually honours an injected line depends on its whitelist-download job's own per-line parsing; no BunkerWeb source is in the repository and the downstream effect was not observed locally. The demonstrated result ends at the text served by /ips.txt.

### Remediation and regression case
Refuse IPv6 scope ids at the parser and make the list writer defensive. In parse_network reject any input containing '%' or interior whitespace before calling ipaddress, and additionally reject a parsed IPv6 network whose network_address.scope_id is not None (scope ids are never meaningful for a reverse-proxy whitelist). In render_list emit only values that are printable, contain no whitespace or '%', and round-trip through ipaddress.ip_network, so rows stored before the fix cannot add lines. Add regression tests: parse_network('2a00::1%x\n127.0.0.1') and parse_network('fe80::1%eth0') raise error.ip_invalid, and every non-header line of render_list output parses as a single network. Verified in the sandbox against the current code: the re-implemented parser refuses all scope-id variants (LF, CRLF, NUL, aligned CIDR) while 1.2.3.4, 203.0.113.42/24, 2a00::1, 2001:db8::/48 and ::ffff:1.2.3.4 are still accepted unchanged, and the defensive render_list drops legacy multi-line rows.

`whitelister/entries.py`:

```python
def parse_network(raw: str, settings: Settings) -> IPNetwork:
    """Parse an address or CIDR. Returns a normalized network object."""
    text = (raw or "").strip()
    # A scope id ("%eth0") is never meaningful for a reverse-proxy whitelist and ipaddress
    # accepts almost any characters inside it (including newlines); refuse it outright.
    if not text or len(text) > 64 or "%" in text or any(ch.isspace() for ch in text):
        raise ValidationError("error.ip_invalid")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValidationError("error.ip_invalid") from exc
    if net.version == 6 and net.network_address.scope_id is not None:
        raise ValidationError("error.ip_invalid")
    min_prefix = settings.min_prefix_v4 if net.version == 4 else settings.min_prefix_v6
    if net.prefixlen < min_prefix:
        raise ValidationError("error.prefix_too_wide", min=min_prefix)
    if net.is_multicast or net.is_unspecified or net.is_loopback or net.is_reserved:
        raise ValidationError("error.ip_not_routable")
    if net.is_private and not settings.allow_private:
        raise ValidationError("error.ip_private")
    return net


def render_list(networks: list[str]) -> str:
    """The plain-text list BunkerWeb downloads: one entry per line.

    Defensive: emit only single printable tokens that parse as a network, so a stored
    value can never contribute more than one line (covers rows stored before the fix).
    """
    safe: list[str] = []
    for n in networks:
        if not n.isprintable() or any(ch.isspace() for ch in n) or "%" in n:
            continue
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            continue
        safe.append(n)
    lines = ["# bunkerweb-whitelister", *safe]
    return "\n".join(lines) + "\n"

```
