from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from whitelister.bunkerweb import cache_file_name
from whitelister.config import ConfigError, load_settings

from .conftest import PASSWORD, login

PROXY_HEADERS = {"x-forwarded-for": "203.0.113.42"}


def run(coro):
    return asyncio.run(coro)


async def _client(app, peer="10.0.0.2"):
    transport = httpx.ASGITransport(app=app, client=(peer, 12345))
    return httpx.AsyncClient(transport=transport, base_url="http://whitelist.test", headers={"host": "whitelist.test"})


def csrf_of(html: str) -> str:
    match = re.search(r'name="_csrf" value="([0-9a-f]+)"', html)
    assert match, "csrf token missing"
    return match.group(1)


# ------------------------------------------------------------------ config


def test_config_requires_trusted_proxies_decision(env):
    env(TRUSTED_PROXIES=None)
    with pytest.raises(ConfigError):
        load_settings()
    env(TRUSTED_PROXIES="none")
    assert load_settings().trusted_proxies == ()


def test_config_requires_password(env):
    env(WHITELISTER_PASSWORD=None)
    with pytest.raises(ConfigError):
        load_settings()
    env(WHITELISTER_PASSWORD="short")
    with pytest.raises(ConfigError):
        load_settings()


def test_config_requires_api_credentials_and_list_url(env):
    env(BW_API_USERNAME=None, BW_API_PASSWORD=None)
    with pytest.raises(ConfigError):
        load_settings()
    env(BW_API_USERNAME=None, BW_API_PASSWORD=None, BW_API_TOKEN="tok", WHITELIST_URL=None)
    with pytest.raises(ConfigError):
        load_settings()


def test_config_reads_secret_files(env, tmp_path):
    secret = tmp_path / "pw"
    secret.write_text(PASSWORD + "\n")
    env(WHITELISTER_PASSWORD=None, WHITELISTER_PASSWORD_FILE=str(secret))
    assert load_settings().password == PASSWORD


def test_config_generates_session_secret_once(env, tmp_path):
    env(SESSION_SECRET=None)
    first = load_settings()
    assert first.generated_secret and (tmp_path / "session.key").exists()
    assert oct((tmp_path / "session.key").stat().st_mode & 0o777) == "0o600"
    second = load_settings()
    assert second.session_secret == first.session_secret and not second.generated_secret


# ------------------------------------------------------------------ auth


def test_login_page_shows_client_ip_and_headers(make_client):
    app, _, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            r = await c.get("/login", headers=PROXY_HEADERS)
            assert r.status_code == 200
            assert "203.0.113.42" in r.text
            assert r.headers["content-security-policy"].startswith("default-src 'none'")
            assert r.headers["x-frame-options"] == "DENY"
            assert r.headers["cache-control"] == "no-store"
            assert "server" not in r.headers
            r = await c.get("/")
            assert r.status_code == 303 and r.headers["location"] == "/login"

    run(go())


def test_login_wrong_password_then_lockout(make_client):
    app, _, _ = make_client(LOGIN_MAX_FAILURES="2", LOGIN_LOCK_SECONDS="30")

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            r = await login(c, "nope")
            assert r.status_code == 401 and "wl_session" not in r.cookies
            r = await login(c, "nope")
            assert r.status_code == 401 and "30" in r.text
            r = await login(c, PASSWORD)  # locked even with the right password
            assert r.status_code == 429
            # another client is unaffected
            async with await _client(app, peer="10.0.0.9") as other:
                r = await login(other, PASSWORD, headers={"x-forwarded-for": "198.51.100.7"})
                assert r.status_code == 303

    run(go())


def test_login_sets_hardened_cookie_and_logout_clears_it(make_client):
    app, _, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            # the way a browser posts it: with Origin and Sec-Fetch-Site
            r = await login(c, headers={"origin": "http://whitelist.test", "sec-fetch-site": "same-origin"})
            assert r.status_code == 303 and r.headers["location"] == "/"
            assert r.headers["referrer-policy"] == "same-origin"
            cookie = r.headers["set-cookie"]
            assert "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict") and "Path=/" in cookie
            r = await c.get("/")
            assert r.status_code == 200
            token = csrf_of(r.text)
            r = await c.post("/logout", data={"_csrf": token})
            assert r.status_code == 303
            r = await c.get("/")
            assert r.status_code == 303
            # the old cookie is dead server-side, not just deleted in the browser
            c.cookies.set("wl_session", cookie.split(";", 1)[0].split("=", 1)[1])
            r = await c.get("/")
            assert r.status_code == 303

    run(go())


def test_cross_site_login_posts_do_not_count_as_failures(make_client):
    app, _, _ = make_client(LOGIN_MAX_FAILURES="2")

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            for _ in range(5):
                r = await login(c, "nope", headers={"sec-fetch-site": "cross-site"})
                assert r.status_code == 403
            r = await login(c, PASSWORD)
            assert r.status_code == 303

    run(go())


def test_ipv6_rotation_shares_one_throttle_key(make_client):
    app, _, _ = make_client(LOGIN_MAX_FAILURES="2")

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c, "nope", headers={"x-forwarded-for": "2001:db8:1:2::1"})
            await login(c, "nope", headers={"x-forwarded-for": "2001:db8:1:2::2"})
            r = await login(c, PASSWORD, headers={"x-forwarded-for": "2001:db8:1:2:ffff::9"})
            assert r.status_code == 429
            r = await login(c, PASSWORD, headers={"x-forwarded-for": "2001:db8:1:3::1"})
            assert r.status_code == 303

    run(go())


def test_unresolvable_client_cannot_log_in(make_client):
    app, _, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            r = await login(c, PASSWORD, headers={"x-forwarded-for": "203.0.113.5, garbage"})
            assert r.status_code == 403

    run(go())


def test_chunked_posts_are_refused(make_client):
    app, _, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            r = await c.post("/login", content=b"password=x", headers={"transfer-encoding": "chunked"})
            assert r.status_code == 411

    run(go())


def test_secure_cookie_uses_host_prefix(make_client):
    app, _, _ = make_client(COOKIE_SECURE="yes", HSTS="yes")

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            r = await login(c)
            assert r.headers["set-cookie"].startswith("__Host-wl_session=")
            assert "Secure" in r.headers["set-cookie"]
            assert r.headers["strict-transport-security"].startswith("max-age=")

    run(go())


# ------------------------------------------------------------------ entries


def test_add_extend_delete_flow_triggers_bunkerweb(make_client, fake_bw):
    app, store, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            page = await c.get("/", headers=PROXY_HEADERS)
            assert "not on the whitelist yet" in page.text
            token = csrf_of(page.text)

            r = await c.post(
                "/entries",
                data={"network": "203.0.113.42", "label": "Jake", "duration": "7", "_csrf": token},
                headers=PROXY_HEADERS,
            )
            assert r.status_code == 303
            page = await c.get("/", headers=PROXY_HEADERS)
            assert "203.0.113.42 is allowed until" in page.text
            assert "on the whitelist until" in page.text
            entry = store.find("203.0.113.42")
            assert entry and entry.label == "Jake" and entry.created_by == "203.0.113.42"
            assert abs((entry.expires_at - datetime.now(UTC)) - timedelta(days=7)) < timedelta(minutes=1)
            assert (
                "DELETE",
                "/cache/global/whitelist/whitelist-download/" + cache_file_name("http://whitelister:8080/ips.txt"),
            ) in fake_bw.calls

            # extend by 14 days from the current end
            r = await c.post(f"/entries/{entry.id}/extend", data={"duration": "14", "_csrf": token})
            assert r.status_code == 303
            updated = store.get(entry.id)
            assert abs((updated.expires_at - entry.expires_at) - timedelta(days=14)) < timedelta(seconds=1)

            # forever
            r = await c.post(f"/entries/{entry.id}/extend", data={"duration": "forever", "_csrf": token})
            assert store.get(entry.id).expires_at is None
            page = await c.get("/")
            assert "∞ forever" in page.text

            # until a date
            r = await c.post(f"/entries/{entry.id}/extend", data={"duration": "date", "until": "2030-01-01", "_csrf": token})
            assert store.get(entry.id).expires_at == datetime(2030, 1, 2, tzinfo=UTC)

            # the list BunkerWeb fetches
            r = await c.get("/ips.txt")
            assert r.status_code == 200 and r.text == "# bunkerweb-whitelister\n203.0.113.42\n"

            r = await c.post(f"/entries/{entry.id}/delete", data={"_csrf": token})
            assert r.status_code == 303 and store.get(entry.id) is None
            r = await c.get("/ips.txt")
            assert r.text == "# bunkerweb-whitelister\n"

    run(go())


def test_add_validation_errors_are_shown(make_client):
    app, store, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            for data, text in [
                ({"network": "nope", "duration": "7"}, "not a valid IP"),
                ({"network": "0.0.0.0/0", "duration": "7"}, "/16 or smaller"),
                ({"network": "1.2.3.4", "duration": ""}, "Pick how long"),
                ({"network": "1.2.3.4", "duration": "date", "until": "2001-01-01"}, "must be in the future"),
                ({"network": "1.2.3.4", "duration": "7", "label": "x" * 70}, "limited to 64"),
            ]:
                r = await c.post("/entries", data={**data, "_csrf": token})
                assert r.status_code == 303
                page = await c.get("/")
                assert text in page.text, text
            assert store.count() == 0

    run(go())


def test_csrf_and_cross_site_posts_are_rejected(make_client):
    app, store, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            r = await c.post("/entries", data={"network": "1.2.3.4", "duration": "7", "_csrf": "0" * 64})
            assert r.status_code == 303 and store.count() == 0
            r = await c.post(
                "/entries",
                data={"network": "1.2.3.4", "duration": "7", "_csrf": token},
                headers={"sec-fetch-site": "cross-site"},
            )
            assert store.count() == 0
            r = await c.post(
                "/entries",
                data={"network": "1.2.3.4", "duration": "7", "_csrf": token},
                headers={"origin": "https://evil.example"},
            )
            assert store.count() == 0
            # without a session at all
            async with await _client(app) as anon:
                r = await anon.post("/entries", data={"network": "1.2.3.4", "duration": "7", "_csrf": token})
                assert r.status_code == 303 and r.headers["location"] == "/login"
            assert store.count() == 0

    run(go())


def test_sync_failure_is_reported_and_retried(make_client, fake_bw):
    app, store, _ = make_client()
    fake_bw.fail = True

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            await c.post("/entries", data={"network": "1.2.3.4", "duration": "7", "_csrf": token})
            page = await c.get("/")
            assert "could not be told to refresh" in page.text
            assert 'data-state="error"' in page.text
            assert store.count() == 1  # saved locally regardless
            fake_bw.fail = False
            await app.state.client.trigger_refresh()
            page = await c.get("/")
            assert 'data-state="ok"' in page.text

    run(go())


def test_first_run_without_cache_schedules_the_job(make_client, fake_bw):
    app, _, _ = make_client()
    fake_bw.cache_exists = False

    async def go():
        async with app.router.lifespan_context(app):
            await app.state.client.trigger_refresh()
        assert ("POST", "/jobs/run") in fake_bw.calls

    run(go())


# ------------------------------------------------------------------ the plain list


def test_ips_txt_only_for_direct_requests_from_allowed_networks(make_client):
    app, _, _ = make_client(LIST_ALLOWED_NETWORKS="10.0.0.0/8")

    async def go():
        async with app.router.lifespan_context(app):
            async with await _client(app, peer="10.0.0.3") as c:
                assert (await c.get("/ips.txt")).status_code == 200
                # came through a proxy -> never, even from an allowed peer
                assert (await c.get("/ips.txt", headers={"x-forwarded-for": "10.0.0.4"})).status_code == 403
                assert (await c.get("/ips.txt", headers={"forwarded": "for=10.0.0.4"})).status_code == 403
            async with await _client(app, peer="203.0.113.9") as outsider:
                assert (await outsider.get("/ips.txt")).status_code == 403

    run(go())


def test_ips_txt_token(make_client):
    app, _, _ = make_client(LIST_TOKEN="s3cret-token")

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            assert (await c.get("/ips.txt")).status_code == 403
            assert (await c.get("/ips.txt?token=wrong")).status_code == 403
            assert (await c.get("/ips.txt?token=s3cret-token")).status_code == 200

    run(go())


def test_expired_entries_leave_the_list_and_purge(make_client):
    app, store, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            now = datetime.now(UTC)
            store.upsert("198.51.100.7", "old", now - timedelta(seconds=1), now, "")
            store.upsert("198.51.100.8", "new", now + timedelta(days=1), now, "")
            r = await c.get("/ips.txt")
            assert r.text == "# bunkerweb-whitelister\n198.51.100.8\n"
            await login(c)
            page = await c.get("/")
            assert "expired on" in page.text
            assert store.purge_expired(datetime.now(UTC))[0].network == "198.51.100.7"

    run(go())


def test_german_translation(make_client):
    app, _, _ = make_client(WHITELISTER_LANG="de")

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            r = await c.get("/login")
            assert "Du kommst gerade von" in r.text and 'lang="de"' in r.text

    run(go())


def test_oversized_bodies_are_rejected(make_client):
    app, _, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            r = await c.post("/login", content=b"password=" + b"a" * 20000, headers={"content-type": "application/x-www-form-urlencoded"})
            assert r.status_code == 413

    run(go())


def test_healthz_and_hidden_docs(make_client):
    app, _, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            health = (await c.get("/healthz")).json()
            assert health == {"status": "ok"}
            assert (await c.get("/docs")).status_code == 404
            assert (await c.get("/openapi.json")).status_code == 404

    run(go())


# ------------------------------------------------------------------ audit regressions


def test_extend_reapplies_current_policy(env, fake_bw, tmp_path):
    from whitelister.app import create_app
    from whitelister.bunkerweb import BunkerWebClient
    from whitelister.entries import EntryStore

    def build(**overrides):
        env(**overrides)
        settings = load_settings()
        store = EntryStore(tmp_path / "db.sqlite3")  # file-backed: the second app reopens the same rows
        bw = BunkerWebClient(settings)
        bw._client = httpx.AsyncClient(transport=httpx.MockTransport(fake_bw.handler), base_url=settings.bw_api_url or "http://x")
        return create_app(settings, store=store, client=bw), store

    app, store = build(ALLOW_PRIVATE="yes", MIN_PREFIX_V4="8")

    async def seed():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            await c.post("/entries", data={"network": "10.0.0.0/8", "duration": "7", "_csrf": token})
            return store.find("10.0.0.0/8")

    entry = run(seed())
    assert entry is not None

    app2, store2 = build(ALLOW_PRIVATE="no", MIN_PREFIX_V4="16")  # same rows, tightened policy

    async def go():
        async with app2.router.lifespan_context(app2), await _client(app2) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            for data in ({"duration": "14"}, {"duration": "forever"}):
                r = await c.post(f"/entries/{entry.id}/extend", data={**data, "_csrf": token})
                assert r.status_code == 303
                assert "/16 or smaller" in (await c.get("/")).text
                assert store2.get(entry.id).expires_at == entry.expires_at

    run(go())


def test_scope_id_cannot_smuggle_lines_into_the_list(make_client):
    app, store, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            token = csrf_of((await c.get("/")).text)
            r = await c.post("/entries", data={"network": "2a00::1%x\n127.0.0.1", "duration": "7", "_csrf": token})
            assert r.status_code == 303 and store.count() == 0
            # a legacy row written before the parser fix never contributes more than one line
            store.upsert("2a00::1%x\n127.0.0.1", "legacy", None, datetime.now(UTC), "")
            store.upsert("203.0.113.5", "ok", None, datetime.now(UTC), "")
            assert (await c.get("/ips.txt")).text == "# bunkerweb-whitelister\n203.0.113.5\n"

    run(go())


def test_syncer_survives_a_store_error_and_healthz_reflects_liveness(make_client):
    app, store, _ = make_client()

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            syncer = app.state.syncer
            calls = {"n": 0}
            original = store.expired_between

            def boom(*a, **k):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError("database is locked")
                return original(*a, **k)

            store.expired_between = boom
            syncer.request_refresh()
            await asyncio.sleep(0.2)
            assert syncer.alive()
            assert (await c.get("/healthz")).status_code == 200
            syncer.request_refresh()
            await asyncio.sleep(0.2)
            assert calls["n"] >= 2 and syncer.alive()
            # a dead loop is visible to the container healthcheck
            await syncer.stop()
            assert (await c.get("/healthz")).status_code == 503

    run(go())


def test_persistent_cache_miss_is_reported_as_error(make_client, fake_bw):
    app, _, _ = make_client()
    fake_bw.cache_exists = False

    async def go():
        async with app.router.lifespan_context(app):
            client = app.state.client
            await client.trigger_refresh()  # first miss: the job is scheduled, counts as success
            assert client.status.ok
            with pytest.raises(RuntimeError, match="WHITELIST_URL"):
                await client.trigger_refresh()  # still missing after a job ran: a name mismatch
            assert "WHITELIST_URL" in (client.status.last_error or "")
            fake_bw.cache_exists = True
            await client.trigger_refresh()
            assert client.status.ok and client.status.misses == 0

    run(go())


def test_footer_never_shows_the_list_token(make_client):
    app, _, _ = make_client(LIST_TOKEN="s3cret-token", WHITELIST_URL="http://whitelister:8080/ips.txt?token=s3cret-token")

    async def go():
        async with app.router.lifespan_context(app), await _client(app) as c:
            await login(c)
            page = (await c.get("/")).text
            assert "s3cret-token" not in page and "http://whitelister:8080/ips.txt" in page

    run(go())


def test_placeholder_secrets_are_refused(env):
    env(WHITELISTER_PASSWORD="change-me-to-at-least-12-characters")
    with pytest.raises(ConfigError):
        load_settings()
    env(LIST_TOKEN="change-me-list-token")
    with pytest.raises(ConfigError):
        load_settings()
    env(LIST_TOKEN_FILE=None)


def test_empty_list_token_file_means_no_token(env, tmp_path):
    empty = tmp_path / "empty"
    empty.write_text("\n")
    env(LIST_TOKEN_FILE=str(empty))
    assert load_settings().list_token is None


# --- BunkerWeb API authentication (issue: non-admin ACL users got HTTP 401) -------------------


def test_acl_user_exchanges_credentials_for_a_biscuit_token_once(make_client, fake_bw):
    """Non-admin users cannot use Basic on protected routes: the client must obtain a token."""
    fake_bw.require_token = True
    app, _store, settings = make_client()
    client = app.state.client

    async def run():
        await client.trigger_refresh()
        await client.trigger_refresh()

    asyncio.run(run())
    assert client.status.ok
    cache_path = "/cache/global/whitelist/whitelist-download/" + cache_file_name(settings.whitelist_url)
    assert [p for _, p in fake_bw.calls] == ["/auth", cache_path, cache_path]
    assert fake_bw.auth_headers[1:] == ["Bearer biscuit-1", "Bearer biscuit-1"]


def test_expired_token_is_renewed_once_and_the_call_retried(make_client, fake_bw):
    fake_bw.require_token = True
    app, _store, settings = make_client()
    client = app.state.client
    asyncio.run(client.trigger_refresh())
    fake_bw.expire_tokens()
    asyncio.run(client.trigger_refresh())
    assert client.status.ok
    assert fake_bw.issued == ["biscuit-1", "biscuit-2"]
    # the refused call, the re-auth, then the retry with the new token
    assert [p for _, p in fake_bw.calls][-3:] == [
        "/cache/global/whitelist/whitelist-download/" + cache_file_name(settings.whitelist_url),
        "/auth",
        "/cache/global/whitelist/whitelist-download/" + cache_file_name(settings.whitelist_url),
    ]
    assert fake_bw.auth_headers[-1] == "Bearer biscuit-2"


def test_wrong_api_credentials_are_reported_without_retry_storm(make_client, fake_bw):
    fake_bw.require_token = True
    app, _store, _settings = make_client(BW_API_PASSWORD="not-the-password")
    client = app.state.client
    with pytest.raises(RuntimeError, match="authentication rejected"):
        asyncio.run(client.trigger_refresh())
    assert client.status.last_error.startswith("authentication rejected")
    assert [p for _, p in fake_bw.calls] == ["/auth"]


def test_token_refused_twice_is_an_error_not_a_loop(make_client, fake_bw):
    fake_bw.require_token = True
    app, _store, _settings = make_client()
    client = app.state.client
    fake_bw.valid_tokens = set()  # the API never accepts what it issues (e.g. CHECK_PRIVATE_IP mismatch)
    original = fake_bw.handler

    def handler(request):
        resp = original(request)
        fake_bw.valid_tokens.clear()
        return resp

    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://bw-api:8888")
    with pytest.raises(RuntimeError, match="HTTP 401"):
        asyncio.run(client.trigger_refresh())
    assert [p for _, p in fake_bw.calls].count("/auth") == 2


def test_static_admin_token_skips_the_auth_endpoint(make_client, fake_bw):
    fake_bw.require_token = True
    fake_bw.valid_tokens.add("break-glass")
    app, _store, _settings = make_client(BW_API_TOKEN="break-glass", BW_API_USERNAME=None, BW_API_PASSWORD=None)
    client = app.state.client
    asyncio.run(client.trigger_refresh())
    assert client.status.ok
    assert "/auth" not in [p for _, p in fake_bw.calls]
    assert fake_bw.auth_headers == ["Bearer break-glass"]


def test_forbidden_names_the_missing_permissions(make_client, fake_bw):
    app, _store, _settings = make_client(BW_API_TOKEN="read-only-token", BW_API_USERNAME=None, BW_API_PASSWORD=None)
    client = app.state.client
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403)), base_url="http://bw-api:8888")
    with pytest.raises(RuntimeError, match="cache_read, cache_delete or job_run"):
        asyncio.run(client.trigger_refresh())
