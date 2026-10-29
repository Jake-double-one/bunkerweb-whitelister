from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from whitelister.app import create_app
from whitelister.bunkerweb import BunkerWebClient
from whitelister.config import load_settings
from whitelister.entries import EntryStore

PASSWORD = "correct horse battery staple"


class FakeBunkerWeb:
    """Records calls to the BunkerWeb API and answers like the real one.

    With ``require_token`` it behaves like bw-api for a non-admin ACL user: protected routes need a
    Biscuit token obtained at ``POST /auth`` with Basic credentials; Basic on the routes is a 401.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.cache_exists = True
        self.fail = False
        self.require_token = False
        self.credentials = ("admin", "secret")
        self.issued: list[str] = []
        self.valid_tokens: set[str] = set()
        self.auth_headers: list[str | None] = []

    def expire_tokens(self) -> None:
        self.valid_tokens.clear()

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        self.auth_headers.append(request.headers.get("Authorization"))
        if self.fail:
            raise httpx.ConnectError("boom", request=request)
        if request.method == "POST" and request.url.path == "/auth":
            expected = "Basic " + base64.b64encode(":".join(self.credentials).encode()).decode()
            if request.headers.get("Authorization") != expected:
                return httpx.Response(401, json={"detail": "Invalid credentials"})
            token = f"biscuit-{len(self.issued) + 1}"
            self.issued.append(token)
            self.valid_tokens.add(token)
            return httpx.Response(200, json={"token": token, "token_type": "bearer"})
        if self.require_token:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth.removeprefix("Bearer ") not in self.valid_tokens:
                return httpx.Response(401, json={"detail": "Not authenticated"})
        if request.url.path == "/ping":
            return httpx.Response(200, json={"status": "ok"})
        if request.method == "DELETE" and request.url.path.startswith("/cache/global/whitelist/whitelist-download/"):
            if self.cache_exists:
                return httpx.Response(200, json={"status": "success", "deleted": 1})
            return httpx.Response(404, json={"status": "error", "message": "Cache file not found"})
        if request.method == "POST" and request.url.path == "/jobs/run":
            body = json.loads(request.content)
            assert body["jobs"][0]["plugin"] == "whitelist"
            return httpx.Response(202, json={"status": "success"})
        return httpx.Response(404)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Callable[..., None]:
    base = {
        "WHITELISTER_PASSWORD": PASSWORD,
        "SESSION_SECRET": "x" * 40,
        "DATA_DIR": str(tmp_path),
        "COOKIE_SECURE": "no",
        "TRUSTED_PROXIES": "10.0.0.0/8",
        "BW_API_URL": "http://bw-api:8888",
        "BW_API_USERNAME": "admin",
        "BW_API_PASSWORD": "secret",
        "WHITELIST_URL": "http://whitelister:8080/ips.txt",
        "SYNC_DEBOUNCE_SECONDS": "0",
        "TZ": "UTC",
    }
    for key in list(base):
        monkeypatch.delenv(key, raising=False)

    def apply(**overrides: str | None) -> None:
        for key, value in {**base, **overrides}.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)

    apply()
    return apply


@pytest.fixture
def fake_bw() -> FakeBunkerWeb:
    return FakeBunkerWeb()


@pytest.fixture
def make_client(env, fake_bw: FakeBunkerWeb):
    """Builds the app (after optional env overrides) and returns a test client plus the store."""

    created: list[httpx.AsyncClient] = []

    def factory(**overrides: str | None):
        env(**overrides)
        settings = load_settings()
        store = EntryStore(":memory:")
        bw = BunkerWebClient(settings)
        bw._client = httpx.AsyncClient(transport=httpx.MockTransport(fake_bw.handler), base_url=settings.bw_api_url or "http://x")
        app = create_app(settings, store=store, client=bw)
        return app, store, settings

    yield factory
    for c in created:
        asyncio.run(c.aclose())


def login(client: httpx.AsyncClient, password: str = PASSWORD, headers: dict | None = None):
    return client.post("/login", data={"password": password}, headers=headers or {})
