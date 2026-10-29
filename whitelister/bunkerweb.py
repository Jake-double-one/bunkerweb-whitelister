"""Client for the BunkerWeb API: tells the scheduler to re-download the list.

BunkerWeb's ``whitelist-download`` job keeps every downloaded URL in its
cache under ``sha1(url) + ".list"`` and skips the download when that file is
younger than one hour. Deleting that cache file through the API marks the
whitelist plugin as changed, so the scheduler re-runs the job, regenerates
the configuration and reloads the instances. When the file does not exist
yet (first run) the job is scheduled directly instead.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass

import httpx

from .config import Settings

log = logging.getLogger("whitelister.bunkerweb")


@dataclass
class SyncStatus:
    last_attempt: float | None = None
    last_success: float | None = None
    last_error: str | None = None
    pending: bool = False

    @property
    def ok(self) -> bool:
        return self.last_error is None and self.last_success is not None


def cache_file_name(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest() + ".list"  # noqa: S324 - BunkerWeb's own naming


class BunkerWebClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.status = SyncStatus()
        headers = {"User-Agent": "bunkerweb-whitelister", "Accept": "application/json"}
        auth: httpx.Auth | None = None
        if settings.bw_api_token:
            headers["Authorization"] = f"Bearer {settings.bw_api_token}"
        elif settings.bw_api_username and settings.bw_api_password:
            auth = httpx.BasicAuth(settings.bw_api_username, settings.bw_api_password)
        self._client = httpx.AsyncClient(
            base_url=settings.bw_api_url or "http://invalid",
            headers=headers,
            auth=auth,
            timeout=settings.sync_timeout_seconds,
            verify=settings.bw_api_verify_tls,
            follow_redirects=False,
        )
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def enabled(self) -> bool:
        return self.settings.api_enabled

    async def ping(self) -> bool:
        if not self.enabled:
            return False
        try:
            resp = await self._client.get("/ping")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def trigger_refresh(self) -> None:
        """Make the scheduler fetch the list again. Raises on failure."""
        if not self.enabled or not self.settings.whitelist_url:
            return
        async with self._lock:
            self.status.last_attempt = time.time()
            try:
                await self._trigger()
            except Exception as exc:
                self.status.last_error = _describe(exc)
                log.warning("BunkerWeb refresh failed: %s", self.status.last_error)
                raise
            self.status.last_success = time.time()
            self.status.last_error = None
            self.status.pending = False
            log.info("BunkerWeb whitelist refresh triggered")

    async def _trigger(self) -> None:
        name = cache_file_name(self.settings.whitelist_url or "")
        resp = await self._client.delete(f"/cache/global/whitelist/whitelist-download/{name}")
        if resp.status_code in (200, 207):
            return
        if resp.status_code == 404:
            # no cached copy yet: schedule the job directly
            resp = await self._client.post("/jobs/run", json={"jobs": [{"plugin": "whitelist", "name": "whitelist-download"}]})
            if resp.status_code in (200, 202):
                return
        raise RuntimeError(f"HTTP {resp.status_code} from BunkerWeb API")


def _describe(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "connection refused"
    if isinstance(exc, httpx.HTTPError):
        return exc.__class__.__name__
    return str(exc) or exc.__class__.__name__


class Syncer:
    """Debounces refresh requests and purges expired entries in the background."""

    def __init__(self, client: BunkerWebClient, store, settings: Settings, interval: float = 30.0) -> None:
        self.client = client
        self.store = store
        self.settings = settings
        self.interval = interval
        self._event = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._stopping = False

    def request_refresh(self) -> None:
        self.client.status.pending = True
        self._event.set()

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="whitelister-sync")

    async def stop(self) -> None:
        self._stopping = True
        self._event.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: S110 - shutting down, nothing to report
                pass

    async def _run(self) -> None:
        from datetime import UTC, datetime, timedelta

        last_tick = datetime.now(UTC)
        while not self._stopping:
            try:
                await asyncio.wait_for(self._event.wait(), timeout=self.interval)
            except TimeoutError:
                pass
            if self._stopping:
                return
            self._event.clear()
            now = datetime.now(UTC)
            for entry in self.store.expired_between(last_tick, now):
                log.info("entry expired: %s (%s)", entry.network, entry.label)
                self.client.status.pending = True
            last_tick = now
            for entry in self.store.purge_expired(now - timedelta(days=self.settings.expired_retention_days)):
                log.info("expired entry removed: %s (%s)", entry.network, entry.label)
            if self.client.status.pending or self.client.status.last_error:
                if self.settings.sync_debounce_seconds:
                    await asyncio.sleep(self.settings.sync_debounce_seconds)
                try:
                    await self.client.trigger_refresh()
                except Exception:  # noqa: S110 - already logged by the client; stays pending for the next tick
                    pass
