"""The web application: login, the whitelist page and the plain list for BunkerWeb."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__
from .bunkerweb import BunkerWebClient, Syncer
from .config import Settings
from .entries import (
    Entry,
    EntryStore,
    ValidationError,
    expiry_from_date,
    expiry_from_days,
    network_text,
    normalize_label,
    parse_network,
    render_list,
)
from .i18n import Translator
from .security import (
    LoginThrottle,
    PasswordChecker,
    Session,
    SessionCodec,
    has_forwarding_headers,
    in_networks,
    parse_ip,
    resolve_client_ip,
    throttle_key,
)

log = logging.getLogger("whitelister")
audit = logging.getLogger("whitelister.audit")

BASE_DIR = Path(__file__).parent
MAX_BODY = 16 * 1024
SKINS = ("dark", "amoled", "sunset", "light", "mint", "mango")
DUE_SOON = timedelta(days=3)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, hsts: bool) -> None:
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY:
            return PlainTextResponse("request too large", status_code=413)
        if request.method in ("POST", "PUT", "PATCH") and "chunked" in request.headers.get("transfer-encoding", "").lower():
            return PlainTextResponse("length required", status_code=411)
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce  # the page's one inline <style> (entry rails) carries it
        response = await call_next(request)
        h = response.headers
        h["Content-Security-Policy"] = (
            f"default-src 'none'; script-src 'self'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; "
            "font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        )
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        # "same-origin", not "no-referrer": Chromium sends "Origin: null" on form posts under no-referrer,
        # which the same-origin check below would (rightly) refuse.
        h["Referrer-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if not request.url.path.startswith("/static/"):
            h["Cache-Control"] = "no-store"
        if self.hsts:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def create_app(settings: Settings, store: EntryStore | None = None, client: BunkerWebClient | None = None) -> FastAPI:
    t = Translator(settings.language)
    tz = _timezone()
    store = store or EntryStore(settings.data_dir / "whitelist.sqlite3")
    client = client or BunkerWebClient(settings)
    syncer = Syncer(client, store, settings)
    codec = SessionCodec(settings.session_secret, settings.session_hours * 3600)
    flash_codec = URLSafeTimedSerializer(settings.session_secret, salt="whitelister.flash")
    checker = PasswordChecker(settings.password, settings.password_hash)
    throttle = LoginThrottle(settings.login_max_failures, settings.login_lock_seconds)
    hash_slots = asyncio.Semaphore(2)  # password checks run in a thread, at most two at a time
    cookie_name = "__Host-wl_session" if settings.cookie_secure else "wl_session"
    flash_cookie = "__Host-wl_flash" if settings.cookie_secure else "wl_flash"

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if settings.generated_secret:
            log.warning("SESSION_SECRET not set: a random one was generated under %s", settings.data_dir)
        if not settings.trusted_proxies:
            log.warning("TRUSTED_PROXIES is empty: forwarding headers are ignored, the TCP peer counts as the client")
        if not settings.cookie_secure:
            log.warning("COOKIE_SECURE=no: only use this on plain-HTTP test setups")
        log.info("bunkerweb-whitelister %s listening, language=%s, api=%s", __version__, t.language, "on" if client.enabled else "off")
        syncer.request_refresh()
        await syncer.start()
        try:
            yield
        finally:
            await syncer.stop()
            await client.aclose()
            store.close()

    app = FastAPI(title="bunkerweb-whitelister", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts)
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    app.state.settings = settings
    app.state.store = store
    app.state.client = client
    app.state.syncer = syncer
    app.state.throttle = throttle

    env = Environment(
        loader=FileSystemLoader(BASE_DIR / "templates"), autoescape=select_autoescape(default=True), undefined=StrictUndefined
    )
    templates = Jinja2Templates(env=env)
    templates.env.globals.update(t=t, version=__version__, skins=SKINS, lang=t.language, default_skin=settings.default_skin)
    templates.env.filters["dt"] = lambda value: _fmt(value, tz, t("date.format"))
    templates.env.filters["day"] = lambda value: _fmt(value, tz, t("date.format_day"))

    # ------------------------------------------------------------ helpers

    def client_ip(request: Request) -> tuple[str | None, bool]:
        peer = request.client.host if request.client else None
        ip, via_proxy = resolve_client_ip(peer, _joined_headers(request), settings.trusted_proxies, settings.client_ip_header)
        return (str(ip) if ip else None), via_proxy

    def current_session(request: Request) -> Session | None:
        session = codec.decode(request.cookies.get(cookie_name))
        if session is not None and not store.session_valid(session.sid, datetime.now(UTC)):
            return None
        return session

    def set_session_cookie(response: Response, session: Session | None) -> None:
        if session is None:
            response.delete_cookie(cookie_name, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
            return
        response.set_cookie(
            cookie_name,
            codec.encode(session),
            max_age=codec.max_age,
            path="/",
            secure=settings.cookie_secure,
            httponly=True,
            samesite="strict",
        )

    def redirect_with_flash(url: str, kind: str, text: str) -> RedirectResponse:
        response = RedirectResponse(url, status_code=303)
        response.set_cookie(
            flash_cookie,
            flash_codec.dumps({"k": kind, "m": text}),
            max_age=60,
            path="/",
            secure=settings.cookie_secure,
            httponly=True,
            samesite="strict",
        )
        return response

    def pop_flash(request: Request, response: Response) -> dict[str, str] | None:
        raw = request.cookies.get(flash_cookie)
        if not raw:
            return None
        response.delete_cookie(flash_cookie, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
        try:
            data = flash_codec.loads(raw, max_age=60)
        except BadSignature:
            return None
        if isinstance(data, dict) and isinstance(data.get("m"), str):
            return {"kind": str(data.get("k", "info")), "text": data["m"]}
        return None

    def same_origin(request: Request) -> bool:
        """Reject cross-site form posts even if a cookie slipped through."""
        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site and fetch_site not in ("same-origin", "none"):
            return False
        origin = request.headers.get("origin")
        host = request.headers.get("host")
        if origin and host:
            origin_host = origin.split("://", 1)[-1].split("/", 1)[0]
            if origin_host.lower() != host.lower():
                return False
        return True

    def require_post(request: Request, csrf: str | None) -> Session | Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        if not same_origin(request) or not codec.check_csrf(session, csrf):
            return redirect_with_flash("/", "alert", t("error.csrf"))
        return session

    def audit_event(request: Request, event: str, **data: Any) -> None:
        ip, _ = client_ip(request)
        audit.info(json.dumps({"event": event, "client": ip, "ts": datetime.now(UTC).isoformat(timespec="seconds"), **data}))

    async def refresh_after_change(request: Request) -> str | None:
        """Tell BunkerWeb now; on failure return the error text (the syncer retries)."""
        if not client.enabled:
            return None
        try:
            await client.trigger_refresh()
        except Exception:
            syncer.request_refresh()
            return client.status.last_error or "error"
        return None

    def api_state() -> tuple[str, str]:
        if not client.enabled:
            return "off", t("header.api_off")
        s = client.status
        if s.last_error:
            return "error", t("header.api_error", error=s.last_error[:24])
        if s.pending or s.last_success is None:
            return "pending", t("header.api_pending")
        return "ok", t("header.api_ok")

    def view_entries(now: datetime) -> list[dict[str, Any]]:
        rows = []
        for e in store.list():
            rows.append(
                {
                    "entry": e,
                    "forever": e.expires_at is None,
                    "expired": e.is_expired(now),
                    "due_soon": e.expires_at is not None and now < e.expires_at <= now + DUE_SOON,
                    "remaining_text": _remaining_text(t, e, now),
                    "rail": _rail_percent(e, now),
                    "extend_presets": [{"days": d, "new_end": _extend_from(e, now) + timedelta(days=d)} for d in settings.duration_presets],
                }
            )
        return rows

    def listed_entry(ip_text: str | None, now: datetime) -> Entry | None:
        if not ip_text:
            return None
        ip = parse_ip(ip_text)
        if ip is None:
            return None
        for e in store.list():
            if e.is_expired(now):
                continue
            try:
                net = ipaddress.ip_network(e.network, strict=False)
            except ValueError:
                continue
            if net.version == ip.version and ip in net:
                return e
        return None

    def parse_duration(duration: str | None, until: str | None, now: datetime) -> datetime | None:
        if duration == "forever":
            return None
        if duration == "date":
            return expiry_from_date(until or "", now, settings, tz)
        try:
            days = int(duration or "")
        except ValueError as exc:
            raise ValidationError("error.duration_missing") from exc
        return expiry_from_days(days, now, settings)

    # ------------------------------------------------------------ routes

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/ips.txt", include_in_schema=False)
    async def ips_txt(request: Request) -> Response:
        """The list BunkerWeb downloads. Only for direct requests from allowed networks."""
        peer = parse_ip(request.client.host) if request.client else None
        headers = dict(request.headers)
        token_ok = settings.list_token is None or _const_eq(request.query_params.get("token", ""), settings.list_token)
        if peer is None or has_forwarding_headers(headers) or not in_networks(peer, settings.list_allowed_networks) or not token_ok:
            return PlainTextResponse("forbidden\n", status_code=403)
        text = render_list(store.active_networks(datetime.now(UTC)))
        return PlainTextResponse(text, headers={"Cache-Control": "no-store"})

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    async def login_form(request: Request) -> Response:
        if current_session(request) is not None:
            return RedirectResponse("/", status_code=303)
        ip, _ = client_ip(request)
        return templates.TemplateResponse(request, "login.html", {"client_ip": ip, "error": None, "session_hours": settings.session_hours})

    @app.post("/login", include_in_schema=False)
    async def login(request: Request, password: str = Form(default="")) -> Response:
        if not same_origin(request):
            # a browser-labelled cross-site post is never a real attempt: refuse without counting it
            return PlainTextResponse("forbidden", status_code=403)
        ip, _ = client_ip(request)
        key = throttle_key(parse_ip(ip)) if ip else None
        if key is None:
            audit_event(request, "login.no_client_ip")
            return PlainTextResponse("forbidden", status_code=403)
        wait = throttle.retry_after(key)
        ctx = {"client_ip": ip, "session_hours": settings.session_hours}
        if wait:
            audit_event(request, "login.locked", retry_after=wait)
            return templates.TemplateResponse(request, "login.html", {**ctx, "error": t("login.locked", seconds=wait)}, status_code=429)
        if hash_slots.locked():
            # more password checks in flight than we are willing to spend CPU on
            return templates.TemplateResponse(request, "login.html", {**ctx, "error": t("login.locked", seconds=5)}, status_code=429)
        async with hash_slots:
            ok = await run_in_threadpool(checker.check, password)
        if not ok:
            lock = throttle.record_failure(key)
            audit_event(request, "login.failed", lock_seconds=lock)
            error = t("login.locked", seconds=lock) if lock else t("login.failed")
            return templates.TemplateResponse(request, "login.html", {**ctx, "error": error}, status_code=401)
        throttle.record_success(key)
        audit_event(request, "login.ok")
        session = codec.new()
        store.sessions_purge(datetime.now(UTC))
        store.session_add(session.sid, datetime.now(UTC) + timedelta(seconds=codec.max_age))
        response = RedirectResponse("/", status_code=303)
        set_session_cookie(response, session)
        return response

    @app.post("/logout", include_in_schema=False)
    async def logout(request: Request, csrf_token: str = Form(default="", alias="_csrf")) -> Response:
        session = current_session(request)
        response = RedirectResponse("/login", status_code=303)
        if session is not None and codec.check_csrf(session, csrf_token):
            audit_event(request, "logout")
            store.session_delete(session.sid)
            set_session_cookie(response, None)
        return response

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index(request: Request) -> Response:
        session = current_session(request)
        if session is None:
            return RedirectResponse("/login", status_code=303)
        now = datetime.now(UTC)
        ip, _ = client_ip(request)
        rows = view_entries(now)
        state, state_text = api_state()
        context = {
            "csrf": session.csrf,
            "nonce": request.state.csp_nonce,
            "client_ip": ip,
            "listed": listed_entry(ip, now),
            "entries": rows,
            "now": now,
            "presets": settings.duration_presets,
            "preset_ends": {d: now + timedelta(days=d) for d in settings.duration_presets},
            "default_preset": settings.duration_presets[min(2, len(settings.duration_presets) - 1)],
            "stats": {
                "active": sum(1 for r in rows if not r["expired"]),
                "due_soon": sum(1 for r in rows if r["due_soon"]),
                "forever": sum(1 for r in rows if r["forever"]),
                "expired": sum(1 for r in rows if r["expired"]),
            },
            "api_state": state,
            "api_state_text": state_text,
            "list_url": settings.whitelist_url or "/ips.txt",
            "api_enabled": client.enabled,
            "min_date": now.astimezone(tz).strftime("%Y-%m-%d"),
            "flash": None,
        }
        response = templates.TemplateResponse(request, "index.html", context)
        flash = pop_flash(request, response)
        if flash:
            context["flash"] = flash
            response = templates.TemplateResponse(request, "index.html", context)
            response.delete_cookie(flash_cookie, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
        return response

    @app.post("/entries", include_in_schema=False)
    async def add_entry(
        request: Request,
        network: str = Form(default=""),
        label: str = Form(default=""),
        duration: str = Form(default=""),
        until: str = Form(default=""),
        csrf_token: str = Form(default="", alias="_csrf"),
    ) -> Response:
        session = require_post(request, csrf_token)
        if isinstance(session, Response):
            return session
        now = datetime.now(UTC)
        try:
            net = parse_network(network, settings)
            text = network_text(net)
            clean_label = normalize_label(label)
            expires = parse_duration(duration, until, now)
        except ValidationError as exc:
            return redirect_with_flash("/", "alert", t(exc.key, **exc.params))
        ip, _ = client_ip(request)
        try:
            entry = store.upsert(text, clean_label, expires, now, created_by=ip or "")
        except ValidationError as exc:
            return redirect_with_flash("/", "alert", t(exc.key, **exc.params))
        audit_event(request, "entry.add", network=entry.network, label=entry.label, expires_at=_iso(entry.expires_at))
        sync_error = await refresh_after_change(request)
        if sync_error:
            return redirect_with_flash("/", "alert", t("flash.sync_failed", error=sync_error))
        if entry.expires_at is None:
            return redirect_with_flash("/", "info", t("flash.added_forever", network=entry.network))
        return redirect_with_flash("/", "info", t("flash.added", network=entry.network, until=_fmt(entry.expires_at, tz, t("date.format"))))

    @app.post("/entries/{entry_id}/extend", include_in_schema=False)
    async def extend_entry(
        request: Request,
        entry_id: int,
        duration: str = Form(default=""),
        until: str = Form(default=""),
        csrf_token: str = Form(default="", alias="_csrf"),
    ) -> Response:
        session = require_post(request, csrf_token)
        if isinstance(session, Response):
            return session
        entry = store.get(entry_id)
        if entry is None:
            return redirect_with_flash("/", "alert", t("error.not_found"))
        now = datetime.now(UTC)
        try:
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
        updated = store.set_expiry(entry_id, new_end)
        if updated is None:
            return redirect_with_flash("/", "alert", t("error.not_found"))
        audit_event(request, "entry.extend", network=updated.network, expires_at=_iso(updated.expires_at))
        sync_error = await refresh_after_change(request)
        if sync_error:
            return redirect_with_flash("/", "alert", t("flash.sync_failed", error=sync_error))
        if updated.expires_at is None:
            return redirect_with_flash("/", "info", t("flash.extended_forever", network=updated.network))
        return redirect_with_flash(
            "/", "info", t("flash.extended", network=updated.network, until=_fmt(updated.expires_at, tz, t("date.format")))
        )

    @app.post("/entries/{entry_id}/delete", include_in_schema=False)
    async def delete_entry(request: Request, entry_id: int, csrf_token: str = Form(default="", alias="_csrf")) -> Response:
        session = require_post(request, csrf_token)
        if isinstance(session, Response):
            return session
        entry = store.get(entry_id)
        if entry is None or not store.delete(entry_id):
            return redirect_with_flash("/", "alert", t("error.not_found"))
        audit_event(request, "entry.delete", network=entry.network)
        sync_error = await refresh_after_change(request)
        if sync_error:
            return redirect_with_flash("/", "alert", t("flash.sync_failed", error=sync_error))
        return redirect_with_flash("/", "info", t("flash.removed", network=entry.network))

    return app


# ---------------------------------------------------------------- small helpers


def _joined_headers(request: Request) -> dict[str, str]:
    """Header map where repeated headers are joined with commas (first-wins would let a client-sent duplicate through)."""
    out: dict[str, str] = {}
    for key, value in request.headers.items():
        out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def _timezone() -> ZoneInfo:
    import os

    name = os.environ.get("TZ", "UTC") or "UTC"
    try:
        return ZoneInfo(name)
    except Exception:
        log.warning("TZ=%r is unknown, falling back to UTC", name)
        return ZoneInfo("UTC")


def _fmt(value: datetime | None, tz: ZoneInfo, fmt: str) -> str:
    if value is None:
        return ""
    return value.astimezone(tz).strftime(fmt)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") if value else None


def _const_eq(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _extend_from(entry: Entry, now: datetime) -> datetime:
    """Extensions count from the current end; expired or endless entries count from now."""
    if entry.expires_at is None or entry.expires_at <= now:
        return now
    return entry.expires_at


def _remaining_text(t: Translator, entry: Entry, now: datetime) -> str:
    remaining = entry.remaining(now)
    if remaining is None or remaining.total_seconds() <= 0:
        return ""
    minutes = int(remaining.total_seconds() // 60)
    if minutes >= 60 * 24:
        return t.plural("list.remaining_days", minutes // (60 * 24))
    if minutes >= 60:
        return t.plural("list.remaining_hours", minutes // 60)
    return t("list.remaining_minutes", count=max(minutes, 1))


def _rail_percent(entry: Entry, now: datetime) -> int:
    if entry.expires_at is None or entry.expires_at <= now:
        return 0
    total = (entry.expires_at - entry.created_at).total_seconds()
    left = (entry.expires_at - now).total_seconds()
    if total <= 0:
        return 100
    return max(4, min(100, round(100 * left / total)))


__all__ = ["create_app", "time"]
