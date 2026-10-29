"""Configuration from environment variables.

Every setting can also be supplied as ``<NAME>_FILE`` pointing to a file
(Docker secrets). The file variant wins over the plain variable.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

PRIVATE_NETWORKS = (
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)


class ConfigError(RuntimeError):
    pass


def _read(name: str, default: str | None = None) -> str | None:
    """Read ``NAME_FILE`` (Docker secret) first, then ``NAME``."""
    file_var = os.environ.get(f"{name}_FILE")
    if file_var:
        try:
            return Path(file_var).read_text(encoding="utf-8").strip()
        except OSError as exc:  # pragma: no cover - depends on the host
            raise ConfigError(f"{name}_FILE: cannot read {file_var}: {exc}") from exc
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip()


def _bool(name: str, default: bool) -> bool:
    raw = _read(name)
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in {"1", "yes", "true", "on"}:
        return True
    if lowered in {"0", "no", "false", "off"}:
        return False
    raise ConfigError(f"{name}: expected yes/no, got {raw!r}")


def _int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = _read(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}: expected an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name}: must be between {minimum} and {maximum}")
    return value


def _networks(name: str, default: tuple[str, ...]) -> tuple[IPNetwork, ...]:
    raw = _read(name)
    items = default if raw is None else tuple(p for p in raw.replace(",", " ").split() if p)
    out: list[IPNetwork] = []
    for item in items:
        try:
            out.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ConfigError(f"{name}: {item!r} is not an IP network") from exc
    return tuple(out)


def _presets(name: str, default: str) -> tuple[int, ...]:
    raw = _read(name, default) or default
    out: list[int] = []
    for part in raw.replace(",", " ").split():
        try:
            days = int(part)
        except ValueError as exc:
            raise ConfigError(f"{name}: {part!r} is not a number of days") from exc
        if not 1 <= days <= 3650:
            raise ConfigError(f"{name}: {days} days is out of range (1-3650)")
        out.append(days)
    if not out:
        raise ConfigError(f"{name}: at least one preset is required")
    return tuple(out)


@dataclass(frozen=True)
class Settings:
    # Who may log in
    password: str | None
    password_hash: str | None
    session_secret: bytes
    session_hours: int
    login_max_failures: int
    login_lock_seconds: int

    # Where requests come from
    trusted_proxies: tuple[IPNetwork, ...]
    client_ip_header: str
    cookie_secure: bool
    hsts: bool

    # Who may fetch the plain list
    list_allowed_networks: tuple[IPNetwork, ...]
    list_token: str | None

    # Entry rules
    duration_presets: tuple[int, ...]
    max_days: int
    expired_retention_days: int
    min_prefix_v4: int
    min_prefix_v6: int
    allow_private: bool

    # BunkerWeb API
    bw_api_url: str | None
    bw_api_username: str | None
    bw_api_password: str | None
    bw_api_token: str | None
    bw_api_verify_tls: bool
    whitelist_url: str | None
    sync_debounce_seconds: int
    sync_timeout_seconds: int

    # Misc
    data_dir: Path
    language: str
    default_skin: str
    listen_host: str
    listen_port: int
    log_level: str
    generated_secret: bool = field(default=False)

    @property
    def api_enabled(self) -> bool:
        return bool(self.bw_api_url)


def load_settings(env_data_dir: str | None = None) -> Settings:
    data_dir = Path(_read("DATA_DIR", env_data_dir or "/data") or "/data")

    password = _read("WHITELISTER_PASSWORD")
    password_hash = _read("WHITELISTER_PASSWORD_HASH")
    if not password and not password_hash:
        raise ConfigError("Set WHITELISTER_PASSWORD or WHITELISTER_PASSWORD_HASH (or the _FILE variants).")
    if password and password_hash:
        raise ConfigError("Set either WHITELISTER_PASSWORD or WHITELISTER_PASSWORD_HASH, not both.")
    if password and len(password) < 12:
        raise ConfigError("WHITELISTER_PASSWORD must be at least 12 characters long.")

    generated = False
    secret_raw = _read("SESSION_SECRET")
    if secret_raw:
        if len(secret_raw) < 32:
            raise ConfigError("SESSION_SECRET must be at least 32 characters long.")
        session_secret = secret_raw.encode("utf-8")
    else:
        session_secret, generated = _load_or_create_secret(data_dir / "session.key")

    bw_api_url = _read("BW_API_URL")
    if bw_api_url:
        bw_api_url = bw_api_url.rstrip("/")
        if not bw_api_url.startswith(("http://", "https://")):
            raise ConfigError("BW_API_URL must start with http:// or https://")
    bw_api_token = _read("BW_API_TOKEN")
    bw_api_username = _read("BW_API_USERNAME")
    bw_api_password = _read("BW_API_PASSWORD")
    if bw_api_url and not bw_api_token and not (bw_api_username and bw_api_password):
        raise ConfigError("BW_API_URL is set: provide BW_API_TOKEN or BW_API_USERNAME and BW_API_PASSWORD.")
    whitelist_url = _read("WHITELIST_URL")
    if bw_api_url and not whitelist_url:
        raise ConfigError("WHITELIST_URL is required when BW_API_URL is set (the URL BunkerWeb fetches the list from).")

    raw_proxies = _read("TRUSTED_PROXIES")
    if raw_proxies is None:
        raise ConfigError(
            "TRUSTED_PROXIES is not set. Name the networks of the reverse proxy (BunkerWeb) whose "
            "X-Forwarded-For may be trusted, or set TRUSTED_PROXIES=none when clients connect directly."
        )
    trusted_proxies = () if raw_proxies.lower() == "none" else _networks("TRUSTED_PROXIES", ())

    language = (_read("WHITELISTER_LANG", "en") or "en").lower()
    skin = (_read("WHITELISTER_SKIN", "auto") or "auto").lower()
    if skin not in {"auto", "dark", "amoled", "sunset", "light", "mint", "mango"}:
        raise ConfigError("WHITELISTER_SKIN must be one of auto, dark, amoled, sunset, light, mint, mango.")

    client_ip_header = (_read("CLIENT_IP_HEADER", "X-Forwarded-For") or "X-Forwarded-For").strip()

    return Settings(
        password=password,
        password_hash=password_hash,
        session_secret=session_secret,
        session_hours=_int("SESSION_HOURS", 12, minimum=1, maximum=24 * 30),
        login_max_failures=_int("LOGIN_MAX_FAILURES", 3, minimum=1, maximum=100),
        login_lock_seconds=_int("LOGIN_LOCK_SECONDS", 30, minimum=1, maximum=3600),
        trusted_proxies=trusted_proxies,
        client_ip_header=client_ip_header,
        cookie_secure=_bool("COOKIE_SECURE", True),
        hsts=_bool("HSTS", False),
        list_allowed_networks=_networks("LIST_ALLOWED_NETWORKS", PRIVATE_NETWORKS),
        list_token=_read("LIST_TOKEN"),
        duration_presets=_presets("DURATION_PRESETS", "1 7 14 30"),
        max_days=_int("MAX_DAYS", 3650, minimum=1, maximum=36500),
        expired_retention_days=_int("EXPIRED_RETENTION_DAYS", 7, minimum=0, maximum=365),
        min_prefix_v4=_int("MIN_PREFIX_V4", 16, minimum=0, maximum=32),
        min_prefix_v6=_int("MIN_PREFIX_V6", 48, minimum=0, maximum=128),
        allow_private=_bool("ALLOW_PRIVATE", True),
        bw_api_url=bw_api_url,
        bw_api_username=bw_api_username,
        bw_api_password=bw_api_password,
        bw_api_token=bw_api_token,
        bw_api_verify_tls=_bool("BW_API_VERIFY_TLS", True),
        whitelist_url=whitelist_url,
        sync_debounce_seconds=_int("SYNC_DEBOUNCE_SECONDS", 3, minimum=0, maximum=300),
        sync_timeout_seconds=_int("SYNC_TIMEOUT_SECONDS", 10, minimum=1, maximum=120),
        data_dir=data_dir,
        language=language,
        default_skin=skin,
        listen_host=_read("LISTEN_HOST", "0.0.0.0") or "0.0.0.0",  # noqa: S104 - a container listens on all interfaces
        listen_port=_int("LISTEN_PORT", 8080, minimum=1, maximum=65535),
        log_level=(_read("LOG_LEVEL", "info") or "info").lower(),
        generated_secret=generated,
    )


def _load_or_create_secret(path: Path) -> tuple[bytes, bool]:
    try:
        existing = path.read_bytes().strip()
        if len(existing) >= 32:
            return existing, False
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    secret = secrets.token_urlsafe(48).encode("ascii")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(secret)
    except OSError as exc:
        print(f"warning: cannot persist session secret at {path}: {exc}; sessions end on restart", file=sys.stderr)
    return secret, True
