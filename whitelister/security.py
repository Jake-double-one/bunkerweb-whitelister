"""Passwords, sessions, CSRF, login throttling and client-IP resolution."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from dataclasses import dataclass

from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import IPNetwork

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# ---------------------------------------------------------------- passwords

PBKDF2_ITERATIONS = 600_000
_DUMMY_HASH: str | None = None


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_raw, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    if not 1_000 <= iterations <= 10_000_000:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


class PasswordChecker:
    """Checks a submitted password in constant-ish time.

    With a plain password both sides are compared with ``compare_digest``.
    With a stored hash the PBKDF2 work is always performed, so a wrong
    password costs the same as a right one.
    """

    def __init__(self, password: str | None, password_hash: str | None) -> None:
        if password_hash:
            self._hash = password_hash
            self._plain = None
        else:
            self._hash = None
            self._plain = (password or "").encode("utf-8")

    def check(self, candidate: str) -> bool:
        if len(candidate) > 1024:
            return False
        if self._hash is not None:
            return verify_password(candidate, self._hash)
        return hmac.compare_digest(candidate.encode("utf-8"), self._plain or b"")


# ---------------------------------------------------------------- sessions


@dataclass(frozen=True)
class Session:
    sid: str
    csrf: str
    issued_at: int


class SessionCodec:
    def __init__(self, secret: bytes, max_age_seconds: int) -> None:
        self._serializer = URLSafeTimedSerializer(secret, salt="whitelister.session")
        self._csrf_key = hashlib.sha256(b"csrf:" + secret).digest()
        self.max_age = max_age_seconds

    def new(self) -> Session:
        sid = secrets.token_urlsafe(32)
        return Session(sid=sid, csrf=self.csrf_for(sid), issued_at=int(time.time()))

    def csrf_for(self, sid: str) -> str:
        return hmac.new(self._csrf_key, sid.encode("ascii"), hashlib.sha256).hexdigest()

    def encode(self, session: Session) -> str:
        return self._serializer.dumps({"sid": session.sid, "iat": session.issued_at})

    def decode(self, value: str | None) -> Session | None:
        if not value or len(value) > 512:
            return None
        try:
            data = self._serializer.loads(value, max_age=self.max_age)
        except BadSignature:
            return None
        sid = data.get("sid") if isinstance(data, dict) else None
        iat = data.get("iat") if isinstance(data, dict) else None
        if not isinstance(sid, str) or not isinstance(iat, int):
            return None
        return Session(sid=sid, csrf=self.csrf_for(sid), issued_at=iat)

    def check_csrf(self, session: Session, token: str | None) -> bool:
        if not token or len(token) > 256:
            return False
        return hmac.compare_digest(session.csrf, token)


# ---------------------------------------------------------------- throttling


def throttle_key(ip: IPAddress | None) -> str | None:
    """IPv4 by address, IPv6 by /64: rotating through a /64 must not buy fresh attempts."""
    if ip is None:
        return None
    if ip.version == 6:
        mapped = ip.ipv4_mapped  # type: ignore[union-attr]
        if mapped is not None:
            return str(mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class LoginThrottle:
    """Per-client lockout: after ``max_failures`` the client waits
    ``lock_seconds``, doubling on every further failure (capped at 1 hour).
    Failures are forgotten after an hour without new ones. A process-wide
    budget (``global_budget`` failures per minute, from all clients
    together) locks the login for everyone for a minute: a distributed
    guessing run then costs attempts, not CPU."""

    MAX_LOCK = 3600
    DECAY = 3600
    MAX_TRACKED = 10_000

    def __init__(self, max_failures: int, lock_seconds: int, global_budget: int = 30) -> None:
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self.global_budget = global_budget
        self._lock = threading.Lock()
        self._state: dict[str, tuple[int, float, float]] = {}  # key -> (failures, locked_until, last_failure)
        self._window_start = 0.0
        self._window_failures = 0
        self._global_until = 0.0

    def retry_after(self, key: str, now: float | None = None) -> int:
        """Seconds the client still has to wait, 0 when allowed."""
        now = now if now is not None else time.time()
        with self._lock:
            until = self._global_until
            _, own_until, _ = self._state.get(key, (0, 0.0, 0.0))
            until = max(until, own_until)
            if until > now:
                return int(until - now) + 1
            return 0

    def record_failure(self, key: str, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        with self._lock:
            if len(self._state) >= self.MAX_TRACKED:
                self._prune(now)
            failures, _, last = self._state.get(key, (0, 0.0, 0.0))
            if now - last > self.DECAY:
                failures = 0
            failures += 1
            lock = 0.0
            if failures >= self.max_failures:
                exponent = failures - self.max_failures
                lock = min(self.lock_seconds * (2**exponent), self.MAX_LOCK)
            self._state[key] = (failures, now + lock, now)

            if now - self._window_start > 60:
                self._window_start, self._window_failures = now, 0
            self._window_failures += 1
            if self._window_failures > self.global_budget:
                self._global_until = max(self._global_until, now + 60)
                lock = max(lock, 60.0)
            return int(lock)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)

    def _prune(self, now: float) -> None:
        for key, (_, until, last) in list(self._state.items()):
            if until <= now and now - last > self.DECAY:
                del self._state[key]
        if len(self._state) >= self.MAX_TRACKED:
            self._state.clear()


# ---------------------------------------------------------------- client IP


def parse_ip(value: str) -> IPAddress | None:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        pass
    # "ip:port" (IPv4) as some proxies send it
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit():
        try:
            return ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return None
    return None


def in_networks(ip: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    for net in networks:
        if ip.version == net.version and ip in net:
            return True
        # IPv4-mapped IPv6 peers (::ffff:10.0.0.1) count as their IPv4 self
        if ip.version == 6 and net.version == 4:
            mapped = ip.ipv4_mapped  # type: ignore[union-attr]
            if mapped is not None and mapped in net:
                return True
    return False


def resolve_client_ip(
    peer: str | None,
    headers: dict[str, str],
    trusted_proxies: tuple[IPNetwork, ...],
    header_name: str = "X-Forwarded-For",
) -> tuple[IPAddress | None, bool]:
    """Return ``(client_ip, via_proxy)``.

    Forwarding headers are honoured only when the TCP peer is a trusted
    proxy. For ``X-Forwarded-For`` the chain is walked from the right and
    the first address that is not a trusted proxy wins. Any other header
    name is taken verbatim (for CDN-style headers such as
    ``CF-Connecting-IP``).
    """
    peer_ip = parse_ip(peer) if peer else None
    if peer_ip is None:
        return None, False
    if not trusted_proxies or not in_networks(peer_ip, trusted_proxies):
        return peer_ip, False

    raw = headers.get(header_name.lower())
    if not raw:
        return peer_ip, False

    if header_name.lower() == "x-forwarded-for":
        hops = [parse_ip(h) for h in raw.split(",")]
        for hop in reversed(hops):
            if hop is None:
                return None, True
            if not in_networks(hop, trusted_proxies):
                return hop, True
        # every hop was a trusted proxy: take the leftmost one
        return (hops[0], True) if hops else (peer_ip, False)

    client = parse_ip(raw)
    return (client, True) if client is not None else (None, True)


def has_forwarding_headers(headers: dict[str, str]) -> bool:
    return any(name in headers for name in ("x-forwarded-for", "forwarded", "x-real-ip", "x-forwarded-host", "x-forwarded-proto"))
