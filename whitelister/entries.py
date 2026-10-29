"""Whitelist entries: validation and SQLite storage."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import threading
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

from .config import IPNetwork, Settings

MAX_LABEL = 64
_MAX_ENTRIES = 5000


class ValidationError(ValueError):
    def __init__(self, key: str, **params: object) -> None:
        super().__init__(key)
        self.key = key
        self.params = params


def normalize_label(raw: str | None) -> str:
    text = unicodedata.normalize("NFC", (raw or "").strip())
    text = re.sub(r"\s+", " ", text)
    text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")  # drop control chars
    if len(text) > MAX_LABEL:
        raise ValidationError("error.label_too_long", max=MAX_LABEL)
    return text


def parse_network(raw: str, settings: Settings) -> IPNetwork:
    """Parse an address or CIDR. Returns a normalized network object."""
    text = (raw or "").strip()
    if not text or len(text) > 64:
        raise ValidationError("error.ip_invalid")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValidationError("error.ip_invalid") from exc
    min_prefix = settings.min_prefix_v4 if net.version == 4 else settings.min_prefix_v6
    if net.prefixlen < min_prefix:
        raise ValidationError("error.prefix_too_wide", min=min_prefix)
    if net.is_multicast or net.is_unspecified or net.is_loopback or net.is_reserved:
        raise ValidationError("error.ip_not_routable")
    if net.is_private and not settings.allow_private:
        raise ValidationError("error.ip_private")
    return net


def network_text(net: IPNetwork) -> str:
    """The form BunkerWeb expects: a bare address for single hosts, CIDR otherwise."""
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


def expiry_from_days(days: int, now: datetime, settings: Settings) -> datetime:
    if not 1 <= days <= settings.max_days:
        raise ValidationError("error.days_out_of_range", max=settings.max_days)
    return now + timedelta(days=days)


def expiry_from_date(raw: str, now: datetime, settings: Settings, tz: tzinfo = UTC) -> datetime:
    """``YYYY-MM-DD`` from a date input: the entry expires at the end of that day in ``tz``."""
    try:
        day = datetime.strptime((raw or "").strip(), "%Y-%m-%d").replace(tzinfo=tz)
    except ValueError as exc:
        raise ValidationError("error.date_invalid") from exc
    expires = (day + timedelta(days=1)).astimezone(UTC)
    if expires <= now:
        raise ValidationError("error.date_in_past")
    if expires > now + timedelta(days=settings.max_days):
        raise ValidationError("error.days_out_of_range", max=settings.max_days)
    return expires


@dataclass(frozen=True)
class Entry:
    id: int
    network: str
    label: str
    created_at: datetime
    expires_at: datetime | None  # None = never
    created_by: str

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def remaining(self, now: datetime) -> timedelta | None:
        if self.expires_at is None:
            return None
        return self.expires_at - now


def _dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


class EntryStore:
    def __init__(self, path: Path | str) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        if str(path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, expires_at TEXT NOT NULL)")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                created_by TEXT NOT NULL DEFAULT ''
            )
            """
        )

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> Entry:
        return Entry(
            id=row["id"],
            network=row["network"],
            label=row["label"],
            created_at=_dt(row["created_at"]) or datetime.now(UTC),
            expires_at=_dt(row["expires_at"]),
            created_by=row["created_by"],
        )

    def list(self) -> list[Entry]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM entries ORDER BY (expires_at IS NULL), expires_at, network").fetchall()
        return [self._row(r) for r in rows]

    def get(self, entry_id: int) -> Entry | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        return self._row(row) if row else None

    def find(self, network: str) -> Entry | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM entries WHERE network = ?", (network,)).fetchone()
        return self._row(row) if row else None

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0])

    def upsert(self, network: str, label: str, expires_at: datetime | None, now: datetime, created_by: str) -> Entry:
        """Create the entry or, when the network exists, replace label and expiry."""
        with self._lock:
            if self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0] >= _MAX_ENTRIES:
                raise ValidationError("error.too_many_entries", max=_MAX_ENTRIES)
            self._conn.execute(
                """
                INSERT INTO entries (network, label, created_at, expires_at, created_by)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(network) DO UPDATE SET
                    label = CASE WHEN excluded.label = '' THEN entries.label ELSE excluded.label END,
                    expires_at = excluded.expires_at,
                    created_by = excluded.created_by
                """,
                (network, label, _iso(now), _iso(expires_at), created_by),
            )
            row = self._conn.execute("SELECT * FROM entries WHERE network = ?", (network,)).fetchone()
        return self._row(row)

    def set_expiry(self, entry_id: int, expires_at: datetime | None) -> Entry | None:
        with self._lock:
            cur = self._conn.execute("UPDATE entries SET expires_at = ? WHERE id = ?", (_iso(expires_at), entry_id))
            if cur.rowcount == 0:
                return None
            row = self._conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        return self._row(row)

    def delete(self, entry_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            return cur.rowcount > 0

    def expired_between(self, since: datetime, until: datetime) -> list[Entry]:
        """Entries whose end lies in (since, until]: they just dropped off the list."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM entries WHERE expires_at IS NOT NULL AND expires_at > ? AND expires_at <= ?",
                (_iso(since), _iso(until)),
            ).fetchall()
        return [self._row(r) for r in rows]

    def purge_expired(self, before: datetime) -> list[Entry]:
        """Delete entries that expired at or before ``before`` and return them."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM entries WHERE expires_at IS NOT NULL AND expires_at <= ?", (_iso(before),)).fetchall()
            expired = [self._row(r) for r in rows]
            if expired:
                self._conn.execute("DELETE FROM entries WHERE expires_at IS NOT NULL AND expires_at <= ?", (_iso(before),))
        return expired

    def active_networks(self, now: datetime) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT network FROM entries WHERE expires_at IS NULL OR expires_at > ? ORDER BY network",
                (_iso(now),),
            ).fetchall()
        return [r["network"] for r in rows]

    # ---- sessions: issued ids live here so logout really ends them

    def session_add(self, sid: str, expires_at: datetime) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO sessions (sid, expires_at) VALUES (?, ?)", (sid, _iso(expires_at)))

    def session_valid(self, sid: str, now: datetime) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM sessions WHERE sid = ? AND expires_at > ?", (sid, _iso(now))).fetchone()
        return row is not None

    def session_delete(self, sid: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE sid = ?", (sid,))

    def sessions_purge(self, now: datetime) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (_iso(now),))


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).replace(tzinfo=None, microsecond=0).isoformat()


def render_list(networks: list[str]) -> str:
    """The plain-text list BunkerWeb downloads: one entry per line."""
    lines = ["# bunkerweb-whitelister", *networks]
    return "\n".join(lines) + "\n"
