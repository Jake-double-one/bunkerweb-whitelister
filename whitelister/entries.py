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
from typing import Any

from .config import IPNetwork, Settings

MAX_LABEL = 64
_MAX_EVENTS = 200
_MAX_INVITES = 100
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
    # An IPv6 scope id ("%eth0") is never meaningful for a reverse-proxy whitelist, and the stdlib
    # accepts almost any character inside it (newlines included): refuse it and any inner whitespace.
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
    updated_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def remaining(self, now: datetime) -> timedelta | None:
        if self.expires_at is None:
            return None
        return self.expires_at - now


@dataclass(frozen=True)
class Invite:
    """A shareable link: whoever opens it can put their own address on the list."""

    id: int
    name: str
    created_at: datetime
    created_by: str
    valid_until: datetime  # the link itself
    access_days: int  # how long each redeemed address stays listed
    max_addresses: int  # 0 = unlimited
    revoked_at: datetime | None
    used: int  # distinct addresses redeemed so far

    def is_open(self, now: datetime) -> bool:
        return self.revoked_at is None and self.valid_until > now

    @property
    def remaining(self) -> int | None:
        return None if self.max_addresses == 0 else max(self.max_addresses - self.used, 0)


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
                created_by TEXT NOT NULL DEFAULT '',
                updated_at TEXT
            )
            """
        )
        if "updated_at" not in {r["name"] for r in self._conn.execute("PRAGMA table_info(entries)")}:
            self._conn.execute("ALTER TABLE entries ADD COLUMN updated_at TEXT")
        self._conn.execute("UPDATE entries SET updated_at = created_at WHERE updated_at IS NULL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                action TEXT NOT NULL,
                network TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT '',
                valid_until TEXT NOT NULL,
                access_days INTEGER NOT NULL,
                max_addresses INTEGER NOT NULL DEFAULT 0,
                revoked_at TEXT
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invite_addresses (
                invite_id INTEGER NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
                network TEXT NOT NULL,
                first_at TEXT NOT NULL,
                last_at TEXT NOT NULL,
                PRIMARY KEY (invite_id, network)
            )
            """
        )
        if "removed_at" not in {r["name"] for r in self._conn.execute("PRAGMA table_info(invite_addresses)")}:
            self._conn.execute("ALTER TABLE invite_addresses ADD COLUMN removed_at TEXT")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> Entry:
        created = _dt(row["created_at"])
        return Entry(
            id=int(row["id"]),
            network=row["network"],
            label=row["label"],
            created_at=created,
            expires_at=_dt(row["expires_at"]),
            created_by=row["created_by"],
            updated_at=_dt(row["updated_at"]) or created,
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
                INSERT INTO entries (network, label, created_at, expires_at, created_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(network) DO UPDATE SET
                    label = CASE WHEN excluded.label = '' THEN entries.label ELSE excluded.label END,
                    expires_at = excluded.expires_at,
                    created_by = excluded.created_by,
                    updated_at = excluded.updated_at
                """,
                (network, label, _iso(now), _iso(expires_at), created_by, _iso_exact(now)),
            )
            row = self._conn.execute("SELECT * FROM entries WHERE network = ?", (network,)).fetchone()
        return self._row(row)

    def set_expiry(self, entry_id: int, expires_at: datetime | None, now: datetime | None = None) -> Entry | None:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE entries SET expires_at = ?, updated_at = ? WHERE id = ?",
                (_iso(expires_at), _iso_exact(now or datetime.now(UTC)), entry_id),
            )
            if cur.rowcount == 0:
                return None
            row = self._conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        return self._row(row)

    def delete(self, entry_id: int, now: datetime | None = None) -> bool:
        """Remove an entry. An address a link had added is remembered as removed, so the link cannot
        bring it back for free: the operator's removal wins over the guest's "renew"."""
        with self._lock:
            row = self._conn.execute("SELECT network FROM entries WHERE id = ?", (entry_id,)).fetchone()
            if row is None:
                return False
            self._conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            self._conn.execute(
                "UPDATE invite_addresses SET removed_at = ? WHERE network = ? AND removed_at IS NULL",
                (_iso(now or datetime.now(UTC)), row["network"]),
            )
            return True

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

    # ---- history: a short, bounded log of what happened, shown on the page

    def event_add(self, action: str, network: str, label: str, actor: str, now: datetime) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (at, action, network, label, actor) VALUES (?, ?, ?, ?, ?)",
                (_iso(now), action, network, label, actor),
            )
            self._conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)", (_MAX_EVENTS,))

    def events_recent(self, limit: int = 5) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [
            {"at": _dt(r["at"]), "action": r["action"], "network": r["network"], "label": r["label"], "actor": r["actor"]} for r in rows
        ]

    # ---- small key/value facts, e.g. when BunkerWeb last fetched the list

    def meta_set(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value)
            )

    def meta_get(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    # ---- invitations: only the token's hash is stored, the link itself is shown once

    def _invite_row(self, row: sqlite3.Row) -> Invite:
        used = self._conn.execute("SELECT COUNT(*) FROM invite_addresses WHERE invite_id = ?", (row["id"],)).fetchone()[0]
        return Invite(
            id=int(row["id"]),
            name=row["name"],
            created_at=_dt(row["created_at"]),
            created_by=row["created_by"],
            valid_until=_dt(row["valid_until"]),
            access_days=int(row["access_days"]),
            max_addresses=int(row["max_addresses"]),
            revoked_at=_dt(row["revoked_at"]),
            used=int(used),
        )

    def invite_create(
        self, token_hash: str, name: str, valid_until: datetime, access_days: int, max_addresses: int, now: datetime, created_by: str
    ) -> Invite:
        with self._lock:
            if (
                self._conn.execute("SELECT COUNT(*) FROM invites WHERE revoked_at IS NULL AND valid_until > ?", (_iso(now),)).fetchone()[0]
                >= _MAX_INVITES
            ):
                raise ValidationError("error.too_many_invites", max=_MAX_INVITES)
            cur = self._conn.execute(
                "INSERT INTO invites (token_hash, name, created_at, created_by, valid_until, access_days, max_addresses) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (token_hash, name, _iso(now), created_by, _iso(valid_until), access_days, max_addresses),
            )
            row = self._conn.execute("SELECT * FROM invites WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._invite_row(row)

    def invite_by_hash(self, token_hash: str) -> Invite | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM invites WHERE token_hash = ?", (token_hash,)).fetchone()
            return None if row is None else self._invite_row(row)

    def invite_get(self, invite_id: int) -> Invite | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM invites WHERE id = ?", (invite_id,)).fetchone()
            return None if row is None else self._invite_row(row)

    def invites_open(self, now: datetime) -> list[Invite]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM invites WHERE revoked_at IS NULL AND valid_until > ? ORDER BY id DESC", (_iso(now),)
            ).fetchall()
            return [self._invite_row(r) for r in rows]

    def invite_revoke(self, invite_id: int, now: datetime) -> Invite | None:
        with self._lock:
            self._conn.execute("UPDATE invites SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (_iso(now), invite_id))
            row = self._conn.execute("SELECT * FROM invites WHERE id = ?", (invite_id,)).fetchone()
            return None if row is None else self._invite_row(row)

    def invite_addresses(self, invite_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT network, first_at, last_at, removed_at FROM invite_addresses WHERE invite_id = ? ORDER BY first_at",
                (invite_id,),
            ).fetchall()
        return [
            {"network": r["network"], "first_at": _dt(r["first_at"]), "last_at": _dt(r["last_at"]), "removed_at": _dt(r["removed_at"])}
            for r in rows
        ]

    def invite_address_state(self, invite_id: int, network: str) -> str | None:
        """``None`` when the link has not seen the address, ``"known"`` when it added it, ``"removed"`` when the
        operator has since taken that entry off the list."""
        with self._lock:
            row = self._conn.execute(
                "SELECT removed_at FROM invite_addresses WHERE invite_id = ? AND network = ?", (invite_id, network)
            ).fetchone()
        if row is None:
            return None
        return "removed" if row["removed_at"] else "known"

    def invite_touch_address(self, invite_id: int, network: str, now: datetime) -> bool:
        """Record a redemption; True when the address is new to this invite (and counts against its budget)."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE invite_addresses SET last_at = ? WHERE invite_id = ? AND network = ?", (_iso(now), invite_id, network)
            )
            if cur.rowcount:
                return False
            self._conn.execute(
                "INSERT INTO invite_addresses (invite_id, network, first_at, last_at) VALUES (?, ?, ?, ?)",
                (invite_id, network, _iso(now), _iso(now)),
            )
            return True

    def invites_purge(self, before: datetime) -> int:
        """Forget links that have been closed (expired or revoked) for a while; their entries live on."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM invites WHERE valid_until <= ? OR (revoked_at IS NOT NULL AND revoked_at <= ?)", (_iso(before), _iso(before))
            )
            return cur.rowcount

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


def _iso_exact(value: datetime) -> str:
    """Full precision, for "changed after the last fetch?" comparisons within the same second."""
    return value.astimezone(UTC).replace(tzinfo=None).isoformat()


def is_list_token(value: str) -> bool:
    """One printable, whitespace-free token that parses as a network: the only thing a list line may be."""
    if not value or not value.isprintable() or "%" in value or any(ch.isspace() for ch in value):
        return False
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def render_list(networks: list[str]) -> str:
    """The plain-text list BunkerWeb downloads: one validated entry per line.

    Defensive at the sink as well: a stored value can never contribute more than one line,
    which also covers rows written before the parser refused scope ids.
    """
    lines = ["# bunkerweb-whitelister", *(n for n in networks if is_list_token(n))]
    return "\n".join(lines) + "\n"


def policy_violations(entries: list[Entry], settings: Settings) -> list[Entry]:
    """Stored rows that no longer pass the current entry policy (after a tightening of the settings)."""
    bad = []
    for e in entries:
        try:
            parse_network(e.network, settings)
        except ValidationError:
            bad.append(e)
    return bad
