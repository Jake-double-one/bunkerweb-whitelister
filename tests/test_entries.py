from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from whitelister.config import load_settings
from whitelister.entries import (
    EntryStore,
    ValidationError,
    expiry_from_date,
    expiry_from_days,
    network_text,
    normalize_label,
    parse_network,
    render_list,
)

NOW = datetime(2026, 10, 29, 11, 30, tzinfo=UTC)


@pytest.fixture
def settings(env):
    return load_settings()


def test_parse_network_accepts_hosts_and_cidrs(settings):
    assert network_text(parse_network("203.0.113.42", settings)) == "203.0.113.42"
    assert network_text(parse_network(" 203.0.113.42/24 ", settings)) == "203.0.113.0/24"
    assert network_text(parse_network("2001:db8::1a2b", settings)) == "2001:db8::1a2b"
    assert network_text(parse_network("2001:db8::/64", settings)) == "2001:db8::/64"


@pytest.mark.parametrize(
    ("raw", "key"),
    [
        ("", "error.ip_invalid"),
        ("hello", "error.ip_invalid"),
        ("300.1.1.1", "error.ip_invalid"),
        ("0.0.0.0/0", "error.prefix_too_wide"),
        ("10.0.0.0/8", "error.prefix_too_wide"),
        ("2001:db8::/32", "error.prefix_too_wide"),
        ("127.0.0.1", "error.ip_not_routable"),
        ("224.0.0.1", "error.ip_not_routable"),
        ("0.0.0.0", "error.ip_not_routable"),  # noqa: S104
        ("1.2.3.4; DROP", "error.ip_invalid"),
    ],
)
def test_parse_network_rejects(settings, raw, key):
    with pytest.raises(ValidationError) as exc:
        parse_network(raw, settings)
    assert exc.value.key == key


def test_private_networks_can_be_forbidden(env):
    env(ALLOW_PRIVATE="no")
    settings = load_settings()
    with pytest.raises(ValidationError) as exc:
        parse_network("192.168.1.10", settings)
    assert exc.value.key == "error.ip_private"


def test_label_normalization():
    assert normalize_label("  Jake   ·\tHomeoffice ") == "Jake · Homeoffice"
    assert normalize_label("a\x00b\x1bc") == "abc"
    assert normalize_label(None) == ""
    with pytest.raises(ValidationError):
        normalize_label("x" * 65)


def test_expiry_helpers(settings):
    assert expiry_from_days(7, NOW, settings) == NOW + timedelta(days=7)
    with pytest.raises(ValidationError):
        expiry_from_days(0, NOW, settings)
    with pytest.raises(ValidationError):
        expiry_from_days(99999, NOW, settings)
    berlin = ZoneInfo("Europe/Berlin")
    end = expiry_from_date("2026-12-31", NOW, settings, berlin)
    assert end == datetime(2026, 12, 31, 23, 0, tzinfo=UTC)  # midnight Berlin, 1 Jan
    with pytest.raises(ValidationError) as exc:
        expiry_from_date("2020-01-01", NOW, settings)
    assert exc.value.key == "error.date_in_past"
    with pytest.raises(ValidationError):
        expiry_from_date("31.12.2026", NOW, settings)


def test_store_roundtrip_and_expiry(tmp_path):
    store = EntryStore(tmp_path / "db.sqlite3")
    a = store.upsert("203.0.113.42", "Jake", NOW + timedelta(days=7), NOW, "203.0.113.42")
    b = store.upsert("198.51.100.0/24", "Office", None, NOW, "203.0.113.42")
    c = store.upsert("192.0.2.9", "Gone", NOW - timedelta(minutes=1), NOW, "")
    assert [e.network for e in store.list()] == ["192.0.2.9", "203.0.113.42", "198.51.100.0/24"]
    assert store.active_networks(NOW) == ["198.51.100.0/24", "203.0.113.42"]
    assert store.get(a.id).label == "Jake"

    # same network again: expiry replaced, empty label keeps the old one
    again = store.upsert("203.0.113.42", "", None, NOW, "")
    assert again.id == a.id and again.label == "Jake" and again.expires_at is None

    assert store.set_expiry(b.id, NOW + timedelta(days=1)).expires_at == NOW + timedelta(days=1)
    assert store.set_expiry(9999, None) is None

    expired = store.purge_expired(NOW)
    assert [e.id for e in expired] == [c.id]
    assert store.count() == 2
    assert store.delete(b.id) and not store.delete(b.id)
    store.close()


def test_render_list():
    assert render_list(["1.2.3.4", "10.0.0.0/24"]) == "# bunkerweb-whitelister\n1.2.3.4\n10.0.0.0/24\n"
