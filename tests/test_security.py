from __future__ import annotations

import ipaddress

from whitelister.security import (
    LoginThrottle,
    PasswordChecker,
    SessionCodec,
    has_forwarding_headers,
    hash_password,
    resolve_client_ip,
    throttle_key,
    verify_password,
)


def nets(*items: str):
    return tuple(ipaddress.ip_network(i) for i in items)


def test_password_hash_roundtrip():
    encoded = hash_password("correct horse battery staple", iterations=2000)
    assert encoded.startswith("pbkdf2_sha256$2000$")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)
    assert not verify_password("x", "garbage")
    assert not verify_password("x", "pbkdf2_sha256$10$YQ==$YQ==")  # too few iterations


def test_password_checker_plain_and_hash():
    assert PasswordChecker("abcdefghijkl", None).check("abcdefghijkl")
    assert not PasswordChecker("abcdefghijkl", None).check("abcdefghijkL")
    assert not PasswordChecker("abcdefghijkl", None).check("a" * 5000)
    hashed = hash_password("hunter2hunter2", iterations=2000)
    assert PasswordChecker(None, hashed).check("hunter2hunter2")
    assert not PasswordChecker(None, hashed).check("hunter2")


def test_session_codec_roundtrip_and_tamper():
    codec = SessionCodec(b"s" * 40, max_age_seconds=60)
    session = codec.new()
    token = codec.encode(session)
    decoded = codec.decode(token)
    assert decoded is not None and decoded.sid == session.sid and decoded.csrf == session.csrf
    assert codec.decode(token[:-3] + "abc") is None
    assert codec.decode(None) is None
    assert codec.decode("x" * 600) is None
    assert codec.check_csrf(session, session.csrf)
    assert not codec.check_csrf(session, session.csrf[:-1])
    assert not codec.check_csrf(session, None)
    # a different secret never validates the same cookie
    assert SessionCodec(b"t" * 40, 60).decode(token) is None


def test_session_expires():
    codec = SessionCodec(b"s" * 40, max_age_seconds=1)
    session = codec.new()
    token = codec.encode(session)
    assert codec.decode(token) is not None
    expired = SessionCodec(b"s" * 40, max_age_seconds=-1)
    assert expired.decode(token) is None


def test_login_throttle_locks_and_backs_off():
    throttle = LoginThrottle(max_failures=3, lock_seconds=30)
    now = 1000.0
    assert throttle.retry_after("1.2.3.4", now) == 0
    assert throttle.record_failure("1.2.3.4", now) == 0
    assert throttle.record_failure("1.2.3.4", now) == 0
    assert throttle.record_failure("1.2.3.4", now) == 30
    assert throttle.retry_after("1.2.3.4", now + 10) > 0
    assert throttle.retry_after("1.2.3.4", now + 31) == 0
    assert throttle.record_failure("1.2.3.4", now + 31) == 60
    assert throttle.retry_after("5.6.7.8", now) == 0
    throttle.record_success("1.2.3.4")
    assert throttle.retry_after("1.2.3.4", now + 32) == 0


def test_throttle_global_budget_and_decay():
    throttle = LoginThrottle(max_failures=100, lock_seconds=30, global_budget=5)
    now = 5000.0
    for i in range(5):
        assert throttle.record_failure(f"k{i}", now) == 0
    assert throttle.record_failure("k9", now) == 60  # the sixth failure within a minute trips the budget
    assert throttle.retry_after("someone-else", now + 1) > 0
    assert throttle.retry_after("someone-else", now + 61) == 0
    # per-key failures are forgotten after an hour of quiet
    t2 = LoginThrottle(max_failures=2, lock_seconds=30)
    t2.record_failure("a", 0.0)
    assert t2.record_failure("a", 4000.0) == 0


def test_throttle_key_groups_ipv6_by_64():
    assert throttle_key(ipaddress.ip_address("2001:db8:1:2::1")) == "2001:db8:1:2::/64"
    assert throttle_key(ipaddress.ip_address("2001:db8:1:2:ffff::1")) == "2001:db8:1:2::/64"
    assert throttle_key(ipaddress.ip_address("203.0.113.9")) == "203.0.113.9"
    assert throttle_key(ipaddress.ip_address("::ffff:203.0.113.9")) == "203.0.113.9"
    assert throttle_key(None) is None


def test_client_ip_without_trusted_proxies_ignores_headers():
    ip, via = resolve_client_ip("10.0.0.5", {"x-forwarded-for": "203.0.113.9"}, ())
    assert str(ip) == "10.0.0.5" and via is False


def test_client_ip_walks_xff_from_the_right():
    trusted = nets("10.0.0.0/8")
    ip, via = resolve_client_ip("10.0.0.5", {"x-forwarded-for": "198.51.100.1, 203.0.113.9, 10.0.0.7"}, trusted)
    assert str(ip) == "203.0.113.9" and via is True
    # a spoofed hop before the real client is ignored because only the rightmost untrusted one counts
    ip, _ = resolve_client_ip("10.0.0.5", {"x-forwarded-for": "1.1.1.1, 203.0.113.9"}, trusted)
    assert str(ip) == "203.0.113.9"
    # garbage in the chain -> no client, never the peer
    ip, _ = resolve_client_ip("10.0.0.5", {"x-forwarded-for": "not-an-ip"}, trusted)
    assert ip is None
    # untrusted peer with a header -> the peer
    ip, _ = resolve_client_ip("192.0.2.1", {"x-forwarded-for": "203.0.113.9"}, trusted)
    assert str(ip) == "192.0.2.1"


def test_client_ip_custom_header_and_mapped_v6():
    trusted = nets("10.0.0.0/8")
    ip, via = resolve_client_ip("::ffff:10.0.0.5", {"cf-connecting-ip": "2001:db8::1"}, trusted, "CF-Connecting-IP")
    assert str(ip) == "2001:db8::1" and via is True
    ip, _ = resolve_client_ip("10.0.0.5", {"x-forwarded-for": "203.0.113.9:4321"}, trusted)
    assert str(ip) == "203.0.113.9"


def test_forwarding_header_detection():
    assert has_forwarding_headers({"x-forwarded-for": "1.2.3.4"})
    assert has_forwarding_headers({"forwarded": "for=1.2.3.4"})
    assert not has_forwarding_headers({"user-agent": "curl"})
