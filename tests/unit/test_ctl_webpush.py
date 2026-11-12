"""control/app/webpush.py: message encryption (RFC 8291 test vector), VAPID, subscriptions and the
single-use action tokens behind the notification buttons (#72)."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app import webpush
from app.webpush import b64u, unb64u
from tests.e2e.mockbots import decrypt

# RFC 8291, Appendix A
RFC = {
    "plaintext": b"When I grow up, I want to be a watermelon",
    "as_private": "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    "ua_public": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    "salt": "DGv6ra1nlYgDCS1FRnbzlw",
    "auth": "BTBZMqHH6r4Tts7J_aSIgg",
    "body": "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK"
    "6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
}


def test_encryption_matches_the_rfc_8291_example():
    as_key = ec.derive_private_key(int.from_bytes(unb64u(RFC["as_private"]), "big"), ec.SECP256R1())
    body = webpush.encrypt(RFC["plaintext"], RFC["ua_public"], RFC["auth"], unb64u(RFC["salt"]), as_key)
    assert b64u(body) == RFC["body"]


def ua_keys():
    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return key, b64u(point), b"0123456789abcdef"


def test_encryption_round_trip_and_size_limit():
    key, p256dh, auth = ua_keys()
    body = webpush.encrypt(b'{"x": 1}', p256dh, b64u(auth))
    assert decrypt(body, key, auth) == b'{"x": 1}'
    with pytest.raises(ValueError):
        webpush.encrypt(b"x" * 5000, p256dh, b64u(auth))


@pytest.fixture
def push(tmp_path, monkeypatch):
    monkeypatch.delenv("PUSH_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("PUSH_TEST_ALLOW_HTTP", raising=False)
    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )

    def make(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return webpush.WebPush(pem, tmp_path / "subs.json", "https://tally.example", b"session-secret")

    return make


def sub(endpoint="https://fcm.googleapis.com/fcm/send/abc"):
    _, p256dh, auth = ua_keys()
    return {"endpoint": endpoint, "keys": {"p256dh": p256dh, "auth": b64u(auth)}}


def test_only_ec_p256_keys_are_accepted(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(ValueError):
        webpush.WebPush(pem, tmp_path / "s.json", "x", b"k")


def test_vapid_header_is_a_valid_es256_jwt(push):
    p = push()
    value = p.vapid("https://fcm.googleapis.com/fcm/send/abc")
    t, k = value.removeprefix("vapid t=").split(", k=")
    header, claims, sig = t.split(".")
    assert json.loads(unb64u(header)) == {"typ": "JWT", "alg": "ES256"}
    c = json.loads(unb64u(claims))
    assert c["aud"] == "https://fcm.googleapis.com" and c["sub"] == "https://tally.example" and c["exp"] > time.time()
    raw = unb64u(sig)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(k))
    pub.verify(der, f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))  # raises if wrong
    assert k == p.public_key


def test_subscriptions_are_validated_stored_and_replaced(push, tmp_path):
    p = push()
    d = p.add(sub(), "my\x00 phone")
    assert d["label"] == "my phone" and d["service"] == "fcm.googleapis.com" and "endpoint" not in d
    assert oct((tmp_path / "subs.json").stat().st_mode)[-3:] == "600"
    again = p.add(sub(), "")  # same endpoint: replaces
    assert len(p.subs) == 1 and again["label"] == "browser"
    assert push().subs[0]["id"] == again["id"]  # persisted
    assert p.remove(again["id"]) and not p.remove("nope") and push().subs == []


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {"endpoint": "https://fcm.googleapis.com/x"},
        sub("http://fcm.googleapis.com/x"),
        sub("https://192.168.1.10/push"),
        sub("https://evil.example/push"),
        sub("https://fcm.googleapis.com/" + "x" * 1100),
        {"endpoint": "https://fcm.googleapis.com/x", "keys": {"p256dh": "AAAA", "auth": "AAAA"}},
        {"endpoint": "https://fcm.googleapis.com/x", "keys": {"p256dh": "!!", "auth": "AAAA"}},
        {**sub(), "keys": {**sub()["keys"], "auth": b64u(b"short")}},
    ],
)
def test_invalid_subscriptions_are_refused(push, bad):
    with pytest.raises(ValueError):
        push().add(bad, "x")


def test_extra_hosts_test_http_and_the_device_limit(push, monkeypatch, caplog):
    p = push(PUSH_ALLOWED_HOSTS="push.example.org, *.autopush.example", PUSH_TEST_ALLOW_HTTP="1")
    p.add(sub("https://push.example.org/wpush/v2/1"), "a")
    p.add(sub("http://a.autopush.example/1"), "b")
    assert "test only" in caplog.text
    monkeypatch.setattr(webpush, "MAX_SUBSCRIPTIONS", 2)
    with pytest.raises(ValueError, match="at most 2"):
        p.add(sub("https://push.example.org/wpush/v2/3"), "c")


def test_unreadable_store_starts_empty(tmp_path, push):
    (tmp_path / "subs.json").write_text("{broken")
    assert push().subs == []
    (tmp_path / "subs.json").write_text(json.dumps([{"id": "x"}, "junk"]))
    assert push().subs == []


def test_request_encrypts_for_the_subscription(push):
    p = push()
    key, p256dh, auth = ua_keys()
    s = p.add({"endpoint": "https://fcm.googleapis.com/x", "keys": {"p256dh": p256dh, "auth": b64u(auth)}}, "a")
    url, body, headers = p.request(p.subs[0], {"title": "t"}, 30, "a123")
    assert url == "https://fcm.googleapis.com/x" and headers["TTL"] == "30" and headers["Topic"] == "a123"
    assert headers["Content-Encoding"] == "aes128gcm" and headers["Authorization"].startswith("vapid t=")
    assert json.loads(decrypt(body, key, auth)) == {"title": "t"}
    assert (
        "Topic" not in p.request(p.subs[0], {}, -5)[2] and p.label(s["id"]) == "a" and p.label("x") == "removed device"
    )


# ---------------------------------------------------------------- action tokens
def test_tokens_are_single_use_bound_and_short_lived(push):
    p = push()
    t = p.mint("ask", "abc123", "once", "sub1", time.time() + 3600)
    claims = p.redeem(t)
    assert claims["k"] == "ask" and claims["i"] == "abc123" and claims["d"] == "once" and claims["s"] == "sub1"
    assert claims["e"] <= time.time() + webpush.ACTION_TTL + 1  # capped at 10 minutes
    with pytest.raises(ValueError, match="already used"):
        p.redeem(t)
    with pytest.raises(ValueError, match="expired"):
        p.redeem(p.mint("ask", "abc123", "deny", "sub1", time.time() - 1))


def test_forged_or_foreign_tokens_are_refused(push, tmp_path):
    p = push()
    t = p.mint("grant", "ab", "read", "s", time.time() + 60)
    raw, sig = t.split(".")
    forged = b64u(json.dumps({**json.loads(unb64u(raw)), "d": "approve"}).encode())
    for bad in (f"{forged}.{sig}", "", "x", f"{raw}.", f"{raw}.{sig[:-2]}AA"):
        with pytest.raises(ValueError, match="invalid action"):
            p.redeem(bad)
    other = webpush.WebPush(
        p.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        tmp_path / "o.json",
        "x",
        b"other secret",
    )
    with pytest.raises(ValueError):
        other.redeem(t)  # another session secret: another key
    wrong = p.mint("ask", "ab", "always", "s", time.time() + 60)  # never minted by control, but signed
    with pytest.raises(ValueError, match="invalid action"):
        p.redeem(wrong)


def test_host_allowed():
    assert webpush.host_allowed("https://updates.push.services.mozilla.com/wpush/v2/x", [])
    assert webpush.host_allowed("https://web.push.apple.com/x", [])
    assert not webpush.host_allowed("https://push.services.mozilla.com.evil.example/x", [])
    assert not webpush.host_allowed("https:///x", [])
    assert not webpush.host_allowed("ftp://fcm.googleapis.com/x", [], allow_http=True)
