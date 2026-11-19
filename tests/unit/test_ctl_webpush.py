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
def devices(p, *ids):
    """The subscriptions the tokens of these tests are minted for (a token needs its device, #241)."""
    p.subs.extend({"id": i, "label": i, "endpoint": "https://fcm.googleapis.com/x"} for i in (ids or ("sub1", "s")))
    return p


def test_tokens_are_single_use_bound_and_short_lived(push):
    p = devices(push())
    t = p.mint("ask", "abc123", "once", "sub1", time.time() + 3600)
    claims = p.redeem(t)
    assert claims["k"] == "ask" and claims["i"] == "abc123" and claims["d"] == "once" and claims["s"] == "sub1"
    assert claims["e"] <= time.time() + webpush.ACTION_TTL + 1  # capped at 10 minutes
    with pytest.raises(ValueError, match="already used"):
        p.redeem(t)
    with pytest.raises(ValueError, match="expired"):
        p.redeem(p.mint("ask", "abc123", "deny", "sub1", time.time() - 1))


def test_forged_or_foreign_tokens_are_refused(push, tmp_path):
    p = devices(push())
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
    for kind, decision in (
        ("ask", "approve"),
        ("ask", "allow"),
        ("grant", "always"),
        ("grant", "write"),
        ("x", "deny"),
    ):
        with pytest.raises(ValueError, match="no such notification action"):
            p.mint(kind, "ab", decision, "s", time.time() + 60)  # control never mints these
        with pytest.raises(ValueError, match="invalid action"):
            p.redeem(signed(p, k=kind, d=decision))  # and refuses them even with a good signature


def signed(p, **claims):
    """A token with a valid signature for any claims: what only a holder of the action key could make."""
    import hashlib
    import hmac

    base = {"k": "ask", "i": "ab", "d": "deny", "s": "s", "e": int(time.time()) + 60, "n": "feed", "b": p.boot}
    raw = b64u(json.dumps({**base, **claims}).encode())
    return f"{raw}.{b64u(hmac.new(p.action_key, raw.encode(), hashlib.sha256).digest())}"


# ---------------------------------------------------------------- configurable buttons (#212)
ALL = ("once", "hour", "always", "domain", "deny", "deny_always")


def test_every_button_has_its_own_token_and_it_decides_only_that(push):
    p = devices(push())
    tokens = {d: p.mint("ask", "abc123", d, "sub1", time.time() + 60) for d in ALL}
    assert len(set(tokens.values())) == len(ALL)
    for d, t in tokens.items():
        claims = p.redeem(t, ask=ALL)
        assert (claims["k"], claims["i"], claims["d"], claims["s"]) == ("ask", "abc123", d, "sub1")
        with pytest.raises(ValueError, match="already used"):
            p.redeem(t, ask=ALL)


@pytest.mark.parametrize("target", ["always", "domain", "hour", "once"])
def test_a_deny_token_cannot_be_turned_into_an_allow(push, target):
    """The decision is inside the signed claims: swapping it breaks the signature, whatever is switched on."""
    p = devices(push())
    for source in ("deny", "deny_always"):
        raw, sig = p.mint("ask", "abc123", source, "sub1", time.time() + 60).split(".")
        swapped = b64u(json.dumps({**json.loads(unb64u(raw)), "d": target}, separators=(",", ":")).encode())
        with pytest.raises(ValueError, match="invalid action"):
            p.redeem(f"{swapped}.{sig}", ask=ALL)
        other = p.mint("ask", "abc123", target, "sub1", time.time() + 60).split(".")
        for mixed in (f"{other[0]}.{sig}", f"{raw}.{other[1]}"):  # claims of one token, signature of another
            with pytest.raises(ValueError, match="invalid action"):
                p.redeem(mixed, ask=ALL)
        assert p.redeem(f"{raw}.{sig}", ask=ALL)["d"] == source  # the untouched token still only denies


def test_a_token_is_bound_to_its_request_and_device(push):
    p = devices(push())
    raw, sig = p.mint("ask", "abc123", "always", "sub1", time.time() + 60).split(".")
    for change in ({"i": "ffff"}, {"s": "sub2"}, {"k": "grant"}, {"e": int(time.time()) + 9999}, {"n": "0" * 16}):
        forged = b64u(json.dumps({**json.loads(unb64u(raw)), **change}, separators=(",", ":")).encode())
        with pytest.raises(ValueError, match="invalid action"):
            p.redeem(f"{forged}.{sig}", ask=ALL)


def test_a_button_that_is_switched_off_is_refused_and_not_used_up(push):
    p = devices(push())
    t = p.mint("ask", "abc123", "always", "sub1", time.time() + 60)
    with pytest.raises(ValueError, match="switched off"):
        p.redeem(t)  # the default: Allow once and Deny
    with pytest.raises(ValueError, match="switched off"):
        p.redeem(t, ask=("once", "domain", "deny_always"))
    assert p.redeem(t, ask=("deny", "always"))["d"] == "always"  # switched on (again): the same token works once
    with pytest.raises(ValueError, match="already used"):
        p.redeem(t, ask=("deny", "always"))
    # grant decisions do not depend on the connection buttons
    assert p.redeem(p.mint("grant", "ab", "read", "s", time.time() + 60), ask=("deny",))["d"] == "read"


def test_an_expired_permanent_allow_token_is_refused(push):
    p = devices(push())
    with pytest.raises(ValueError, match="expired"):
        p.redeem(p.mint("ask", "abc123", "always", "sub1", time.time() - 1), ask=ALL)
    assert json.loads(unb64u(p.mint("ask", "a", "always", "s", time.time() + 86400).split(".")[0]))["e"] <= (
        time.time() + webpush.ACTION_TTL + 1
    )


# ---------------------------------------------------------------- tokens end with their device and at a restart (#241)
def test_a_token_stops_working_when_its_device_is_removed(push):
    """The reviewer's reproduction: remove the device, then press the button of a notification it still shows."""
    p = push()
    phone, tablet = p.add(sub(), "lost phone"), p.add(sub("https://fcm.googleapis.com/fcm/send/other"), "tablet")
    exp = time.time() + 600
    ask = p.mint("ask", "abc123", "once", phone["id"], exp)
    grant = p.mint("grant", "abc124", "approve", phone["id"], exp)
    kept = p.mint("ask", "abc123", "once", tablet["id"], exp)
    assert p.remove(phone["id"])
    for token in (ask, grant):
        for _ in range(2):  # refused every time, and not for being "used"
            with pytest.raises(ValueError, match="this device was removed from tallygate: open tallygate to decide"):
                p.redeem(token)
    assert p.used == {}
    assert p.redeem(kept)["s"] == tablet["id"]  # the other device's button is untouched
    # the same browser subscribing again is a new device with a new id: the old token stays dead
    again = p.add(sub(), "lost phone")
    assert again["id"] != phone["id"]
    with pytest.raises(ValueError, match="removed"):
        p.redeem(ask)


def test_a_token_for_a_device_that_never_existed_is_refused(push):
    p = push()
    with pytest.raises(ValueError, match="removed"):
        p.redeem(p.mint("ask", "abc123", "deny", "nope", time.time() + 60))


def test_a_used_token_stays_used_across_a_restart(push):
    """The used-token set is memory only. A second WebPush on the same files and session secret is control
    after a restart: before the fix it took the used token again."""
    before = push()
    sid = before.add(sub(), "phone")["id"]
    exp = time.time() + 600
    used, unused = before.mint("ask", "abc123", "once", sid, exp), before.mint("ask", "abc123", "deny", sid, exp)
    assert before.redeem(used)["d"] == "once"
    after = push()
    assert [s["id"] for s in after.subs] == [sid] and after.boot != before.boot
    for token in (used, unused):  # neither the replay nor a button that was never pressed
        with pytest.raises(ValueError, match="tallygate was restarted since this notification: open tallygate"):
            after.redeem(token)
    assert after.used == {}
    assert after.redeem(after.mint("ask", "abc123", "once", sid, exp))["d"] == "once"  # new prompts work
    assert before.redeem(unused)["d"] == "deny"  # and the boot id is all that differs


def test_the_boot_id_is_signed_and_a_token_without_one_is_refused(push):
    p = devices(push())
    raw, sig = p.mint("ask", "abc123", "once", "sub1", time.time() + 60).split(".")
    claims = json.loads(unb64u(raw))
    assert claims["b"] == p.boot and len(p.boot) == 8
    other = devices(push())
    forged = b64u(json.dumps({**claims, "b": other.boot}, separators=(",", ":")).encode())
    with pytest.raises(ValueError, match="invalid action"):
        other.redeem(f"{forged}.{sig}")  # rewriting the boot id breaks the signature
    for missing in (None, "", 0):  # e.g. minted by a version before the boot id existed
        with pytest.raises(ValueError, match="restarted"):
            p.redeem(signed(p, s="sub1", b=missing))
    assert p.label("sub1") == "sub1" and p.label("nope") == "removed device"


def test_host_allowed():
    assert webpush.host_allowed("https://updates.push.services.mozilla.com/wpush/v2/x", [])
    assert webpush.host_allowed("https://web.push.apple.com/x", [])
    assert not webpush.host_allowed("https://push.services.mozilla.com.evil.example/x", [])
    assert not webpush.host_allowed("https:///x", [])
    assert not webpush.host_allowed("ftp://fcm.googleapis.com/x", [], allow_http=True)
