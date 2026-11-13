"""Web Push for the installable UI (#72): VAPID (RFC 8292), message encryption (RFC 8291, aes128gcm),
subscriptions, and single-use action tokens for the notification buttons.

The notification's *Allow once* / *Deny* buttons work without opening the UI. They are not approve URLs:
each button carries a token that is signed with a key derived from the session secret, bound to one
pending request, one decision and one subscription, valid for at most ACTION_TTL seconds and accepted once.
The token travels end-to-end encrypted to the subscribed browser (the push service cannot read it) and is
sent back by the service worker as a POST with the CSRF header.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
from fnmatch import fnmatchcase
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("control")

ACTION_TTL = 600  # a notification button works for at most 10 minutes (and never after the request expired)
MAX_SUBSCRIPTIONS = 20
RECORD_SIZE = 4096
# Push services of the common browsers. Others (e.g. a self-hosted autopush) via PUSH_ALLOWED_HOSTS: the
# control plane only ever posts to these hosts, so a subscription cannot point it at the LAN.
PUSH_HOSTS = ("fcm.googleapis.com", "*.push.services.mozilla.com", "*.push.apple.com", "*.notify.windows.com")
DECISIONS = {"ask": ("once", "deny"), "grant": ("approve", "read", "deny")}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 with a single expand block (length <= 32), as RFC 8291 uses it."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def _point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def encrypt(
    payload: bytes,
    p256dh: str,
    auth: str,
    salt: bytes | None = None,
    server_key: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    """RFC 8291 message encryption with the aes128gcm content coding (RFC 8188), one record."""
    ua_public = unb64u(p256dh)
    auth_secret = unb64u(auth)
    salt = salt or os.urandom(16)
    server_key = server_key or ec.generate_private_key(ec.SECP256R1())
    as_public = _point(server_key.public_key())
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    shared = server_key.exchange(ec.ECDH(), ua_key)
    ikm = _hkdf(auth_secret, shared, b"WebPush: info\x00" + ua_public + as_public, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    if len(payload) + 1 + 16 > RECORD_SIZE:
        raise ValueError("push payload too large")
    body = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)  # 0x02: last record, no padding
    return salt + RECORD_SIZE.to_bytes(4, "big") + bytes([len(as_public)]) + as_public + body


def host_allowed(endpoint: str, extra: list[str], allow_http: bool = False) -> bool:
    u = urllib.parse.urlsplit(endpoint)
    if u.scheme != "https" and not (allow_http and u.scheme == "http"):
        return False
    host = (u.hostname or "").lower()
    return bool(host) and any(fnmatchcase(host, p) for p in (*PUSH_HOSTS, *extra))


class WebPush:
    def __init__(self, private_pem: bytes, store: Path, subject: str, action_key: bytes) -> None:
        key = serialization.load_pem_private_key(private_pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("the VAPID key must be an EC P-256 private key")
        self.key = key
        self.public_key = b64u(_point(key.public_key()))  # the browser's applicationServerKey
        self.store = store
        self.subject = subject
        self.action_key = hmac.new(action_key, b"tallygate push actions", hashlib.sha256).digest()
        self.extra_hosts = [h.strip().lower() for h in os.environ.get("PUSH_ALLOWED_HOSTS", "").split(",") if h.strip()]
        self.allow_http = os.environ.get("PUSH_TEST_ALLOW_HTTP") == "1"  # TEST ONLY: mock push services
        if self.allow_http:
            log.warning("PUSH_TEST_ALLOW_HTTP is set - push endpoints over plain HTTP are accepted (test only)")
        self.used: dict[str, float] = {}  # token nonce -> expiry (single use)
        self.subs: list[dict] = []
        try:
            data = json.loads(store.read_text(encoding="utf-8"))
            self.subs = [s for s in data if isinstance(s, dict) and {"id", "endpoint", "p256dh", "auth"} <= set(s)]
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.error("push subscriptions in %s unreadable (%s): starting without", store, e)

    # ---------------------------------------------------------------- subscriptions
    def _save(self) -> None:
        tmp = self.store.with_name(self.store.name + ".tmp")
        tmp.write_text(json.dumps(self.subs, indent=1), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(self.store)

    def add(self, sub: dict, label: str) -> dict:
        """Validate and store a browser's PushSubscription (JSON). The same endpoint replaces its old entry."""
        if not isinstance(sub, dict) or not isinstance(sub.get("keys"), dict):
            raise ValueError("expected a PushSubscription: {endpoint, keys: {p256dh, auth}}")
        endpoint = str(sub.get("endpoint", ""))
        if len(endpoint) > 1024 or not host_allowed(endpoint, self.extra_hosts, self.allow_http):
            raise ValueError("push endpoint is not a known push service (see PUSH_ALLOWED_HOSTS)")
        p256dh, auth = str(sub["keys"].get("p256dh", "")), str(sub["keys"].get("auth", ""))
        try:
            point, secret = unb64u(p256dh), unb64u(auth)
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError as e:
            raise ValueError("invalid subscription keys") from e
        if len(point) != 65 or len(secret) != 16:
            raise ValueError("invalid subscription keys")
        self.subs = [s for s in self.subs if s["endpoint"] != endpoint]
        if len(self.subs) >= MAX_SUBSCRIPTIONS:
            raise ValueError(f"at most {MAX_SUBSCRIPTIONS} devices; remove one first")
        clean = "".join(c for c in str(label) if c.isprintable())[:40].strip() or "browser"
        entry = {
            "id": secrets.token_hex(6),
            "endpoint": endpoint,
            "p256dh": p256dh,
            "auth": auth,
            "label": clean,
            "created": time.time(),
        }
        self.subs.append(entry)
        self._save()
        return self.public(entry)

    @staticmethod
    def public(s: dict) -> dict:
        return {
            "id": s["id"],
            "label": s["label"],
            "created": s["created"],
            "service": urllib.parse.urlsplit(s["endpoint"]).hostname,
        }

    def remove(self, sid: str) -> bool:
        before = len(self.subs)
        self.subs = [s for s in self.subs if s["id"] != sid]
        if len(self.subs) != before:
            self._save()
            return True
        return False

    # ---------------------------------------------------------------- sending
    def vapid(self, endpoint: str) -> str:
        """Authorization header value (RFC 8292): an ES256 JWT for the push service's origin."""
        u = urllib.parse.urlsplit(endpoint)
        header = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        claims = {"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600, "sub": self.subject}
        body = b64u(json.dumps(claims, separators=(",", ":")).encode())
        r, s = decode_dss_signature(self.key.sign(f"{header}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        sig = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return f"vapid t={header}.{body}.{sig}, k={self.public_key}"

    def request(self, sub: dict, message: dict, ttl: int, topic: str | None = None) -> tuple[str, bytes, dict]:
        """(url, body, headers) for one push message to one subscription."""
        body = encrypt(json.dumps(message, separators=(",", ":")).encode(), sub["p256dh"], sub["auth"])
        headers = {
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(max(0, int(ttl))),
            "Urgency": "high",
            "Authorization": self.vapid(sub["endpoint"]),
        }
        if topic:
            headers["Topic"] = topic  # a newer message with the same topic replaces an undelivered one
        return sub["endpoint"], body, headers

    # ---------------------------------------------------------------- action tokens
    def mint(self, kind: str, item_id: str, decision: str, sub_id: str, expires: float) -> str:
        exp = int(min(expires, time.time() + ACTION_TTL))
        claims = {"k": kind, "i": item_id, "d": decision, "s": sub_id, "e": exp, "n": secrets.token_hex(8)}
        raw = b64u(json.dumps(claims, separators=(",", ":")).encode())
        return f"{raw}.{b64u(hmac.new(self.action_key, raw.encode(), hashlib.sha256).digest())}"

    def redeem(self, token: str) -> dict:
        """The token's claims if it is genuine, unexpired and unused; marks it used. ValueError otherwise."""
        raw, _, sig = str(token).partition(".")
        good = b64u(hmac.new(self.action_key, raw.encode(), hashlib.sha256).digest())
        if not raw or not hmac.compare_digest(sig.encode(), good.encode()):
            raise ValueError("invalid action")
        claims = json.loads(unb64u(raw))
        now = time.time()
        self.used = {n: e for n, e in self.used.items() if e > now}
        if claims["e"] <= now:
            raise ValueError("this action has expired: open tallygate to decide")
        if claims["n"] in self.used:
            raise ValueError("this action was already used")
        if claims["d"] not in DECISIONS.get(claims["k"], ()):
            raise ValueError("invalid action")
        self.used[claims["n"]] = claims["e"]
        return claims

    def label(self, sub_id: str) -> str:
        return next((s["label"] for s in self.subs if s["id"] == sub_id), "removed device")
