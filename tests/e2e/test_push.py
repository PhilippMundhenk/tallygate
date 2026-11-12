"""Phone approvals without a chat bot (#72): Web Push with action tokens, and ntfy / Gotify / Pushover.

The mock push service records what control sends; the test decrypts it like a browser and presses the
notification's buttons through /api/push/act, without a session."""

from __future__ import annotations

import contextlib
import json
import time

import pytest

from .conftest import CONTROL_PASSWORD, start_echo
from .helpers import Api, http_via_proxy
from .mockbots import decrypt
from .test_gateway import in_thread

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Device:
    """A browser's push subscription: its key pair and the mock push endpoint."""

    def __init__(self, mockbots, name: str) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth = name.encode().ljust(16, b"_")[:16]
        self.name = name
        self.mock = mockbots
        point = self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.sub = {
            "endpoint": f"{mockbots.base}/push/{name}",
            "keys": {"p256dh": b64u(point), "auth": b64u(self.auth)},
        }

    def messages(self) -> list[tuple[dict, dict]]:
        out = []
        for h, body in self.mock.got("push"):
            with contextlib.suppress(Exception):  # another device's message does not decrypt with this key
                out.append((h, json.loads(decrypt(body, self.key, self.auth))))
        return out

    def wait(self, pred, timeout: float = 8) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for h, m in self.messages():
                if pred(m):
                    return {**m, "_headers": h}
            time.sleep(0.1)
        raise AssertionError(f"no push message for {self.name}: {[m for _, m in self.messages()]}")


@pytest.fixture
def ui(control_with, mockbots):
    mockbots.received.clear()
    base = control_with(
        PUSH_TEST_ALLOW_HTTP="1",
        PUSH_ALLOWED_HOSTS="127.0.0.1",
        NTFY_URL=f"{mockbots.base}/ntfy/tally",
        NTFY_TOKEN="ntfy-secret",
        GOTIFY_URL=f"{mockbots.base}/gotify",
        GOTIFY_TOKEN="gotify-secret",
        PUSHOVER_TOKEN="po-app",
        PUSHOVER_USER="po-user",
        PUSHOVER_API_BASE=mockbots.base,
        PUBLIC_URL=base_url_placeholder,
    )
    api = Api(base, csrf_header="X-Tallygate")
    assert api.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    api.anon = Api(base, csrf_header="X-Tallygate")  # no session: like a service worker after the session ended
    return api


base_url_placeholder = "http://127.0.0.1"  # PUBLIC_URL: only the click link in ntfy/Gotify/Pushover


def act(api, token, **headers):
    return api.anon.call("POST", "/api/push/act", {"token": token}, headers=headers)


def test_allow_from_the_notification_without_a_session(gateway, mockbots, ui):
    status, st, _ = ui.call("GET", "/api/push")
    assert status == 200 and st["enabled"] and st["subscriptions"] == [] and len(st["public_key"]) > 80
    phone = Device(mockbots, "phone")
    status, d, _ = ui.call("POST", "/api/push/subscribe", {"subscription": phone.sub, "label": "my phone"})
    assert status == 201 and d["label"] == "my phone"
    assert ui.call("GET", "/api/meta")[1]["notify"]["webpush"] is True

    port = start_echo()
    t, res = in_thread(http_via_proxy, gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    m = phone.wait(lambda m: m.get("tokens") and f":{port} " in m["body"])
    assert [a["action"] for a in m["actions"]] == ["once", "deny"] and m["url"] == "/#approvals"
    h = m["_headers"]
    assert h["Content-Encoding"] == "aes128gcm" and h["Authorization"].startswith("vapid t=") and h["Topic"]

    # the CSRF rule holds without a session too
    assert act(ui, m["tokens"]["once"], **{"X-Tallygate": ""})[0] == 403
    assert act(ui, m["tokens"]["once"], Origin="https://evil.example")[0] == 403
    status, r, _ = act(ui, m["tokens"]["once"])
    assert status == 200 and r == {"ok": True, "decision": "once"}
    t.join(10)
    assert res["r"][0] == 200
    _, evs, _ = gateway["api"].call("GET", "/events?limit=20")
    assert any(e["port"] == port and e["reason"] == "once by push:my phone" for e in evs)
    assert act(ui, m["tokens"]["once"])[1]["error"] == "this action was already used"
    assert act(ui, m["tokens"]["deny"])[0] == 409  # already decided
    assert act(ui, "forged.token")[0] == 403
    done = phone.wait(lambda m: m.get("silent") and m["tag"] == f"a{m['tag'][1:]}" and "→" in m["body"])
    assert "allow (once, by push:my phone)" in done["body"]

    # the same ask went to ntfy, Gotify and Pushover as text with a link, without buttons or tokens
    (nh, _), *_ = [x for x in mockbots.got("ntfy") if f":{port}" in x[1].decode()]
    assert (
        nh["Authorization"] == "Bearer ntfy-secret" and nh["Click"] == "http://127.0.0.1" and nh["Priority"] == "high"
    )
    gotify = [json.loads(b) for h, b in mockbots.got("gotify") if h["X-Gotify-Key"] == "gotify-secret"]
    assert any(f":{port}" in g["message"] and g["priority"] == 8 for g in gotify)
    assert any(f"%3A{port}" in b.decode() and b"token=po-app" in b for _, b in mockbots.got("pushover"))
    assert not any(b"tokens" in b for _, b in mockbots.got("ntfy"))


def test_grant_request_offers_only_read_from_the_notification(gateway, mockbots, ui):
    phone = Device(mockbots, "grantphone")
    ui.call("POST", "/api/push/subscribe", {"subscription": phone.sub, "label": "g"})
    status, r, _ = gateway["agent"].call("POST", "/v1/grants/svc/request", {"level": "write", "reason": "push"})
    assert status == 202
    m = phone.wait(lambda m: m.get("tokens") and m["tag"] == f"g{r['id']}")
    assert [a["action"] for a in m["actions"]] == ["read", "deny"]  # write needs the UI or a chat bot
    assert act(ui, m["tokens"]["read"])[0] == 200
    _, st, _ = gateway["agent"].call("GET", f"/v1/requests/{r['id']}")
    assert st["status"] == "approved" and st["granted_level"] == "read"
    phone.wait(lambda m: m.get("silent") and m["tag"] == f"g{r['id']}")
    _, g, _ = gateway["api"].call("GET", "/grants")
    for a in g["active"]:
        gateway["api"].call("DELETE", f"/active-grants/{a['id']}?by=e2e")


def test_devices_test_message_and_expired_subscriptions(mockbots, ui):
    assert ui.call("POST", "/api/push/test", {})[0] == 400  # nobody subscribed
    keep, gone = Device(mockbots, "keep"), Device(mockbots, "gone")
    mockbots.push_status["gone"] = 410
    ids = {}
    for dev in (keep, gone):
        ids[dev.name] = ui.call("POST", "/api/push/subscribe", {"subscription": dev.sub, "label": dev.name})[1]["id"]
    status, r, _ = ui.call("POST", "/api/push/test", {})
    assert status == 200 and r["delivered"] == 1
    assert keep.wait(lambda m: m.get("tag") == "test")["body"].startswith("Test notification")
    assert [s["label"] for s in ui.call("GET", "/api/push")[1]["subscriptions"]] == ["keep"]  # 410: removed
    assert ui.call("DELETE", f"/api/push/{ids['keep']}")[0] == 200
    assert ui.call("DELETE", f"/api/push/{ids['keep']}")[0] == 404
    status, r, _ = ui.call(
        "POST", "/api/push/subscribe", {"subscription": {**keep.sub, "endpoint": "https://evil.example/x"}}
    )
    assert status == 400 and "known push service" in r["error"]
    assert ui.call("POST", "/api/push/subscribe", [1])[0] == 400
    mockbots.push_status["keep"] = 500
    ui.call("POST", "/api/push/subscribe", {"subscription": keep.sub, "label": "keep"})
    status, r, _ = ui.call("POST", "/api/push/test", {})
    assert status == 502 and "no browser" in r["error"]
    mockbots.push_status.clear()


def test_pwa_files_are_public_and_the_rest_is_not(control):
    anon = Api(control["base"])
    status, body, headers = anon.call("GET", "/sw.js")
    assert status == 200 and b"notificationclick" in body and headers["Service-Worker-Allowed"] == "/"
    assert headers["Content-Type"].startswith("text/javascript")
    status, manifest, headers = anon.call("GET", "/manifest.webmanifest")
    assert status == 200 and manifest["start_url"] == "/#approvals" and "manifest+json" in headers["Content-Type"]
    for icon in manifest["icons"]:
        assert anon.call("GET", icon["src"])[0] == 200
    assert anon.call("GET", "/static/app.js")[0] == 302  # everything else still needs a login
    assert anon.call("GET", "/api/push")[0] == 401
    assert anon.call("GET", "/api/push/act")[0] == 403  # only POST
    csp = anon.call("GET", "/login")[2]["Content-Security-Policy"]
    assert "manifest-src 'self'" in csp and "worker-src 'self'" in csp


def test_web_push_is_off_when_the_data_volume_is_not_writable(control_with, tmp_path):
    blocked = tmp_path / "not-a-dir"
    blocked.write_text("")
    base = control_with(CONTROL_DATA=blocked, SESSION_SECRET="e2e")
    api = Api(base, csrf_header="X-Tallygate")
    api.call("POST", "/login", form={"password": CONTROL_PASSWORD})
    assert api.call("GET", "/api/push")[1] == {"enabled": False, "subscriptions": []}
    assert api.call("POST", "/api/push/subscribe", {"subscription": {}})[0] == 503
    assert api.call("POST", "/api/push/act", {"token": "x"})[0] == 503


def test_digest_goes_to_the_notification_channels(mockbots, ui, gateway):
    phone = Device(mockbots, "digest")
    ui.call("POST", "/api/push/subscribe", {"subscription": phone.sub, "label": "d"})
    ui.call("PATCH", "/api/gw/availability", {"away": True})
    try:
        port = start_echo()
        http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    finally:
        ui.call("PATCH", "/api/gw/availability", {"away": False})
    assert f":{port}" in phone.wait(lambda m: m.get("tag") == "digest")["body"]
    deadline = time.time() + 5
    while not any(f":{port}" in b.decode() for _, b in mockbots.got("ntfy")) and time.time() < deadline:
        time.sleep(0.1)
    (h, _), *_ = [x for x in mockbots.got("ntfy") if f":{port}" in x[1].decode()]
    assert h["Priority"] == "default" and h["Title"] == "tallygate digest"
