"""Mock Telegram Bot API + Matrix client-server API, plus a Web Push service, ntfy, Gotify and Pushover.

When the control plane posts an approval message, the mock "user" answers after a short delay
according to `plan` (set by the test): a Telegram button press or Matrix reactions/replies.
"""

from __future__ import annotations

import asyncio
import itertools
import socket
import threading

from aiohttp import web


class MockBots:
    def __init__(self) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.log: list[tuple[str, str]] = []
        # telegram: {"scope_label": "Always (host)", "user_id": 4242, "chat_id": 777}
        # matrix:   {"actions": [("@user:hs", "reaction", "👎") | ("@user:hs", "text", "allow {n}")]}
        self.plan: dict = {}
        # outages for sending: {"telegram" | "matrix": "error" | "slow" | "slow-reactions"}
        self.fail: dict[str, str] = {}
        self._ids = itertools.count(100)
        self._tg_updates: list = []
        self._mx_events: list = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._runner: web.AppRunner | None = None
        self._tasks: set[asyncio.Task] = set()
        # Web Push / ntfy / Gotify / Pushover: every request as (kind, headers, body); push status per id
        self.received: list[tuple[str, dict, bytes]] = []
        self.push_status: dict[str, int] = {}

    def _keep(self, task: asyncio.Task) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        ready = threading.Event()

        def run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._serve())
            ready.set()
            self._loop.run_forever()

        threading.Thread(target=run, daemon=True).start()
        ready.wait(10)

    def stop(self) -> None:
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

    async def _serve(self) -> None:
        app = web.Application()
        app.router.add_post("/bot{tok}/{method}", self._tg)
        app.router.add_get("/_matrix/client/v3/account/whoami", self._mx_whoami)
        app.router.add_put("/_matrix/client/v3/rooms/{room}/send/{type}/{txn}", self._mx_send)
        app.router.add_get("/_matrix/client/v3/sync", self._mx_sync)
        app.router.add_post("/push/{sid}", self._plain_post)
        app.router.add_post("/ntfy/{topic}", self._plain_post)
        app.router.add_post("/gotify/message", self._plain_post)
        app.router.add_post("/1/messages.json", self._plain_post)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, "127.0.0.1", self.port).start()

    def messages(self, kind: str) -> list[str]:
        return [text for k, text in self.log if k == kind]

    # ---------------------------------------------------------------- Telegram
    async def _press(self, btn: dict, plan: dict, message_id=None, text=None) -> None:
        await asyncio.sleep(0.8)
        self._tg_updates.append(
            {
                "update_id": next(self._ids),
                "callback_query": {
                    "id": "cb",
                    "data": btn["callback_data"],
                    "from": {"id": plan.get("user_id", 4242), "username": "tester"},
                    "message": {"chat": {"id": plan.get("chat_id", 777)}, "message_id": message_id, "text": text},
                },
            }
        )

    async def _tg(self, request: web.Request) -> web.Response:
        method = request.match_info["method"]
        p = await request.json()
        if method == "sendMessage":
            if self.fail.get("telegram") == "slow":
                await asyncio.sleep(30)
            if self.fail.get("telegram") == "error":
                return web.json_response({"ok": False, "description": "service unavailable"}, status=503)
            mid = next(self._ids)
            self.log.append(("tg.send", p["text"]))
            plan = self.plan.get("telegram")
            if plan:
                buttons = [b for row in p["reply_markup"]["inline_keyboard"] for b in row]
                label = plan["scope_label"]
                btn = next((b for b in buttons if b["text"] == label or b["text"].startswith(label)), None)
                if btn is None:
                    return web.json_response({"ok": True, "result": {"message_id": mid}})

                async def press():
                    await asyncio.sleep(0.8)
                    self._tg_updates.append(
                        {
                            "update_id": next(self._ids),
                            "callback_query": {
                                "id": "cb",
                                "data": btn["callback_data"],
                                "from": {"id": plan.get("user_id", 4242), "username": "tester"},
                                "message": {"chat": {"id": plan.get("chat_id", 777)}},
                            },
                        }
                    )

                self._keep(asyncio.create_task(press()))
            return web.json_response({"ok": True, "result": {"message_id": mid}})
        if method == "getUpdates":
            for _ in range(20):
                if request.transport is None or request.transport.is_closing():
                    return web.json_response({"ok": True, "result": []})
                if self._tg_updates:
                    break
                await asyncio.sleep(0.2)
            updates, self._tg_updates = self._tg_updates, []
            return web.json_response({"ok": True, "result": updates})
        if method in ("answerCallbackQuery", "editMessageText"):
            self.log.append((f"tg.{method}", p.get("text", "")))
            plan = self.plan.get("telegram") or {}
            if method == "editMessageText" and plan.get("then"):  # e.g. press "Revoke" once it appears
                buttons = [b for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row]
                btn = next((b for b in buttons if b["text"] == plan["then"]), None)
                if btn:
                    self._keep(asyncio.create_task(self._press(btn, plan, p.get("message_id"), p.get("text"))))
            return web.json_response({"ok": True, "result": True})
        return web.json_response({"ok": False, "description": f"unknown {method}"})

    # ---------------------------------------------------------------- Matrix
    async def _mx_whoami(self, _request):
        return web.json_response({"user_id": "@bot:hs"})

    async def _mx_send(self, request: web.Request) -> web.Response:
        body = await request.json()
        if self.fail.get("matrix") == "slow":
            await asyncio.sleep(30)
        if self.fail.get("matrix") == "error":
            return web.json_response({"errcode": "M_UNKNOWN", "error": "service unavailable"}, status=503)
        eid = f"$e{next(self._ids)}"
        if request.match_info["type"] == "m.room.message":
            self.log.append(("mx.msg", body["body"]))
            plan = self.plan.get("matrix")
            if plan and ("wants to connect" in body["body"] or "Grant request" in body["body"]):
                short = body["body"].split("#", 1)[1].split()[0]

                async def act():
                    await asyncio.sleep(0.8)
                    for sender, kind, value in plan["actions"]:
                        if kind == "wait":  # e.g. until a grant is active before replying "revoke {n}"
                            await asyncio.sleep(float(value))
                        elif kind == "reaction":
                            self._mx_events.append(
                                {
                                    "type": "m.reaction",
                                    "sender": sender,
                                    "content": {
                                        "m.relates_to": {"rel_type": "m.annotation", "event_id": eid, "key": value}
                                    },
                                }
                            )
                        else:
                            self._mx_events.append(
                                {
                                    "type": "m.room.message",
                                    "sender": sender,
                                    "content": {"msgtype": "m.text", "body": value.format(n=short)},
                                }
                            )

                self._keep(asyncio.create_task(act()))
        elif request.match_info["type"] == "m.reaction":
            if self.fail.get("matrix") == "slow-reactions":  # a slow homeserver, prompts still go through
                await asyncio.sleep(3)
            self.log.append(("mx.reaction", body["m.relates_to"]["key"]))
        return web.json_response({"event_id": eid})

    async def _mx_sync(self, request: web.Request) -> web.Response:
        if "since" not in request.query:
            return web.json_response({"next_batch": "s0"})
        for _ in range(20):
            if request.transport is None or request.transport.is_closing():
                return web.json_response({})  # client (an old control process) is gone: don't eat events
            if self._mx_events:
                break
            await asyncio.sleep(0.2)
        events, self._mx_events = self._mx_events, []
        return web.json_response(
            {"next_batch": f"s{next(self._ids)}", "rooms": {"join": {"!room:hs": {"timeline": {"events": events}}}}}
        )

    # ---------------------------------------------------------------- push services
    async def _plain_post(self, request: web.Request) -> web.Response:
        kind = request.path.split("/")[1]
        self.received.append((kind if kind != "1" else "pushover", dict(request.headers), await request.read()))
        if kind == "push":
            return web.Response(status=self.push_status.get(request.match_info["sid"], 201))
        if self.fail.get(kind) == "error":
            return web.json_response({"error": "down"}, status=500)
        return web.json_response({"ok": True})

    def got(self, kind: str) -> list[tuple[dict, bytes]]:
        return [(h, b) for k, h, b in self.received if k == kind]


def decrypt(body: bytes, ua_private, auth: bytes) -> bytes:
    """RFC 8291 decryption, as a browser does it (independent of control/app/webpush.py)."""
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def hkdf(salt, ikm, info, n):
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:n]

    salt, idlen = body[:16], body[20]
    as_public, ct = body[21 : 21 + idlen], body[21 + idlen :]
    ua_public = ua_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    shared = ua_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    ikm = hkdf(auth, shared, b"WebPush: info\x00" + ua_public + as_public, 32)
    plain = AESGCM(hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)).decrypt(
        hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12), ct, None
    )
    assert plain.endswith(b"\x02")
    return plain[:-1]
