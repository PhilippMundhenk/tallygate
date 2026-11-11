"""Mock Telegram Bot API + Matrix client-server API.

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
        self._ids = itertools.count(100)
        self._tg_updates: list = []
        self._mx_events: list = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._runner: web.AppRunner | None = None
        self._tasks: set[asyncio.Task] = set()

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
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, "127.0.0.1", self.port).start()

    def messages(self, kind: str) -> list[str]:
        return [text for k, text in self.log if k == kind]

    # ---------------------------------------------------------------- Telegram
    async def _tg(self, request: web.Request) -> web.Response:
        method = request.match_info["method"]
        p = await request.json()
        if method == "sendMessage":
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
            return web.json_response({"ok": True, "result": True})
        return web.json_response({"ok": False, "description": f"unknown {method}"})

    # ---------------------------------------------------------------- Matrix
    async def _mx_whoami(self, _request):
        return web.json_response({"user_id": "@bot:hs"})

    async def _mx_send(self, request: web.Request) -> web.Response:
        body = await request.json()
        eid = f"$e{next(self._ids)}"
        if request.match_info["type"] == "m.room.message":
            self.log.append(("mx.msg", body["body"]))
            plan = self.plan.get("matrix")
            if plan and ("wants to connect" in body["body"] or "Grant request" in body["body"]):
                short = body["body"].split("#", 1)[1].split()[0]

                async def act():
                    await asyncio.sleep(0.8)
                    for sender, kind, value in plan["actions"]:
                        if kind == "reaction":
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
