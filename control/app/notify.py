"""Human-in-the-loop notifications: Telegram (inline buttons) and Matrix (reactions or text replies).

Telegram: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ALLOWED_USER_IDS (comma list, required).
Matrix:   MATRIX_HOMESERVER, MATRIX_ACCESS_TOKEN, MATRIX_ROOM_ID, MATRIX_ALLOWED_USERS (comma list, required).
          Use an UNENCRYPTED room (the bot does not do E2EE); host it on your own homeserver.

Two kinds of prompts: connection requests (scopes below) and grant requests (approve / read-only /
deny, then revoke). Both share one short-number space for Matrix text replies.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import json
import logging
import os
import time
import urllib.parse
import uuid

import aiohttp

log = logging.getLogger("notify")
QUEUE_SIZE = 1000  # gateway events waiting for delivery; beyond that new events are dropped (logged)
SEND_TIMEOUT = 15  # per chat API call (not the long polls): a hanging API delays later prompts at most this long

BUTTONS = [  # (scope, label, matrix reaction)
    ("once", "Allow 2 min", "👍"),
    ("hour", "Allow 1 h", "⏰"),
    ("always", "Always (host)", "✅"),
    ("domain", "Always (*.domain)", "🌐"),
    ("deny", "Deny", "👎"),
    ("deny_always", "Block forever", "⛔"),
]
REACTION_TO_SCOPE = {r: s for s, _, r in BUTTONS}
GRANT_REACTIONS = {"👍": "approve", "📖": "read", "👎": "deny"}
GRANT_WORDS = {"approve": "approve", "allow": "approve", "read": "read", "deny": "deny", "block": "deny"}
TEXT_TO_SCOPE = {
    "allow": "once",
    "once": "once",
    "hour": "hour",
    "always": "always",
    "domain": "domain",
    "deny": "deny",
    "block": "deny_always",
}


def _describe(p: dict) -> str:
    """Approval text. The host is agent-chosen: show the registrable domain separately so that
    look-alikes such as github.com.evil.example stand out, and flag punycode (IDN) names."""
    ips = ", ".join(p.get("ips") or []) or "not resolved yet"
    text = f"{p['host']}:{p['port']} via {p.get('proto')} (IPs: {ips})"
    if p.get("domain") and p["domain"] != p["host"]:
        text += f"\nDomain: {p['domain']}"
    if p.get("idn"):
        text += "\n⚠ internationalised (punycode) name - check for look-alikes"
    return text


def _scope_label(scope: str, label: str, p: dict) -> str:
    if scope == "domain":
        return f"Always (*.{p['domain']})" if p.get("domain") else ""
    return label


class Notifier:
    def __init__(self, app, decide, decide_grant=None, revoke_grant=None) -> None:
        self.app = app
        self.decide = decide  # async (pending_id, scope, by) -> (status, data)
        self.decide_grant = decide_grant  # async (request_id, decision, by) -> (status, data)
        self.revoke_grant = revoke_grant  # async (active_id, by) -> (status, data)
        self.gmsgs: dict[str, dict] = {}  # grant request id -> {"tg", "mx", "short", "text", "aid", "expires"}
        self.public_url = os.environ.get("PUBLIC_URL", "")
        self.tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.tg_base = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
        self.tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
        self.tg_users = {u.strip() for u in os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").split(",") if u.strip()}
        self.mx_hs = os.environ.get("MATRIX_HOMESERVER", "").rstrip("/")
        self.mx_token = os.environ.get("MATRIX_ACCESS_TOKEN", "")
        self.mx_room = os.environ.get("MATRIX_ROOM_ID", "")
        self.mx_users = {u.strip() for u in os.environ.get("MATRIX_ALLOWED_USERS", "").split(",") if u.strip()}
        if self.mx_hs and not self.mx_users:
            log.error("MATRIX_ALLOWED_USERS is required - Matrix approvals disabled")
            self.mx_hs = ""
        if self.tg_token and not self.tg_users:
            # In a group chat every member could otherwise press "Allow".
            log.error("TELEGRAM_ALLOWED_USER_IDS is required - Telegram approvals disabled")
            self.tg_token = ""
        # pending id -> {"tg": message_id, "mx": event_id, "short": n, "text": str}
        self.msgs: dict[str, dict] = {}
        self.short: dict[int, str] = {}
        self._n = 0
        # Gateway events wait here, so slow chat APIs never block the reader of the gateway stream.
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=QUEUE_SIZE)

    def describe(self) -> dict:
        return {
            "telegram": bool(self.tg_token and self.tg_chat),
            "matrix": bool(self.mx_hs and self.mx_token and self.mx_room),
        }

    def start(self) -> list[asyncio.Task]:
        tasks = [asyncio.create_task(self._worker())]
        if self.describe()["telegram"]:
            tasks.append(asyncio.create_task(self._tg_poll()))
        if self.describe()["matrix"]:
            tasks.append(asyncio.create_task(self._mx_sync()))
        return tasks

    @property
    def http(self) -> aiohttp.ClientSession:
        return self.app["http"]

    # ---------------------------------------------------------------- events from gateway
    def enqueue(self, ev: dict) -> None:
        """Called by the gateway stream reader; never waits."""
        try:
            self.queue.put_nowait(ev)
        except asyncio.QueueFull:
            log.warning("notification queue full, dropping %s event", ev.get("type"))

    async def _worker(self) -> None:
        while True:  # one event at a time, in order: a 'resolved' must not overtake its 'ask'
            ev = await self.queue.get()
            await self.handle(ev)

    async def _channels(self, what: str, **sends) -> dict:
        """Send to all channels concurrently, each on its own: a failing or slow channel neither stops
        nor delays the other. Returns {channel: result} for the channels that succeeded."""
        names = [n for n, coro in sends.items() if coro is not None]
        results = await asyncio.gather(*(sends[n] for n in names), return_exceptions=True)
        ok = {}
        for name, res in zip(names, results, strict=True):
            if isinstance(res, Exception):
                msg = str(res).replace(self.tg_token, "<token>") if self.tg_token else str(res)
                log.warning("%s: sending %s failed: %s", name, what, msg)
            else:
                ok[name] = res
        return ok

    async def handle(self, ev: dict) -> None:
        try:
            if ev["type"] == "ask":
                await self._on_ask(ev["pending"])
            elif ev["type"] == "resolved":
                await self._on_resolved(ev)
            elif ev["type"] == "grant_request":
                await self._on_grant_request(ev["request"], ev.get("grant") or {})
            elif ev["type"] == "grant_resolved":
                await self._on_grant_resolved(ev["request"])
        except Exception as e:  # noqa: BLE001
            log.warning("notification failed: %s", e)

    async def _on_ask(self, p: dict) -> None:
        now = time.time()
        for pid, e in list(self.msgs.items()):  # drop entries whose 'resolved' event we missed
            if e.get("expires", now) < now - 300:
                self.short.pop(e["short"], None)
                del self.msgs[pid]
        self._n = self._n % 999 + 1
        while self._n in self.short:  # never reuse a number that is still open
            self._n = self._n % 999 + 1
        entry = {"short": self._n, "text": _describe(p), "expires": p.get("expires", now)}
        self.msgs[p["id"]] = entry
        self.short[self._n] = p["id"]
        timeout = int(p["expires"] - time.time())
        on = self.describe()
        sent = await self._channels(
            "approval prompt",
            tg=self._tg_send(p, timeout) if on["telegram"] else None,
            mx=self._mx_send(p, entry["short"], timeout) if on["matrix"] else None,
        )
        entry.update(sent)

    async def _on_resolved(self, ev: dict) -> None:
        entry = self.msgs.pop(ev["id"], None)
        if not entry:
            return
        self.short.pop(entry["short"], None)
        outcome = (
            f"{ev.get('action')} ({ev.get('scope') or ev.get('reason')}{', by ' + ev['by'] if ev.get('by') else ''})"
        )
        tg = mx = None
        if entry.get("tg"):
            tg = self._tg(
                "editMessageText",
                chat_id=self.tg_chat,
                message_id=entry["tg"],
                text=f"{'✅' if ev.get('action') == 'allow' else '⛔'} {entry['text']}\n→ {outcome}",
            )
        if entry.get("mx"):
            mx = self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                {
                    "msgtype": "m.notice",
                    "body": f"#{entry['short']} → {outcome}",
                    "m.relates_to": {"m.in_reply_to": {"event_id": entry["mx"]}},
                },
            )
        await self._channels("outcome", tg=tg, mx=mx)

    # ---------------------------------------------------------------- grants
    def _next_short(self, key: str) -> int:
        now = time.time()
        for rid, e in list(self.gmsgs.items()):  # forget entries well past their lifetime
            if e.get("expires", now) < now - 300:
                self.short.pop(e["short"], None)
                del self.gmsgs[rid]
        self._n = self._n % 999 + 1
        while self._n in self.short:
            self._n = self._n % 999 + 1
        self.short[self._n] = key
        return self._n

    async def _on_grant_request(self, r: dict, g: dict) -> None:
        short = self._next_short("g:" + r["id"])
        targets = "\n".join("  " + t for t in g.get("targets", []))
        text = (
            f"🔑 Grant request: {r['name']} ({r['level']}) for {r['ttl_label']}\n"
            f"{g.get('description', '')}\n{targets}\n"
            f"Agent's reason (unverified): {r.get('reason') or '(none)'}"
        )
        entry = {"short": short, "text": text, "expires": r["expires"]}
        self.gmsgs[r["id"]] = entry
        timeout = int(r["expires"] - time.time())
        on = self.describe()
        sent = await self._channels(
            "grant prompt",
            tg=self._tg_send_grant(r, g, text, timeout) if on["telegram"] else None,
            mx=self._mx_send_grant(short, text) if on["matrix"] else None,
        )
        entry.update(sent)

    async def _tg_send_grant(self, r: dict, g: dict, text: str, timeout: int) -> int:
        kb = [[{"text": f"✅ Approve {r['level']} ({r['ttl_label']})", "callback_data": f"g:{r['id']}:approve"}]]
        if r["level"] == "write" and "read" in g.get("levels", []):
            kb.append([{"text": "📖 Approve read-only", "callback_data": f"g:{r['id']}:read"}])
        kb.append([{"text": "⛔ Deny", "callback_data": f"g:{r['id']}:deny"}])
        res = await self._tg(
            "sendMessage",
            chat_id=self.tg_chat,
            text=f"{text}\nAuto-deny in {timeout}s.",
            reply_markup={"inline_keyboard": kb},
            disable_web_page_preview=True,
        )
        return res["message_id"]

    async def _mx_send_grant(self, short: int, text: str) -> str:
        body = f"#{short} {text}\nReact: 👍 approve  📖 read-only  👎 deny — or reply: approve|read|deny {short}"
        html_body = html.escape(body).replace("\n", "<br/>")
        res = await self._mx_put(
            f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
            {"msgtype": "m.text", "body": body, "format": "org.matrix.custom.html", "formatted_body": html_body},
        )
        event_id = res["event_id"]
        for reaction in GRANT_REACTIONS:
            try:
                await self._mx_put(
                    f"/rooms/{self._room()}/send/m.reaction/{uuid.uuid4().hex}",
                    {"m.relates_to": {"rel_type": "m.annotation", "event_id": event_id, "key": reaction}},
                )
            except Exception:  # noqa: BLE001
                break
        return event_id

    async def _on_grant_resolved(self, r: dict) -> None:
        entry = self.gmsgs.get(r["id"])
        if not entry:
            return
        if r["status"] == "approved":
            until = time.strftime("%H:%M", time.localtime(time.time() + r["ttl"]))
            outcome = f"✅ {r['granted_level']} until {until} (by {r['decided_by']})"
            entry["aid"], entry["expires"] = r["grant_id"], time.time() + r["ttl"]
        else:
            outcome = f"⛔ {r['status']}" + (f" (by {r['decided_by']})" if r.get("decided_by") else "")
            self.short.pop(entry["short"], None)
            self.gmsgs.pop(r["id"], None)
        tg = mx = None
        if entry.get("tg"):
            markup = (
                {"inline_keyboard": [[{"text": "Revoke", "callback_data": f"r:{r['grant_id']}"}]]}
                if r["status"] == "approved"
                else {"inline_keyboard": []}
            )
            tg = self._tg(
                "editMessageText",
                chat_id=self.tg_chat,
                message_id=entry["tg"],
                text=f"{entry['text']}\n→ {outcome}",
                reply_markup=markup,
            )
        if entry.get("mx"):
            note = f"#{entry['short']} → {outcome}" + (
                f" — reply 'revoke {entry['short']}' to end it" if r["status"] == "approved" else ""
            )
            mx = self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                {"msgtype": "m.notice", "body": note, "m.relates_to": {"m.in_reply_to": {"event_id": entry["mx"]}}},
            )
        await self._channels("grant outcome", tg=tg, mx=mx)

    async def _apply_grant(self, rid: str, decision: str, by: str) -> str:
        if decision == "revoke":
            entry = self.gmsgs.get(rid, {})
            if not entry.get("aid") or not self.revoke_grant:
                return "nothing to revoke"
            status, data = await self.revoke_grant(entry["aid"], by)
        else:
            if not self.decide_grant:
                return "grants not supported"
            status, data = await self.decide_grant(rid, decision, by)
        if status == 200:
            return "ok"
        return data.get("error", f"error {status}") if isinstance(data, dict) else f"error {status}"

    async def _apply(self, pid: str, scope: str, by: str) -> str:
        status, data = await self.decide(pid, scope, by)
        if status == 200:
            return "ok"
        return data.get("error", f"error {status}") if isinstance(data, dict) else f"error {status}"

    # ---------------------------------------------------------------- Telegram
    async def _tg(self, method: str, **params):
        timeout = 40 if method == "getUpdates" else SEND_TIMEOUT  # getUpdates long-polls for 30 s
        async with self.http.post(
            f"{self.tg_base}/bot{self.tg_token}/{method}", json=params, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as r:
            data = await r.json(content_type=None)
            if not data.get("ok"):
                raise RuntimeError(f"telegram {method}: {data.get('description')}")
            return data["result"]

    async def _tg_send(self, p: dict, timeout: int) -> int:
        buttons = [(scope, _scope_label(scope, label, p)) for scope, label, _ in BUTTONS]
        buttons = [(scope, label) for scope, label in buttons if label]
        kb = [
            [{"text": label, "callback_data": f"d:{p['id']}:{scope}"} for scope, label in buttons[i : i + 2]]
            for i in range(0, len(buttons), 2)
        ]
        text = f"🔐 Agent wants to connect:\n{_describe(p)}\nAuto-deny in {timeout}s."
        if self.public_url:
            text += f"\n{self.public_url}"
        res = await self._tg(
            "sendMessage",
            chat_id=self.tg_chat,
            text=text,
            reply_markup={"inline_keyboard": kb},
            disable_web_page_preview=True,
        )
        return res["message_id"]

    async def _tg_poll(self) -> None:
        offset = None
        while True:
            try:
                params = {"timeout": 30, "allowed_updates": ["callback_query"]}
                if offset:
                    params["offset"] = offset
                for upd in await self._tg("getUpdates", **params):
                    offset = upd["update_id"] + 1
                    cq = upd.get("callback_query")
                    if not cq:
                        continue
                    uid = str(cq["from"]["id"])
                    chat = str(cq.get("message", {}).get("chat", {}).get("id"))
                    if chat != str(self.tg_chat) or (self.tg_users and uid not in self.tg_users):
                        await self._tg("answerCallbackQuery", callback_query_id=cq["id"], text="Not authorised")
                        continue
                    who = cq["from"].get("username") or uid
                    parts = cq["data"].split(":")
                    if parts[0] == "d" and len(parts) == 3:
                        result = await self._apply(parts[1], parts[2], f"telegram:{who}")
                    elif parts[0] == "g" and len(parts) == 3:
                        result = await self._apply_grant(parts[1], parts[2], f"telegram:{who}")
                    elif parts[0] == "r" and len(parts) == 2 and self.revoke_grant:
                        status, _ = await self.revoke_grant(parts[1], f"telegram:{who}")
                        result = "revoked" if status == 200 else "already ended"
                        msg = cq.get("message", {})
                        with contextlib.suppress(Exception):
                            await self._tg(
                                "editMessageText",
                                chat_id=self.tg_chat,
                                message_id=msg.get("message_id"),
                                text=f"{msg.get('text', '')}\n→ revoked by {who}",
                                reply_markup={"inline_keyboard": []},
                            )
                    else:
                        continue
                    await self._tg("answerCallbackQuery", callback_query_id=cq["id"], text=result[:180])
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.warning("telegram poll: %s", str(e).replace(self.tg_token, "<token>"))
                await asyncio.sleep(5)

    # ---------------------------------------------------------------- Matrix
    def _room(self) -> str:
        return urllib.parse.quote(self.mx_room, safe="")

    async def _mx(self, method: str, path: str, body=None, params=None):
        async with self.http.request(
            method,
            f"{self.mx_hs}/_matrix/client/v3{path}",
            json=body,
            params=params,
            headers={"Authorization": f"Bearer {self.mx_token}"},
            timeout=aiohttp.ClientTimeout(total=60 if path == "/sync" else SEND_TIMEOUT),  # /sync long-polls
        ) as r:
            data = await r.json(content_type=None)
            if r.status >= 400:
                raise RuntimeError(f"matrix {path}: {data.get('error', r.status)}")
            return data

    async def _mx_put(self, path: str, body: dict):
        return await self._mx("PUT", path, body)

    async def _mx_send(self, p: dict, short: int, timeout: int) -> str:
        legend = "  ".join(f"{r} {lbl}" for s, label, r in BUTTONS if (lbl := _scope_label(s, label, p)))
        body = (
            f"🔐 #{short} Agent wants to connect: {_describe(p)} — auto-deny in {timeout}s.\n"
            f"React: {legend}\nor reply: allow|hour|always|domain|deny|block {short}"
        )
        html_body = (
            f"🔐 <b>#{short}</b> Agent wants to connect: <code>{html.escape(_describe(p))}</code>"
            f" — auto-deny in {timeout}s.<br/>React: {html.escape(legend)}<br/>"
            f"or reply: <code>allow|hour|always|domain|deny|block {short}</code>"
        )
        res = await self._mx_put(
            f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
            {"msgtype": "m.text", "body": body, "format": "org.matrix.custom.html", "formatted_body": html_body},
        )
        event_id = res["event_id"]
        for _, _, reaction in BUTTONS:  # pre-seed reactions so a single tap works
            try:
                await self._mx_put(
                    f"/rooms/{self._room()}/send/m.reaction/{uuid.uuid4().hex}",
                    {"m.relates_to": {"rel_type": "m.annotation", "event_id": event_id, "key": reaction}},
                )
            except Exception:  # noqa: BLE001
                break
        return event_id

    async def _mx_sync(self) -> None:
        try:
            self.mx_self = (await self._mx("GET", "/account/whoami"))["user_id"]
        except Exception as e:  # noqa: BLE001
            log.error("matrix whoami failed: %s", e)
            self.mx_self = None
        if self.mx_self in self.mx_users:
            log.error("bot user %s must not be in MATRIX_ALLOWED_USERS - Matrix approvals disabled", self.mx_self)
            return
        flt = json.dumps(
            {
                "room": {"rooms": [self.mx_room], "timeline": {"limit": 50}},
                "presence": {"types": []},
                "account_data": {"types": []},
            }
        )
        since = None
        while True:
            try:
                params = {"timeout": "30000", "filter": flt}
                if since:
                    params["since"] = since
                data = await self._mx("GET", "/sync", params=params)
                first = since is None
                since = data["next_batch"]
                if first:
                    continue  # skip history
                room = data.get("rooms", {}).get("join", {}).get(self.mx_room, {})
                for ev in room.get("timeline", {}).get("events", []):
                    await self._mx_event(ev)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.warning("matrix sync: %s", e)
                await asyncio.sleep(5)

    async def _mx_event(self, ev: dict) -> None:
        sender = ev.get("sender")
        if sender == getattr(self, "mx_self", None) or sender not in self.mx_users:
            return
        content = ev.get("content", {})
        pid = scope = None
        if ev.get("type") == "m.reaction":  # grant prompt?
            rel = content.get("m.relates_to", {})
            rid = next((k for k, v in self.gmsgs.items() if v.get("mx") == rel.get("event_id")), None)
            decision = GRANT_REACTIONS.get(rel.get("key", "").replace("️", ""))
            if rid and decision:
                return await self._mx_grant(rid, decision, sender)
        elif ev.get("type") == "m.room.message":
            words = content.get("body", "").strip().lower().split()
            if len(words) == 2 and words[1].lstrip("#").isdigit():
                key = self.short.get(int(words[1].lstrip("#")), "")
                if key.startswith("g:"):
                    decision = "revoke" if words[0] == "revoke" else GRANT_WORDS.get(words[0])
                    if decision:
                        return await self._mx_grant(key[2:], decision, sender)
                    return
        if ev.get("type") == "m.reaction":
            rel = content.get("m.relates_to", {})
            key = rel.get("key", "").replace("️", "")
            scope = REACTION_TO_SCOPE.get(key) or REACTION_TO_SCOPE.get(rel.get("key", ""))
            pid = next((k for k, v in self.msgs.items() if v.get("mx") == rel.get("event_id")), None)
        elif ev.get("type") == "m.room.message":
            words = content.get("body", "").strip().lower().split()
            if len(words) == 2 and words[0] in TEXT_TO_SCOPE and words[1].lstrip("#").isdigit():
                scope = TEXT_TO_SCOPE[words[0]]
                pid = self.short.get(int(words[1].lstrip("#")))
        if pid and scope and not pid.startswith("g:"):
            result = await self._apply(pid, scope, f"matrix:{sender}")
            if result != "ok":
                await self._mx_put(
                    f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                    {"msgtype": "m.notice", "body": f"Could not apply: {result}"},
                )

    async def _mx_grant(self, rid: str, decision: str, sender: str) -> None:
        result = await self._apply_grant(rid, decision, f"matrix:{sender}")
        if result != "ok":
            await self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                {"msgtype": "m.notice", "body": f"Could not apply: {result}"},
            )
        elif decision == "revoke":
            entry = self.gmsgs.pop(rid, None)
            if entry:
                self.short.pop(entry["short"], None)
            await self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                {"msgtype": "m.notice", "body": f"Grant revoked by {sender}"},
            )
