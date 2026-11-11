"""Human-in-the-loop notifications: Telegram (inline buttons) and Matrix (reactions or text replies).

Telegram: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ALLOWED_USER_IDS (comma list, required).
Matrix:   MATRIX_HOMESERVER, MATRIX_ACCESS_TOKEN, MATRIX_ROOM_ID, MATRIX_ALLOWED_USERS (comma list, required).
          Use an UNENCRYPTED room (the bot does not do E2EE); host it on your own homeserver.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import time
import urllib.parse
import uuid

import aiohttp

log = logging.getLogger("notify")

BUTTONS = [  # (scope, label, matrix reaction)
    ("once", "Allow 2 min", "👍"),
    ("hour", "Allow 1 h", "⏰"),
    ("always", "Always (host)", "✅"),
    ("domain", "Always (*.domain)", "🌐"),
    ("deny", "Deny", "👎"),
    ("deny_always", "Block forever", "⛔"),
]
REACTION_TO_SCOPE = {r: s for s, _, r in BUTTONS}
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
    def __init__(self, app, decide) -> None:
        self.app = app
        self.decide = decide  # async (pending_id, scope, by) -> (status, data)
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

    def describe(self) -> dict:
        return {
            "telegram": bool(self.tg_token and self.tg_chat),
            "matrix": bool(self.mx_hs and self.mx_token and self.mx_room),
        }

    def start(self) -> list[asyncio.Task]:
        tasks = []
        if self.describe()["telegram"]:
            tasks.append(asyncio.create_task(self._tg_poll()))
        if self.describe()["matrix"]:
            tasks.append(asyncio.create_task(self._mx_sync()))
        return tasks

    @property
    def http(self) -> aiohttp.ClientSession:
        return self.app["http"]

    # ---------------------------------------------------------------- events from gateway
    async def handle(self, ev: dict) -> None:
        try:
            if ev["type"] == "ask":
                await self._on_ask(ev["pending"])
            elif ev["type"] == "resolved":
                await self._on_resolved(ev)
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
        if self.describe()["telegram"]:
            entry["tg"] = await self._tg_send(p, timeout)
        if self.describe()["matrix"]:
            entry["mx"] = await self._mx_send(p, entry["short"], timeout)

    async def _on_resolved(self, ev: dict) -> None:
        entry = self.msgs.pop(ev["id"], None)
        if not entry:
            return
        self.short.pop(entry["short"], None)
        outcome = (
            f"{ev.get('action')} ({ev.get('scope') or ev.get('reason')}{', by ' + ev['by'] if ev.get('by') else ''})"
        )
        if entry.get("tg"):
            await self._tg(
                "editMessageText",
                chat_id=self.tg_chat,
                message_id=entry["tg"],
                text=f"{'✅' if ev.get('action') == 'allow' else '⛔'} {entry['text']}\n→ {outcome}",
            )
        if entry.get("mx"):
            await self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                {
                    "msgtype": "m.notice",
                    "body": f"#{entry['short']} → {outcome}",
                    "m.relates_to": {"m.in_reply_to": {"event_id": entry["mx"]}},
                },
            )

    async def _apply(self, pid: str, scope: str, by: str) -> str:
        status, data = await self.decide(pid, scope, by)
        if status == 200:
            return "ok"
        return data.get("error", f"error {status}") if isinstance(data, dict) else f"error {status}"

    # ---------------------------------------------------------------- Telegram
    async def _tg(self, method: str, **params):
        async with self.http.post(
            f"{self.tg_base}/bot{self.tg_token}/{method}", json=params, timeout=aiohttp.ClientTimeout(total=40)
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
                    try:
                        _, pid, scope = cq["data"].split(":")
                    except ValueError:
                        continue
                    who = cq["from"].get("username") or uid
                    result = await self._apply(pid, scope, f"telegram:{who}")
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
            timeout=aiohttp.ClientTimeout(total=60),
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
        if pid and scope:
            result = await self._apply(pid, scope, f"matrix:{sender}")
            if result != "ok":
                await self._mx_put(
                    f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                    {"msgtype": "m.notice", "body": f"Could not apply: {result}"},
                )
