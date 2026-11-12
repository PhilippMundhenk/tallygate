"""Human-in-the-loop notifications: Telegram (inline buttons) and Matrix (reactions or text replies).

Telegram: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ALLOWED_USER_IDS (comma list, required).
Matrix:   MATRIX_HOMESERVER, MATRIX_ACCESS_TOKEN, MATRIX_ROOM_ID, MATRIX_ALLOWED_USERS (comma list, required).
          Use an UNENCRYPTED room (the bot does not do E2EE); host it on your own homeserver.
Web Push: browsers that subscribed in the UI (app/webpush.py); Allow 2 min / Deny buttons with action tokens.
ntfy:     NTFY_URL (topic URL), NTFY_TOKEN (optional).  Gotify: GOTIFY_URL, GOTIFY_TOKEN (application token).
Pushover: PUSHOVER_TOKEN (application), PUSHOVER_USER (user or group key).
          These three only notify (with a link to the UI): deciding needs the UI, a chat bot or Web Push.

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


def digest_text(ev: dict, public_url: str = "", limit: int = 20) -> str:
    """The digest: what was refused without asking while the operator was away or in quiet hours."""
    items = ev.get("items") or []
    total = len(items) + int(ev.get("more") or 0)
    lines = [f"📋 tallygate digest ({ev.get('why', 'while away')}): {total} request(s) refused without asking"]
    for i in items[:limit]:
        what = f"grant {i['host']}" if i.get("kind") == "grant" else f"{i['host']}:{i['port']}"
        lines.append(f"  {what}" + (f" ×{i['count']}" if i.get("count", 1) > 1 else ""))
    if total > min(len(items), limit):
        lines.append(f"  … and {total - min(len(items), limit)} more")
    lines.append(
        "Allow what you need in the UI (Approvals → Availability)" + (f": {public_url}" if public_url else ".")
    )
    return "\n".join(lines)


def context_line(p: dict) -> str:
    """The agent's most recent claim about what it is doing (#74), for the end-to-end encrypted Web Push
    message only: third-party chat services do not get agent-written text from the workspace."""
    ctx = (p.get("context") or [{}])[0]
    what = f"{ctx['tool']}: {ctx['text']}" if ctx.get("tool") and ctx.get("text") else ctx.get("text", "")
    text = " – ".join(x for x in (what, ctx.get("note", "")) if x)
    return f"\nAgent says (unverified): {text[:160]}" if text else ""


def _scope_label(scope: str, label: str, p: dict) -> str:
    if scope == "domain":
        return f"Always (*.{p['domain']})" if p.get("domain") else ""
    return label


class Notifier:
    def __init__(self, app, decide, decide_grant=None, revoke_grant=None, push=None) -> None:
        self.app = app
        self.push = push  # webpush.WebPush, or None when Web Push is off
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
        self.ntfy_url = os.environ.get("NTFY_URL", "").strip()
        self.ntfy_token = os.environ.get("NTFY_TOKEN", "")
        self.gotify_url = os.environ.get("GOTIFY_URL", "").rstrip("/")
        self.gotify_token = os.environ.get("GOTIFY_TOKEN", "")
        self.po_token = os.environ.get("PUSHOVER_TOKEN", "")
        self.po_user = os.environ.get("PUSHOVER_USER", "")
        self.po_base = os.environ.get("PUSHOVER_API_BASE", "https://api.pushover.net").rstrip("/")
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
        self.tasks: set[asyncio.Task] = set()  # background work outside the worker (Matrix reaction seeding)

    def describe(self) -> dict:
        return {
            "telegram": bool(self.tg_token and self.tg_chat),
            "matrix": bool(self.mx_hs and self.mx_token and self.mx_room),
            "webpush": bool(self.push and self.push.subs),
            "ntfy": bool(self.ntfy_url),
            "gotify": bool(self.gotify_url and self.gotify_token),
            "pushover": bool(self.po_token and self.po_user),
        }

    def start(self) -> list[asyncio.Task]:
        tasks = [asyncio.create_task(self._worker())]
        if self.describe()["telegram"]:
            tasks.append(asyncio.create_task(self._tg_poll()))
        if self.describe()["matrix"]:
            tasks.append(asyncio.create_task(self._mx_sync()))
        return tasks

    def _background(self, coro) -> None:
        """Run coro without holding up the worker (the next prompt must not wait for it); kept until done."""
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    async def close(self) -> None:
        """Cancel background work and wait for it, so nothing uses the HTTP session after it is closed."""
        tasks = list(self.tasks)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

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
                msg = str(res)
                for secret in (self.tg_token, self.ntfy_token, self.gotify_token, self.po_token):
                    msg = msg.replace(secret, "<token>") if secret else msg
                log.warning("%s: sending %s failed: %s", name, what, msg)
            else:
                ok[name] = res
        return ok

    @staticmethod
    def _expired(ev: dict) -> bool:
        """A prompt for an ask or grant request that already timed out (e.g. after a backlog) is pointless."""
        key = {"ask": "pending", "grant_request": "request"}.get(ev.get("type"))
        item = ev.get(key) if key else None
        exp = item.get("expires") if isinstance(item, dict) else None
        return isinstance(exp, (int, float)) and exp <= time.time()

    async def handle(self, ev: dict) -> None:
        try:
            if self._expired(ev):
                log.info("skipping %s event: expired before it could be sent", ev["type"])
            elif ev["type"] == "ask":
                await self._on_ask(ev["pending"])
            elif ev["type"] == "resolved":
                await self._on_resolved(ev)
            elif ev["type"] == "grant_request":
                await self._on_grant_request(ev["request"], ev.get("grant") or {})
            elif ev["type"] == "grant_resolved":
                await self._on_grant_resolved(ev["request"])
            elif ev["type"] == "digest":
                await self._on_digest(ev)
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
            push=self._push_ask(p, timeout) if on["webpush"] else None,
            **self._plain(
                "tallygate: approval needed", f"🔐 Agent wants to connect:\n{_describe(p)}\nAuto-deny in {timeout}s."
            ),
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
        push = None
        if entry.get("push") and self.push:
            done = {"title": f"{'✅' if ev.get('action') == 'allow' else '⛔'} {entry['text'].splitlines()[0]}"}
            push = self._push_all(
                lambda _s: {**done, "body": f"→ {outcome}", "tag": f"a{ev['id']}", "silent": True}, 600
            )
        await self._channels("outcome", tg=tg, mx=mx, push=push)

    async def _on_digest(self, ev: dict) -> None:
        """One message for everything that was refused while nobody could answer (away / quiet hours, #73)."""
        text = digest_text(ev, self.public_url)
        on = self.describe()
        await self._channels(
            "digest",
            tg=self._tg("sendMessage", chat_id=self.tg_chat, text=text, disable_web_page_preview=True)
            if on["telegram"]
            else None,
            mx=self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}", {"msgtype": "m.notice", "body": text}
            )
            if on["matrix"]
            else None,
            push=self._push_all(lambda _s: {"title": "tallygate digest", "body": text, "tag": "digest"}, 3600)
            if on["webpush"]
            else None,
            **self._plain("tallygate digest", text, high=False),
        )

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
            push=self._push_grant(r, g, text, timeout) if on["webpush"] else None,
            **self._plain("tallygate: grant requested", f"{text}\nAuto-deny in {timeout}s."),
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
        self._background(self._mx_seed(event_id, list(GRANT_REACTIONS)))
        return event_id

    async def _mx_seed(self, event_id: str, reactions: list[str]) -> None:
        """Pre-seed reactions so a single tap answers. Runs in the background: a slow homeserver (up to
        SEND_TIMEOUT per reaction) must not delay the next prompt. Stops at the first failure."""
        for reaction in reactions:
            try:
                await self._mx_put(
                    f"/rooms/{self._room()}/send/m.reaction/{uuid.uuid4().hex}",
                    {"m.relates_to": {"rel_type": "m.annotation", "event_id": event_id, "key": reaction}},
                )
            except Exception:  # noqa: BLE001 - the prompt stands; text replies still work
                return

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
        push = None
        if entry.get("push") and self.push:
            msg = {"title": f"🔑 {r['name']}", "body": f"→ {outcome}", "tag": f"g{r['id']}", "silent": True}
            push = self._push_all(lambda _s: msg, 600)
        await self._channels("grant outcome", tg=tg, mx=mx, push=push)

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

    # ---------------------------------------------------------------- Web Push (#72)
    async def _push_all(self, make, ttl: int, topic: str | None = None) -> int:
        """Send to every subscribed browser (make(sub) -> message; tokens are bound to the subscription).
        Subscriptions the push service no longer knows (404/410) are removed. Raises if none got it."""
        subs = list(self.push.subs)
        results = await asyncio.gather(*(self._push_one(s, make(s), ttl, topic) for s in subs), return_exceptions=True)
        delivered = 0
        for sub, res in zip(subs, results, strict=True):
            if isinstance(res, Exception):
                log.warning("web push to %s failed: %s", sub["label"], res)
            elif res in (404, 410):
                log.info("web push subscription %s has expired: removed", sub["label"])
                self.push.remove(sub["id"])
            elif 200 <= res < 300:
                delivered += 1
            else:
                log.warning("web push to %s: HTTP %s", sub["label"], res)
        if subs and not delivered:
            raise RuntimeError("no browser could be reached")
        return delivered

    async def _push_one(self, sub: dict, message: dict, ttl: int, topic: str | None) -> int:
        url, body, headers = self.push.request(sub, message, ttl, topic)
        async with self.http.post(
            url, data=body, headers=headers, timeout=aiohttp.ClientTimeout(total=SEND_TIMEOUT)
        ) as r:
            return r.status

    async def _push_ask(self, p: dict, timeout: int) -> bool:
        def make(sub: dict) -> dict:
            def mint(decision: str) -> str:
                return self.push.mint("ask", p["id"], decision, sub["id"], p["expires"])

            return {
                "title": "🔐 tallygate: approval needed",
                "body": f"{_describe(p)}{context_line(p)}\nAuto-deny in {timeout}s.",
                "tag": f"a{p['id']}",
                "url": "/#approvals",
                "actions": [{"action": "once", "title": "Allow 2 min"}, {"action": "deny", "title": "Deny"}],
                "tokens": {"once": mint("once"), "deny": mint("deny")},
            }

        await self._push_all(make, timeout, f"a{p['id']}")
        return True

    async def _push_grant(self, r: dict, g: dict, text: str, timeout: int) -> bool:
        """Approve from the notification only at read level: write access needs the UI or a chat bot."""
        if r["level"] == "read":
            actions = [("approve", "Approve read")]
        elif "read" in g.get("levels", []):
            actions = [("read", "Approve read-only")]
        else:
            actions = []
        actions.append(("deny", "Deny"))

        def make(sub: dict) -> dict:
            return {
                "title": f"🔑 tallygate: grant {r['name']} ({r['level']})",
                "body": f"{text}\nAuto-deny in {timeout}s.",
                "tag": f"g{r['id']}",
                "url": "/#approvals",
                "actions": [{"action": d, "title": t} for d, t in actions],
                "tokens": {d: self.push.mint("grant", r["id"], d, sub["id"], r["expires"]) for d, _ in actions},
            }

        await self._push_all(make, timeout, f"g{r['id']}")
        return True

    # ---------------------------------------------------------------- ntfy, Gotify, Pushover (#72)
    def _plain(self, title: str, text: str, high: bool = True) -> dict:
        """Notification-only channels: the same text as Telegram and a link to the UI, no decision buttons
        (an approve link would be an unauthenticated approval)."""
        on = self.describe()
        return {
            "ntfy": self._ntfy(title, text, high) if on["ntfy"] else None,
            "gotify": self._gotify(title, text, high) if on["gotify"] else None,
            "pushover": self._pushover(title, text, high) if on["pushover"] else None,
        }

    async def _post(self, name: str, url: str, **kw) -> None:
        async with self.http.post(url, timeout=aiohttp.ClientTimeout(total=SEND_TIMEOUT), **kw) as r:
            if r.status >= 300:
                raise RuntimeError(f"{name}: HTTP {r.status}")

    async def _ntfy(self, title: str, text: str, high: bool) -> None:
        headers = {"Title": title, "Tags": "lock" if high else "clipboard", "Priority": "high" if high else "default"}
        if self.public_url:
            headers["Click"] = self.public_url
        if self.ntfy_token:
            headers["Authorization"] = f"Bearer {self.ntfy_token}"
        await self._post("ntfy", self.ntfy_url, data=text.encode(), headers=headers)

    async def _gotify(self, title: str, text: str, high: bool) -> None:
        body: dict = {"title": title, "message": text, "priority": 8 if high else 4}
        if self.public_url:
            body["extras"] = {"client::notification": {"click": {"url": self.public_url}}}
        await self._post("gotify", f"{self.gotify_url}/message", json=body, headers={"X-Gotify-Key": self.gotify_token})

    async def _pushover(self, title: str, text: str, high: bool) -> None:
        form = {"token": self.po_token, "user": self.po_user, "title": title, "message": text[:1024]}
        form["priority"] = "1" if high else "0"
        if self.public_url:
            form["url"], form["url_title"] = self.public_url, "Open tallygate"
        await self._post("pushover", f"{self.po_base}/1/messages.json", data=form)

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
        self._background(self._mx_seed(event_id, [reaction for _, _, reaction in BUTTONS]))
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
