"""Human-in-the-loop notifications: Telegram (inline buttons) and Matrix (reactions or text replies).

Telegram: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ALLOWED_USER_IDS (comma list, required).
Matrix:   MATRIX_HOMESERVER, MATRIX_ACCESS_TOKEN, MATRIX_ROOM_ID, MATRIX_ALLOWED_USERS (comma list, required).
          Use an UNENCRYPTED room (the bot does not do E2EE); host it on your own homeserver.
Web Push: browsers that subscribed in the UI (app/webpush.py); buttons with action tokens (Allow once / Deny
          unless the operator chose others, #212).
ntfy:     NTFY_URL (topic URL), NTFY_TOKEN (optional).  Gotify: GOTIFY_URL, GOTIFY_TOKEN (application token).
Pushover: PUSHOVER_TOKEN (application), PUSHOVER_USER (user or group key).
          These three only notify (with a link to the UI): deciding needs the UI, a chat bot or Web Push.

The bot channels take their settings from the web UI (app/notifyconfig.py, ADR-0018) or, per field, from
the environment variables above; reconfigure() applies a change without a restart.

Two kinds of prompts: connection requests (scopes below) and grant requests (approve / read-only /
deny, then revoke). Both share one short-number space for Matrix text replies.

Which buttons a connection request shows is a setting (#212, notifyconfig.ASK_ACTIONS): ask_buttons() turns
it into the buttons of one request. Web Push offers exactly those, and only Deny buttons for an IP address;
Telegram and Matrix show them first and keep every scope behind "More" (they authenticate the user).
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import ipaddress
import json
import logging
import os
import time
import urllib.parse
import uuid

import aiohttp

from app.notifyconfig import ASK_ACTIONS, NotifyConfig, ask_label

log = logging.getLogger("notify")
QUEUE_SIZE = 1000  # gateway events waiting for delivery; beyond that new events are dropped (logged)
SEND_TIMEOUT = 15  # per chat API call (not the long polls): a hanging API delays later prompts at most this long

REACTIONS = {"once": "👍", "hour": "⏰", "always": "✅", "domain": "🌐", "deny": "👎", "deny_always": "⛔"}
BUTTONS = [(scope, label, REACTIONS[scope]) for scope, (label, _, _) in ASK_ACTIONS.items()]  # + matrix reaction
# What Telegram and Matrix offer first while no buttons were chosen in the UI; the other scopes are behind
# "More" (#121). Once buttons are saved (#212) they are the first choices of these channels too.
PRIMARY = ("once", "always", "deny")
IP_NOTE = "\nIP address: it can only be denied from here. To allow it, open tallygate."
MORE = "More…"
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

# Channel metadata for the Setup UI and the per-channel Test button (#180). The order is the order
# the UI lists them in. CHANNEL_ENV names the environment variables each bot channel needs, shown
# when it is off as the alternative to configuring it in the UI (#201). Web Push is set up per-browser
# in the UI instead and is tested via /api/push/test.
CHANNEL_LABELS = {
    "telegram": "Telegram",
    "matrix": "Matrix",
    "ntfy": "ntfy",
    "gotify": "Gotify",
    "pushover": "Pushover",
    "webpush": "Web Push",
}
CHANNEL_ENV = {
    "telegram": "TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ALLOWED_USER_IDS",
    "matrix": "MATRIX_HOMESERVER, MATRIX_ACCESS_TOKEN, MATRIX_ROOM_ID, MATRIX_ALLOWED_USERS",
    "ntfy": "NTFY_URL",
    "gotify": "GOTIFY_URL, GOTIFY_TOKEN",
    "pushover": "PUSHOVER_TOKEN, PUSHOVER_USER",
}
SOURCE_TEXT = {
    "ui": "Configured in the web UI.",
    "environment": "Configured in the environment.",
    "mixed": "Configured in the web UI and the environment.",
}
POLLS = ("telegram", "matrix")  # channels with a long-lived poll loop (they receive the decisions)
TEST_TITLE = "tallygate test"
TEST_TEXT = "tallygate test notification - this channel is working."


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


def connectivity_text(ev: dict) -> str:
    """The gateway has no connection (or has one again, #218): a fixed text and a time, nothing from the agent."""
    since = ev.get("since")
    if not ev.get("down"):
        return "✅ tallygate: the gateway has a connection again."
    at = time.strftime("%H:%M", time.localtime(since)) if isinstance(since, (int, float)) else "?"
    return (
        f"⚠️ tallygate: no connection from the gateway since {at}. Lookups and connections fail: "
        "a problem of the host's network, not a policy decision."
    )


def context_line(p: dict) -> str:
    """The agent's most recent claim about what it is doing (#74), for the end-to-end encrypted Web Push
    message only: third-party chat services do not get agent-written text from the workspace."""
    ctx = (p.get("context") or [{}])[0]
    what = f"{ctx['tool']}: {ctx['text']}" if ctx.get("tool") and ctx.get("text") else ctx.get("text", "")
    text = " – ".join(x for x in (what, ctx.get("note", "")) if x)
    return f"\nAgent says (unverified): {text[:160]}" if text else ""


def is_ip(host: str) -> bool:
    """An IP literal, as the gateway sees it (egressgw.policy.is_ip): its approval is an address rule."""
    try:
        ipaddress.ip_address(str(host).strip("[]"))
        return True
    except ValueError:
        return False


def ask_buttons(actions, p: dict, deny_only_for_ip: bool = False) -> list[tuple[str, str]]:
    """The buttons of one connection request as (scope, label), from the configured actions, in their order.

    - `domain` only when the gateway names a registrable domain for the host (then it would accept the
      scope), and its label shows the pattern that would be allowed.
    - deny_only_for_ip (Web Push): an IP-literal destination gets no allow button. Its approval is an address
      rule on top of the list, which opens the address even inside a blocked range; that is decided in the
      UI, where the rule list is in view, not from a lock screen."""
    ip = is_ip(p.get("host", ""))
    out = []
    for scope in actions:
        if scope == "domain" and (ip or not p.get("domain")):
            continue
        if deny_only_for_ip and ip and ASK_ACTIONS[scope][2] == "allow":
            continue
        out.append((scope, ask_label(scope, p.get("domain"))))
    return out


class Notifier:
    def __init__(self, app, decide, decide_grant=None, revoke_grant=None, push=None, config=None) -> None:
        self.app = app
        self.push = push  # webpush.WebPush, or None when Web Push is off
        self.decide = decide  # async (pending_id, scope, by) -> (status, data)
        self.decide_grant = decide_grant  # async (request_id, decision, by) -> (status, data)
        self.revoke_grant = revoke_grant  # async (active_id, by) -> (status, data)
        self.gmsgs: dict[str, dict] = {}  # grant request id -> {"tg", "mx", "short", "text", "aid", "expires"}
        self.public_url = os.environ.get("PUBLIC_URL", "")
        self.config: NotifyConfig = config or NotifyConfig(None)  # UI values over the environment (#201)
        self.problems: dict[str, str] = {}  # channel -> why it is off although it has settings
        self._load()
        # pending id -> {"tg": message_id, "mx": event_id, "short": n, "text": str}
        self.msgs: dict[str, dict] = {}
        self.short: dict[int, str] = {}
        self._n = 0
        # Gateway events wait here, so slow chat APIs never block the reader of the gateway stream.
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.tasks: set[asyncio.Task] = set()  # background work outside the worker (Matrix reaction seeding)
        self.worker: asyncio.Task | None = None
        self.polls: dict[str, asyncio.Task] = {}  # channel -> its poll loop (at most one each)
        self._started = False
        self._reconfigure = asyncio.Lock()

    def _load(self) -> None:
        """Read the channel settings: per field the value saved in the UI, else the environment variable.
        Telegram and Matrix decide approvals, so without their allowed users they stay off (ADR-0010)."""
        tg, mx = self.config.effective("telegram"), self.config.effective("matrix")
        ntfy, gotify, po = (self.config.effective(c) for c in ("ntfy", "gotify", "pushover"))
        self.problems = {}
        self.tg_token = tg["bot_token"]
        self.tg_base = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
        self.tg_chat = tg["chat_id"]
        self.tg_users = {u.strip() for u in tg["allowed_user_ids"].split(",") if u.strip()}
        self.mx_hs = mx["homeserver"].rstrip("/")
        self.mx_token = mx["access_token"]
        self.mx_room = mx["room_id"]
        self.mx_users = {u.strip() for u in mx["allowed_users"].split(",") if u.strip()}
        if self.mx_hs and not self.mx_users:
            log.error("the allowed Matrix users (MATRIX_ALLOWED_USERS) are required - Matrix approvals disabled")
            self.mx_hs = ""
            self.problems["matrix"] = "Off: the allowed users are required (only they may decide)."
        self.ntfy_url = ntfy["url"].strip()
        self.ntfy_token = ntfy["token"]
        self.gotify_url = gotify["url"].rstrip("/")
        self.gotify_token = gotify["token"]
        self.po_token = po["token"]
        self.po_user = po["user"]
        self.po_base = os.environ.get("PUSHOVER_API_BASE", "https://api.pushover.net").rstrip("/")
        if self.tg_token and not self.tg_users:
            # In a group chat every member could otherwise press "Allow".
            log.error(
                "the allowed Telegram user ids (TELEGRAM_ALLOWED_USER_IDS) are required - Telegram approvals disabled"
            )
            self.tg_token = ""
            self.problems["telegram"] = "Off: the allowed user ids are required (only they may decide)."

    def describe(self) -> dict:
        return {
            "telegram": bool(self.tg_token and self.tg_chat),
            "matrix": bool(self.mx_hs and self.mx_token and self.mx_room),
            "webpush": bool(self.push and self.push.subs),
            "ntfy": bool(self.ntfy_url),
            "gotify": bool(self.gotify_url and self.gotify_token),
            "pushover": bool(self.po_token and self.po_user),
        }

    def status(self) -> list[dict]:
        """Per-channel detail for the Setup UI (#180, #201): configured?, a short human-readable why,
        where the settings come from (source: ui / environment / mixed / unset; None for Web Push, which is
        subscribed per browser) and whether the UI can configure the channel (configurable: a bot channel
        and the data volume is writable). describe() stays a plain bool map (used internally and by
        /api/meta's "notify" for backward compatibility, see tests/e2e/test_notifications.py)."""
        on = self.describe()
        out: list[dict] = []
        for key, label in CHANNEL_LABELS.items():
            configured = on[key]
            source = None
            if key == "webpush":
                if self.push is None:
                    reason = "Unavailable: the control data volume is not writable."
                elif configured:
                    reason = "Device(s) subscribed in this browser; set up below."
                else:
                    reason = "No device subscribed yet - turn it on below."
            else:
                source = self.config.source(key)
                if configured:
                    reason = SOURCE_TEXT[source]
                elif key in self.problems:
                    reason = self.problems[key]
                elif source != "unset":
                    reason = "Incomplete: a required setting is missing."
                elif self.config.writable:
                    reason = f"Not configured. Use Configure, or set {CHANNEL_ENV[key]} in the environment."
                else:
                    reason = f"Not configured in the environment ({CHANNEL_ENV[key]})."
            out.append(
                {
                    "channel": key,
                    "label": label,
                    "configured": configured,
                    "source": source,
                    "configurable": key != "webpush" and self.config.writable,
                    "reason": reason,
                }
            )
        return out

    def redact(self, msg: str) -> str:
        """Strip channel tokens from an error before it reaches the UI (an aiohttp error can carry the
        request URL, and Telegram/ntfy/Gotify/Pushover put the token in the URL or headers)."""
        for secret in (self.tg_token, self.mx_token, self.ntfy_token, self.gotify_token, self.po_token, self.po_user):
            if secret:
                msg = msg.replace(secret, "<token>")
        return msg

    async def send_test(self, channel: str) -> None:
        """Send a single "tallygate test" notification through one channel and raise on failure (#180).
        Web Push has its own /api/push/test; this covers the outbound-polling bot channels. It reuses
        the same low-level senders as real prompts, so a passing test proves the channel's credentials
        and reachability. Raises ValueError for an unknown or unconfigured channel; the underlying
        senders raise RuntimeError/ClientError when the service rejects the message."""
        if channel not in CHANNEL_LABELS:
            raise ValueError("unknown channel")
        if channel == "webpush":
            raise ValueError("Web Push is tested from the device list (/api/push/test)")
        if not self.describe()[channel]:
            raise ValueError("channel not configured")
        if channel == "telegram":
            await self._tg("sendMessage", chat_id=self.tg_chat, text=TEST_TEXT, disable_web_page_preview=True)
        elif channel == "matrix":
            await self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
                {"msgtype": "m.notice", "body": TEST_TEXT},
            )
        elif channel == "ntfy":
            await self._ntfy(TEST_TITLE, TEST_TEXT, high=False)
        elif channel == "gotify":
            await self._gotify(TEST_TITLE, TEST_TEXT, high=False)
        elif channel == "pushover":
            await self._pushover(TEST_TITLE, TEST_TEXT, high=False)

    def start(self) -> list[asyncio.Task]:
        self._started = True
        self.worker = asyncio.create_task(self._worker())
        for channel in POLLS:
            self._start_poll(channel)
        return [self.worker, *self.polls.values()]

    def _poll_key(self, channel: str) -> tuple | None:
        """Everything a poll loop depends on; None while the channel is off. A loop is restarted exactly
        when this changes."""
        if not self.describe()[channel]:
            return None
        if channel == "telegram":
            return (self.tg_token, self.tg_base, self.tg_chat, frozenset(self.tg_users))
        return (self.mx_hs, self.mx_token, self.mx_room, frozenset(self.mx_users))

    def _start_poll(self, channel: str) -> None:
        if self._poll_key(channel) is not None:
            self.polls[channel] = asyncio.create_task(self._tg_poll() if channel == "telegram" else self._mx_sync())

    async def reconfigure(self) -> list[str]:
        """Apply changed channel settings without a restart (#201). The senders read the new values at
        once. A poll loop is touched only when its own channel changed: the old loop is cancelled and
        awaited before the new one starts, so there is never more than one per channel. The worker, the
        queue and the open prompts (msgs, gmsgs, short numbers) stay, so a prompt that is waiting can
        still be answered. Returns the channels whose poll loop was stopped or (re)started."""
        async with self._reconfigure:
            before = {c: self._poll_key(c) for c in POLLS}
            self._load()
            changed = [c for c in POLLS if self._poll_key(c) != before[c]]
            for channel in changed:
                old = self.polls.pop(channel, None)
                if old:
                    old.cancel()
                    await asyncio.gather(old, return_exceptions=True)
                if self._started:
                    self._start_poll(channel)
            return changed

    def _background(self, coro) -> None:
        """Run coro without holding up the worker (the next prompt must not wait for it); kept until done."""
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    async def close(self) -> None:
        """Cancel background work and wait for it, so nothing uses the HTTP session after it is closed."""
        tasks = [*self.tasks, *self.polls.values(), *([self.worker] if self.worker else [])]
        self.polls, self.worker, self._started = {}, None, False
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
                log.warning("%s: sending %s failed: %s", name, what, self.redact(str(res)))
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
            elif ev["type"] == "connectivity":
                await self._on_connectivity(ev)
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
        entry = {
            "short": self._n,
            "text": _describe(p),
            "expires": p.get("expires", now),
            "host": p.get("host", ""),
            "domain": p.get("domain"),
        }
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
        await self._announce("digest", "tallygate digest", digest_text(ev, self.public_url), 3600)

    async def _on_connectivity(self, ev: dict) -> None:
        """Once when the gateway loses its connection and once when it is back (#218): a notice, no buttons."""
        text = connectivity_text(ev)
        await self._announce(
            "connectivity",
            "tallygate: no connection" if ev.get("down") else "tallygate: connected",
            text,
            3600,
            high=bool(ev.get("down")),
        )

    async def _announce(self, what: str, title: str, text: str, ttl: int, high: bool = False) -> None:
        on = self.describe()
        await self._channels(
            what,
            tg=self._tg("sendMessage", chat_id=self.tg_chat, text=text, disable_web_page_preview=True)
            if on["telegram"]
            else None,
            mx=self._mx_put(
                f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}", {"msgtype": "m.notice", "body": text}
            )
            if on["matrix"]
            else None,
            push=self._push_all(lambda _s: {"title": title, "body": text, "tag": what}, ttl) if on["webpush"] else None,
            **self._plain(title, text, high=high),
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
        """The buttons are the configured ones (#212), in their order; the device shows as many as it can
        (sw.js). A token is minted only for a button that is offered, and it carries its decision."""
        actions = self.config.actions()
        buttons = ask_buttons(actions, p, deny_only_for_ip=True)
        withheld = is_ip(p.get("host", "")) and any(ASK_ACTIONS[a][2] == "allow" for a in actions)

        def make(sub: dict) -> dict:
            def mint(decision: str) -> str:
                return self.push.mint("ask", p["id"], decision, sub["id"], p["expires"])

            return {
                "title": "🔐 tallygate: approval needed",
                "body": f"{_describe(p)}{context_line(p)}{IP_NOTE if withheld else ''}\nAuto-deny in {timeout}s.",
                "tag": f"a{p['id']}",
                "url": "/#approvals",
                "actions": [{"action": scope, "title": label} for scope, label in buttons],
                "tokens": {scope: mint(scope) for scope, _ in buttons},
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

    def _first(self) -> tuple[str, ...]:
        """The scopes Telegram and Matrix offer first: the buttons saved in the UI (#212), else PRIMARY."""
        return tuple(self.config.ask_actions or PRIMARY)

    def _tg_keyboard(self, pid: str, p: dict, full: bool = False) -> dict:
        """The first choices and "More"; `full` is what "More" turns it into: every scope."""
        buttons = ask_buttons([scope for scope, _, _ in BUTTONS] if full else self._first(), p)
        row = [{"text": label, "callback_data": f"d:{pid}:{scope}"} for scope, label in buttons]
        if not full:
            row.append({"text": MORE, "callback_data": f"m:{pid}"})
        return {"inline_keyboard": [row[i : i + 2] for i in range(0, len(row), 2)]}

    async def _tg_send(self, p: dict, timeout: int) -> int:
        text = f"🔐 Agent wants to connect:\n{_describe(p)}\nAuto-deny in {timeout}s."
        if self.public_url:
            text += f"\n{self.public_url}"
        res = await self._tg(
            "sendMessage",
            chat_id=self.tg_chat,
            text=text,
            reply_markup=self._tg_keyboard(p["id"], p),
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
                    elif parts[0] == "m" and len(parts) == 2:  # "More": show every scope on the same message
                        entry = self.msgs.get(parts[1])
                        result = "More choices" if entry else "already decided"
                        if entry:
                            await self._tg(
                                "editMessageReplyMarkup",
                                chat_id=self.tg_chat,
                                message_id=cq.get("message", {}).get("message_id") or entry.get("tg"),
                                reply_markup=self._tg_keyboard(parts[1], entry, full=True),
                            )
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
                log.warning("telegram poll: %s", self.redact(str(e)))
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
        first = ask_buttons(self._first(), p)  # in the configured order (#212)
        shown = {s for s, _ in first}
        legend = "  ".join(f"{REACTIONS[s]} {lbl}" for s, lbl in first)
        rest = ask_buttons([s for s, _, _ in BUTTONS if s not in shown], p)
        more = "  ".join(f"{REACTIONS[s]} {lbl}" for s, lbl in rest)
        body = (
            f"🔐 #{short} Agent wants to connect: {_describe(p)} — auto-deny in {timeout}s.\n"
            f"React: {legend}\nMore: {more}\nor reply: allow|hour|always|domain|deny|block {short}"
        )
        html_body = (
            f"🔐 <b>#{short}</b> Agent wants to connect: <code>{html.escape(_describe(p))}</code>"
            f" — auto-deny in {timeout}s.<br/>React: {html.escape(legend)}<br/>More: {html.escape(more)}<br/>"
            f"or reply: <code>allow|hour|always|domain|deny|block {short}</code>"
        )
        res = await self._mx_put(
            f"/rooms/{self._room()}/send/m.room.message/{uuid.uuid4().hex}",
            {"msgtype": "m.text", "body": body, "format": "org.matrix.custom.html", "formatted_body": html_body},
        )
        event_id = res["event_id"]
        self._background(self._mx_seed(event_id, [REACTIONS[s] for s, _ in first]))
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
