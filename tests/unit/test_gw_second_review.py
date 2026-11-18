"""The second security review of ADR-0019 (docs/security-review.md): what its fixes must hold.

  * F1: an IP address written like a name (`192.168.1.1.`, `127.1`, `2130706433`, `0x7f.1`) is not a name. It
    is refused as an invalid host name in every mode, never asked about, never resolved - and an approval can
    never be the rule that opens a blocked range.
  * F2: whoever replaces the whole policy (PUT, import, restore) is told which address rules are open inside
    the blocked ranges; the log says it at every start.
  * F3: `expires` is a finite number and `host` a text, or the write is refused and nothing changes.
  * F6: an address `deny` is never an "unused rule".

The evaluation itself (F4, the reason text; F5, the embedded IPv4 forms) is in test_gw_rule_list.py."""

import asyncio
import json
import logging
import random
import re
import socket
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from aiohttp.test_utils import TestClient, TestServer

from egressgw import api, core
from egressgw.model import Access
from egressgw.policy import is_ip, valid_hostname

from .test_gw_api import admin
from .test_gw_locked import CONTROL, PUBLIC, TOKEN, connect, connect_and_answer, make  # noqa: F401 (fixture)

AUTH = {"Authorization": f"Bearer {TOKEN}"}
STATIC = Path(__file__).resolve().parents[2] / "control" / "app" / "static"
LAN16, META16 = "block-192.168.0.0_16", "block-169.254.0.0_16"
INVALID = "egress policy: blocked (invalid hostname)"

# An IPv4 address in the spellings that resolvers and browsers read as an address, but `ipaddress` does not
DISGUISED = [
    "192.168.1.1.",  # a trailing dot
    "169.254.169.254.",  # cloud metadata
    "10.0.0.5.",
    "127.1",  # short forms: the last number fills the remaining bytes
    "192.168.257",
    "2130706433",  # one decimal number
    "3232235777",  # 192.168.1.1
    "0x7f.1",  # hex
    "0x7f000001",
    "0XC0.0XA8.1.1",
    "0300.0250.1.1",  # octal
    "017700000001",
    "0x7f.1.",
    f"{PUBLIC}.",  # a public address: not blocked, but still not a name
    f"{CONTROL}.",  # the stack itself
]


def raw(g, method, path, text):
    """A request whose body is sent as written (JSON that `json.dumps` would not produce)."""

    async def go():
        async with TestClient(TestServer(api.build_app(g))) as c:
            r = await c.request(method, path, data=text, headers={**AUTH, "Content-Type": "application/json"})
            return r.status, await r.text()

    return asyncio.run(go())


def state(g, tmp_path):
    """Everything a refused write must leave alone: the policy in force, the file, the versions, the admin log."""
    admins = [e["id"] for e in g.events.recent(200) if e["kind"] == "admin"]
    return g.policy.to_dict(), (tmp_path / "policy.yaml").read_text(), len(g.history.versions(1000)), admins


# ---------------------------------------------------------------- F1: an IP written as a name
MODES = {
    "ask": {"default": "ask"},
    "deny": {"default": "deny"},
    "allow": {"default": "allow"},
    "ask rule for every name": {"default": "deny", "rules": [{"id": "any", "action": "ask", "host": "*"}]},
    "allow rule for every name": {"default": "deny", "rules": [{"id": "any", "action": "allow", "host": "*"}]},
}


@pytest.mark.parametrize("mode", [*MODES, "learning", "away"])
def test_an_ip_written_as_a_name_is_refused_never_asked_about_and_never_resolved(make, tmp_path, mode):  # noqa: F811
    doc = MODES.get(mode, {"default": "deny" if mode == "learning" else "ask"})
    g = make(config={}, policy={"ask_timeout": 5, "seeded": [], "rules": [], **doc})
    if mode == "learning":
        g.start_learning(10, [443, 80], "web:admin")
    if mode == "away":
        g.availability.set_away(True, None, "web:admin")
    before, events = state(g, tmp_path), len(g.events.recent(500))
    for host in DISGUISED:
        for port in (443, 80, 8080):
            t0 = time.time()
            err, resolved, addr = connect(g, host, port, ips=(PUBLIC,))
            assert err == INVALID, (host, port, err)
            assert resolved == [] and addr == (host, port) and time.time() - t0 < 1  # not held for an answer
            assert g.pending == {} and g.verdicts == {}
            ev = g.events.recent(1)[0]
            assert (ev["kind"], ev["action"], ev["reason"], ev["host"], ev["ips"]) == (
                "conn",
                "deny",
                "invalid hostname",
                host,
                [],
            )
    assert state(g, tmp_path) == before  # no rule, no version, no admin event
    assert len(g.events.recent(500)) == events + len(DISGUISED) * 3  # one refusal each, and no "ask"
    assert admin(g, "GET", "/availability")[1]["missed"] == []  # nothing in the digest to allow with one click
    assert admin(g, "GET", "/learning")[1].get("hosts", []) == []
    # the addresses themselves, written as addresses, are decided as before
    for host, port, block in (("192.168.1.1", 443, LAN16), ("169.254.169.254", 80, META16)):
        err, resolved, _ = connect(g, host, port)
        assert err.startswith("egress policy: blocked (") and f"(rule {block}" in err and resolved == [], err
    assert "locked: " in connect(g, CONTROL, 8080)[0]
    assert g.pending == {} and admin(g, "GET", "/availability")[1]["missed"] == []


def test_learning_mode_does_not_cover_an_ip_whatever_its_spelling(make):  # noqa: F811
    """Learning mode lets names through, not IP literals (threat model T39): the dotted form was let through."""
    g = make(config={}, policy={"default": "deny", "seeded": [], "rules": []})
    g.start_learning(10, [443], "web:admin")
    assert connect(g, "new.example")[0] is None and g.events.recent(1)[0]["reason"] == "learning mode"
    assert connect(g, PUBLIC)[0] == "egress policy: blocked (default)"
    for host in (f"{PUBLIC}.", "1572395042", "93.184.55330", "0x5d.0xb8.0xd8.0x22"):
        assert connect(g, host)[0] == INVALID, host
    # mitmproxy hands non-ASCII names over decoded: digits of another script fold to ASCII digits (IDNA)
    for host in ("９３.184.216.34", "93。184。216。34", "９３.１８４.２１６.３４."):
        assert connect(g, host)[0] == INVALID, host
    assert [e["host"] for e in g.events.recent(50) if e["action"] == "allow"] == ["new.example"]


def test_while_you_are_away_only_what_was_really_asked_is_in_the_digest(make):  # noqa: F811
    g = make(config={}, policy={"default": "ask", "ask_timeout": 5, "seeded": [], "rules": []})
    g.availability.set_away(True, None, "web:admin")
    assert connect(g, "192.168.1.1.", 8080)[0] == INVALID
    assert "rule block-192.168.0.0_16" in connect(g, "192.168.1.1", 8080)[0]  # a blocked address is not asked
    assert "away" in connect(g, "new.example", 8080)[0]
    assert "away" in connect(g, "1.2.3.4", 8080)[0]
    missed = admin(g, "GET", "/availability")[1]["missed"]
    assert sorted((m["kind"], m["host"], m["port"]) for m in missed) == [
        ("conn", "1.2.3.4", 8080),
        ("conn", "new.example", 8080),
    ]


def test_allowing_an_address_from_the_digest_takes_a_second_click():
    """`Allow for 1 h` in the away digest posts a rule to /destinations; for an address that is an address
    rule at the top. A text check of the UI code: the address case goes through confirmClick, and the test
    the UI uses for "is an address" is true for every address and for no name the gateway asks about."""
    js = (STATIC / "availability.js").read_text(encoding="utf-8")
    assert 'const address = /^[\\d.]+$/.test(m.host) || m.host.includes(":");' in js
    assert re.search(r"b\.onclick = address\s*\?\s*confirmClick\(b, `Allow the address \$\{what\}\?", js)

    def address(host):  # the same test in Python
        return bool(re.fullmatch(r"[0-9.]+", host)) or ":" in host

    for host in ("1.2.3.4", "192.168.1.1", "fd00::1", "::ffff:10.0.0.5", "2001:db8::1", "[fd00::1]"):
        assert is_ip(host) and address(host)
    for host in ("new.example", "1.example", "a.b.1e3", "xn--bcher-kva.example", "1-2.3-4.example"):
        assert Access.checked_name(host) == host and not address(host)


def spellings(rng):
    """One IPv4 address in a random spelling: 1 to 4 parts, each decimal, hex or octal, perhaps a trailing dot,
    perhaps upper case, perhaps digits and dots of another script (IDNA folds them to ASCII)."""
    octets = [rng.randrange(256) for _ in range(4)]
    parts = rng.randint(1, 4)
    values = [*octets[: parts - 1], int.from_bytes(bytes(octets[parts - 1 :]), "big")]
    forms = (str, hex, lambda v: f"0{v:o}", lambda v: f"0X{v:X}", lambda v: f"00{v}" if v < 8 else str(v))
    text = ".".join(rng.choice(forms)(v) for v in values)
    if rng.random() < 0.4:
        text += "."
    if rng.random() < 0.2:
        text = text.translate(str.maketrans("0123456789.", "０１２３４５６７８９。"))
    elif rng.random() < 0.2:
        text = text.replace(".", rng.choice("。．｡"))
    return text


LABELS = ["a", "example", "x", "0x", "0", "1", "7f", "0x7f", "1e3", "08", "0b1", "0o7", "xn--bcher-kva", "a-1", "_srv",
          "bücher", "пример", "例え", "١٢٣", "１２３", "x１", "127", "0xg", "-a", "a-", "", "x" * 63, "y" * 64]  # fmt: skip
ALPHABET = "0123456789abcdefxX.-_:[]%/ ０１。é"


def names(rng):
    """A random host string: labels from a list that mixes names, numbers and near-numbers, or plain noise."""
    kind = rng.random()
    if kind < 0.6:
        text = ".".join(rng.choice(LABELS) for _ in range(rng.randint(1, 4)))
        return text + rng.choice(["", "", ".", ".."])
    if kind < 0.8:
        return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 18)))
    return rng.choice(["::1", "[::1]", "fd00::1", "::ffff:10.0.0.5", "1.2.3.4", "[1.2.3.4]", "fe80::1%eth0", "::"])


def is_an_address_for_a_resolver(text):
    """What the C library reads as an address: the oracle next to `ipaddress` (which is strict)."""
    for parse in (socket.inet_aton, lambda t: socket.inet_pton(socket.AF_INET6, t)):
        try:
            parse(text)
            return True
        except (OSError, ValueError):
            pass
    return False


@pytest.mark.parametrize("seed", [208, 216, 20261117])
def test_what_is_accepted_as_a_name_is_never_an_address(seed):
    """`valid_hostname` / `checked_name` over generated strings: whatever comes back as a name is not something
    `is_ip` accepts (the approval would become an address rule), nor something a resolver reads as an address."""
    rng = random.Random(seed)  # noqa: S311 - a reproducible test sequence
    accepted = 0
    for i in range(6000):
        text = spellings(rng) if i % 2 else names(rng)
        name = Access.checked_name(text)
        if i % 2:
            assert name is None, f"{text!r} is an IPv4 address and was accepted as the name {name!r}"
        if text.isascii() and valid_hostname(text):
            assert name == text.lower().rstrip("."), text
            assert not is_ip(text) and not is_ip(text.rstrip("."))
        if name is None:
            continue
        accepted += 1
        assert valid_hostname(name) and name == name.lower() and name.isascii() and not name.endswith("."), text
        assert not is_ip(name) and not is_ip(f"[{name}]"), f"{text!r} -> {name!r}"
        assert not is_an_address_for_a_resolver(name), f"{text!r} -> {name!r}"
        last = name.rsplit(".", 1)[-1]
        assert not last.isdigit() and not re.fullmatch(r"0x[0-9a-f]*", last), f"{text!r} -> {name!r}"
        assert not re.fullmatch(r"[0-9.]+", name) and ":" not in name  # the UI's test for "an address"
    assert accepted > 300  # the generator does produce names


@pytest.mark.parametrize(
    "host, name",
    [
        ("Example.COM.", "example.com"),
        ("1.example", "1.example"),  # a number is fine anywhere but in the last label
        ("192.168.1.1.example", "192.168.1.1.example"),
        ("127.0.0.1.nip.example", "127.0.0.1.nip.example"),
        ("x.1e3", "x.1e3"),
        ("0x.example", "0x.example"),
        ("a.0xg", "a.0xg"),  # not a hex number
        ("bücher.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("192.168.1.1.", None),
        ("192.168.1.1..", None),
        ("127.1", None),
        ("1", None),
        ("0x", None),  # "0x" alone is the number 0 for a browser
        ("a.b.0x1f", None),  # the last label decides: resolvers differ on the rest
        ("example.123", None),
        ("example.１２３", None),  # folds to example.123
        ("١٢٣", "xn--9hbcd"),  # digits IDNA does not fold: a name, and no resolver reads it as a number
        ("[::1]", None),
        ("::1", None),
        ("", None),
        (".", None),
    ],
)
def test_names_that_end_in_a_number(host, name):
    assert Access.checked_name(host) == name
    if name is not None:
        assert not is_ip(name) and not is_an_address_for_a_resolver(name)


# ---------------------------------------------------------------- F1: an approval never opens a blocked range
def answered(g, host, port, ips, *bodies):
    """A request as the gateway holds it while it waits for you, answered through the API with each body in
    turn. Returns ([(status, json), ...], the decision the connection got or None if it still waits, what
    GET /pending lists afterwards)."""

    async def go():
        async with TestClient(TestServer(api.build_app(g))) as c:
            task = asyncio.ensure_future(g.ask(host, port, list(ips), "regular", "172.31.10.9"))
            await asyncio.sleep(0.05)
            (p,) = g.pending.values()
            out = []
            for body in bodies:
                r = await c.post(f"/pending/{p.id}/decide", json=body, headers=AUTH)
                out.append((r.status, await r.json()))
            await asyncio.sleep(0.05)
            pending = await (await c.get("/pending", headers=AUTH)).json()
            dec = task.result() if task.done() else None
            if not task.done():  # end the wait as a closed connection would
                task.cancel()
                g.pending.clear()
            return out, dec, pending

    return asyncio.run(asyncio.wait_for(go(), 10))


ALLOWING = [{"scope": "once"}, {"scope": "hour"}, {"scope": "allow", "ttl": 600}, {"scope": "always"}]


@pytest.mark.parametrize(
    "host, block",
    [
        ("192.168.1.1", "192.168.0.0/16"),
        ("169.254.169.254", "169.254.0.0/16"),
        ("fd00::1", "fc00::/7"),
        ("::ffff:10.0.0.5", "10.0.0.0/8"),  # IPv4-mapped: the IPv4 address
        ("64:ff9b::a00:5", "64:ff9b::/96"),
    ],
)
def test_an_approval_for_an_address_inside_a_blocked_range_is_refused(make, tmp_path, host, block):  # noqa: F811
    """Such a request should not exist: a blocked address is refused without a question. If one does (the
    finding: `192.168.1.1.` was asked about as a name), the answer must not be the rule that opens the range."""
    g = make(config={}, policy={"default": "ask", "ask_timeout": 30, "seeded": [], "rules": []})
    before = state(g, tmp_path)
    results, dec, pending = answered(g, host, 443, [], *ALLOWING)
    for status, body in results:
        assert status == 400, body
        assert body["error"].startswith(f"{host} is refused by the list (rule block-") and "an approval cannot open it" in body["error"]
        assert "an approval cannot open it" in body["error"]
    assert dec is None and [p["host"] for p in pending] == [host]  # still waiting: it can be denied
    assert state(g, tmp_path) == before and g.policy.evaluate(host, 443, []).action == "deny"
    assert connect(g, host)[0].startswith("egress policy: blocked (rule block-")
    # denying works, for now or for good, and adds what a denial always adds: a deny rule for the address
    for scope in ("deny", "deny_always"):
        results, dec, pending = answered(g, host, 443, [], {"scope": "once"}, {"scope": scope, "by": "web:admin"})
        assert [s for s, _ in results] == [400, 200] and pending == []
        assert (dec.action, dec.reason) == ("deny", f"{scope} by web:admin")
        top = g.policy.rules[0]
        assert (top.action, top.source, top.port) == ("deny", "approval", 443) and top.cidr.split("/")[0] in (
            host,
            "10.0.0.5",
        )
        assert g.policy.remove_rule(top.id)
    assert g.policy.evaluate(host, 443, []).action == "deny"


def test_an_approval_for_an_address_outside_every_block_still_works(make):  # noqa: F811
    g = make(config={}, policy={"default": "ask", "ask_timeout": 30, "seeded": [], "rules": []})
    results, dec, pending = answered(g, "1.2.3.4", 8080, ["1.2.3.4"], {"scope": "always", "by": "web:admin"})
    assert [s for s, _ in results] == [200] and pending == [] and dec.action == "allow"
    top = g.policy.rules[0]
    assert (top.action, top.cidr, top.port, top.source) == ("allow", "1.2.3.4/32", 8080, "approval")
    assert results[0][1]["rule"]["id"] == top.id
    # a name is approved as a name: the answer is a name rule, which opens no range - nothing to refuse
    results, dec, _ = answered(g, "nas.example", 443, [], {"scope": "always"})
    assert results[0][0] == 200 and g.policy.rules[0].host == "nas.example" and dec.action == "allow"
    assert "inside blocked range" in connect(g, "nas.example", ips=("192.168.1.10",))[0]
    # a block you deleted blocks nothing: the address is then asked about and can be approved
    assert admin(g, "DELETE", f"/destinations/{LAN16}")[0] == 200
    err, _, seen = connect_and_answer(g, "192.168.1.30", 8080, scope="once")
    assert err is None and seen[0]["ips"] == ["192.168.1.30"]
    # an address allow of yours above the block: the address is open, an approval for another port is fine
    g = make(config={}, policy={
        "default": "ask", "ask_timeout": 30, "seeded": [],
        "rules": [{"id": "dev", "action": "allow", "cidr": "192.168.1.10/32", "port": 443}],
    })  # fmt: skip
    results, _, _ = answered(g, "192.168.1.10", 443, ["192.168.1.10"], {"scope": "once"})
    assert results[0][0] == 200
    results, _, _ = answered(g, "192.168.1.10", 22, ["192.168.1.10"], {"scope": "once"})
    assert results[0][0] == 400  # port 22 is not open: the block is the first address rule for it


# ---------------------------------------------------------------- F2: what is open inside the blocked ranges
ABOVE = [
    {"id": "lan", "action": "allow", "cidr": "192.168.1.0/24", "port": 443},
    {"id": "q", "action": "ask", "cidr": "10.0.0.5/32"},
    {"id": "pub", "action": "allow", "cidr": "8.8.8.0/24"},  # in no blocked range
    {"id": "gone", "action": "allow", "cidr": "172.16.0.0/12", "expires": 1},  # expired: no rule
    {"id": "names", "action": "allow", "host": "*"},  # a name rule opens no range
    {"id": "mine", "action": "deny", "cidr": "192.168.1.9/32"},
]
NOTE = "open inside blocked ranges: 10.0.0.5/32 (ask rule q), 192.168.1.0/24 (allow rule lan)"  # in block order


def last_admin(g):
    return next(e["reason"] for e in g.events.recent(20) if e["kind"] == "admin")


def test_replacing_the_policy_says_which_address_rules_are_open_inside_the_blocks(make):  # noqa: F811
    g = make(config={}, policy={"default": "ask", "seeded": [], "rules": []})
    cur = admin(g, "GET", "/policy")[1]
    assert g.opened_note() == ""
    assert admin(g, "PUT", "/policy", cur)[0] == 200 and last_admin(g) == "policy replaced via API"  # nothing to say
    doc = {**cur, "rules": [*ABOVE, *cur["rules"]]}
    # PUT /policy
    assert admin(g, "PUT", "/policy", doc)[0] == 200
    assert last_admin(g) == f"policy replaced via API; {NOTE}"
    assert g.policy.evaluate("192.168.1.1", 443, []).rule_id == "lan"  # it is in force: recorded, not refused
    # an allow for everything is named once, not once for each block it reaches into
    wide = {**cur, "rules": [{"id": "v4", "action": "allow", "cidr": "0.0.0.0/0"}, *cur["rules"]]}
    assert admin(g, "PUT", "/policy", wide)[0] == 200
    assert last_admin(g) == "policy replaced via API; open inside blocked ranges: 0.0.0.0/0 (allow rule v4)"
    # the same rules below the blocks open nothing, and nothing is said
    assert admin(g, "PUT", "/policy", {**cur, "rules": [*cur["rules"], *ABOVE]})[0] == 200
    assert last_admin(g) == "policy replaced via API" and g.policy.evaluate("192.168.1.1", 443, []).action == "deny"
    # import: the preview warns before anything is applied, the event records it afterwards
    text = yaml.safe_dump({"tallygate_export": 1, "policy": doc})
    status, preview = admin(g, "POST", "/policy/import", {"yaml": text})
    assert status == 200 and preview["applied"] is False and preview["warnings"] == [NOTE]
    assert g.policy.evaluate("192.168.1.1", 443, []).action == "deny"
    status, applied = admin(g, "POST", "/policy/import", {"yaml": text, "apply": True})
    assert applied["applied"] is True and applied["warnings"] == [NOTE]
    assert last_admin(g) == f"policy imported (0 UI grants); {NOTE}"
    # together with a deleted block: both notes
    less = {**doc, "rules": [r for r in doc["rules"] if r["id"] != "block-10.0.0.0_8"]}
    status, preview = admin(
        g, "POST", "/policy/import", {"yaml": yaml.safe_dump({"tallygate_export": 1, "policy": less})}
    )
    assert preview["warnings"] == [
        "built-in block(s) not in force in this policy: 10.0.0.0/8",
        "open inside blocked ranges: 192.168.1.0/24 (allow rule lan)",
    ]
    # restore of an earlier version
    assert admin(g, "PUT", "/policy", cur)[0] == 200 and g.opened_note() == ""
    vid = next(v["id"] for v in g.history.versions(50) if v["what"] == "policy imported")
    assert admin(g, "POST", f"/policy/history/{vid}/restore")[0] == 200
    assert last_admin(g) == f"policy version {vid} restored; {NOTE}"
    # a clean import has no warning
    status, preview = admin(
        g, "POST", "/policy/import", {"yaml": yaml.safe_dump({"tallygate_export": 1, "policy": cur})}
    )
    assert preview["warnings"] == []


def test_every_start_logs_which_address_rules_are_open_inside_the_blocks(make, caplog):  # noqa: F811
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(config={}, policy={"default": "ask", "seeded": [], "rules": []})
    assert "open inside blocked ranges" not in caplog.text  # a list without such rules: no warning
    for rule in ABOVE[:2][::-1]:
        assert admin(g, "POST", "/destinations", {"id": rule["id"], "access": rule["action"],
                                                  "match": {k: rule[k] for k in ("cidr", "port") if k in rule}})[0] == 201  # fmt: skip
    caplog.clear()
    with caplog.at_level(logging.WARNING, "egressgw"):
        core.Gateway()  # a restart
    assert [r.getMessage() for r in caplog.records if "open inside" in r.getMessage()] == [f"policy: {NOTE}"]
    # a `never` entry added to the gateway config later is seeded at the bottom: below the address rules that
    # were there before, which keep deciding for their addresses. The start says so
    g = make(config={}, policy={
        "default": "deny", "seeded": [],
        "rules": [{"id": "old", "action": "allow", "cidr": "198.18.7.7/32", "port": 443}],
    })  # fmt: skip
    assert g.policy.remove_rule("block-198.18.0.0_15")
    g.save_policy("test", "the block deleted")
    caplog.clear()
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(config={"never": ["198.18.7.0/24"]})
    assert "blocks seeded as deny rules at the bottom: 198.18.7.0/24" in caplog.text
    assert "policy: open inside blocked ranges: 198.18.7.7/32 (allow rule old)" in caplog.text
    assert connect(g, "198.18.7.7")[0] is None and connect(g, "198.18.7.8")[0] is not None


# ---------------------------------------------------------------- F3: expires is finite, host is a text
NOT_A_TIME = ["NaN", "Infinity", "-Infinity", "1e999", '"soon"', "true", "[1]"]


@pytest.mark.parametrize("value", NOT_A_TIME)
def test_an_expires_that_is_not_a_finite_time_is_refused_and_nothing_changes(make, tmp_path, value):  # noqa: F811
    """The finding: `expires: NaN` in PUT /policy answered 400 with the new policy in force, not saved and not
    recorded - and a rule that never ends."""
    g = make(config={}, policy={
        "default": "ask", "seeded": [], "rules": [{"id": "ok", "action": "allow", "host": "ok.example"}],
    })  # fmt: skip
    before = state(g, tmp_path)
    cur = admin(g, "GET", "/policy")[1]
    opened = {"id": "open", "action": "allow", "cidr": "0.0.0.0/0", "expires": "VALUE"}
    doc = json.dumps({**cur, "default": "allow", "rules": [opened, *cur["rules"]]}).replace('"VALUE"', value)
    status, text = raw(g, "PUT", "/policy", doc)
    assert status == 400 and "rule open: expires must be a unix time or null" in text
    assert state(g, tmp_path) == before
    assert g.policy.default == "ask" and g.policy.evaluate("10.0.0.5", 443, []).action == "deny"
    # a single rule: added and edited
    body = json.dumps({"access": "allow", "match": {"cidr": "10.0.0.5/32"}, "expires": "VALUE"})
    status, text = raw(g, "POST", "/destinations", body.replace('"VALUE"', value))
    assert status == 400 and "expires must be a unix time or null" in text
    for rule in ("ok", "block-10.0.0.0_8"):
        status, text = raw(g, "PATCH", f"/destinations/{rule}", f'{{"expires": {value}}}')
        assert status == 400 and f"rule {rule}: expires must be a unix time or null" in text
    assert state(g, tmp_path) == before
    # the gateway still saves: the next change is stored and recorded as always
    assert admin(g, "POST", "/destinations", {"access": "allow", "match": {"host": "next.example"}})[0] == 201
    assert len(g.history.versions(1000)) == before[2] + 1
    assert core.Gateway().policy.to_dict() == g.policy.to_dict()


def test_an_import_with_an_expires_that_is_not_a_time_is_refused_whole(make, tmp_path):  # noqa: F811
    g = make(config={}, policy={"default": "ask", "seeded": [], "rules": []})
    before = state(g, tmp_path)
    cur = admin(g, "GET", "/policy")[1]
    for value in (float("nan"), float("inf")):  # YAML: .nan and .inf
        rule = {"id": "open", "action": "allow", "cidr": "0.0.0.0/0", "expires": value}
        text = yaml.safe_dump({"tallygate_export": 1, "policy": {**cur, "default": "allow", "rules": [rule]}})
        assert ".nan" in text or ".inf" in text
        for apply in (False, True):
            status, err = admin(g, "POST", "/policy/import", {"yaml": text, "apply": apply})
            assert status == 400 and "rule open: expires must be a unix time or null" in err["error"]
        assert state(g, tmp_path) == before


def test_a_finite_expires_is_still_a_time_limit(make):  # noqa: F811
    g = make(config={}, policy={"default": "deny", "seeded": [], "rules": []})
    soon = time.time() + 3600
    for value in (soon, round(soon), 1e12):
        status, d = admin(
            g, "POST", "/destinations", {"access": "allow", "match": {"host": "t.example"}, "expires": value}
        )
        assert status == 201 and d["expires"] == round(value)
    status, d = admin(g, "POST", "/destinations", {"access": "allow", "match": {"host": "t.example"}, "expires": None})
    assert status == 201 and "expires" not in d


@pytest.mark.parametrize("host", [123, 1.5, True, ["a.example"], {"a": 1}])
def test_a_host_that_is_not_a_text_is_refused_and_nothing_changes(make, tmp_path, host):  # noqa: F811
    g = make(config={}, policy={"default": "ask", "seeded": [], "rules": []})
    before = state(g, tmp_path)
    cur = admin(g, "GET", "/policy")[1]
    doc = {**cur, "default": "allow", "rules": [{"id": "h", "action": "allow", "host": host}, *cur["rules"]]}
    status, err = admin(g, "PUT", "/policy", doc)
    assert status == 400 and err["error"] == "rule h: host must be a text"
    status, err = admin(
        g, "POST", "/policy/import", {"yaml": yaml.safe_dump({"tallygate_export": 1, "policy": doc}), "apply": True}
    )
    assert status == 400 and err["error"] == "rule h: host must be a text"
    # a single rule: refused before a rule is built (today as an internal error, 500, not as a 400)
    status, _ = raw(g, "POST", "/destinations", json.dumps({"access": "allow", "match": {"host": host}}))
    assert status in (400, 500)
    assert state(g, tmp_path) == before
    assert connect(g, "192.168.1.1")[0] is not None  # every evaluation still works


# ---------------------------------------------------------------- F6: an address deny is never unused
def test_a_block_you_edited_and_edited_back_is_never_offered_as_unused(make):  # noqa: F811
    """A block set to `ask` and back to `deny` is your rule from then on (`source: user`). It still blocks its
    range, so "remove unused rules" must not delete it - nor any other address `deny`: a block that never
    matched has done its job."""
    g = make(config={"never": ["203.0.113.7/32"]}, policy={
        "default": "ask", "seeded": [],
        "rules": [
            {"id": "idle", "action": "allow", "host": "idle.example"},
            {"id": "no", "action": "deny", "host": "no.example"},
            {"id": "dev", "action": "allow", "cidr": "192.168.1.10/32", "port": 443},
            {"id": "isp", "action": "deny", "cidr": "198.51.100.0/24", "port": 25},
            {"id": "tmp", "action": "deny", "cidr": "9.9.9.9/32", "expires": time.time() + 3600},
        ],
    })  # fmt: skip
    for block in ("block-10.0.0.0_8", "block-203.0.113.7_32"):
        assert admin(g, "PATCH", f"/destinations/{block}", {"access": "ask"})[0] == 200
        status, d = admin(g, "PATCH", f"/destinations/{block}", {"access": "deny"})
        assert status == 200 and d["source"] == "user"
    g.flush_hits()
    g.events.db.execute("UPDATE rule_hits SET since = 1")  # every rule is old and never matched
    stats = {r["id"]: r for r in admin(g, "GET", "/rules/stats")[1]["rules"]}
    assert sorted(i for i, r in stats.items() if r["stale"]) == ["dev", "idle", "no"]  # name rules, address allows
    assert not any(r["stale"] for r in stats.values() if r.get("cidr") and r["action"] == "deny")
    every = [r.id for r in g.policy.rules]
    status, r = admin(g, "POST", "/rules/cleanup", {"ids": every})
    assert status == 200 and r["removed"] == ["idle", "no", "dev"]
    assert r["kept"] == [i for i in every if i not in ("idle", "no", "dev")]
    left = {x.id: x for x in g.policy.rules}
    assert left["block-10.0.0.0_8"].source == "user" and left["block-203.0.113.7_32"].source == "user"
    assert {"isp", "tmp"} <= set(left) and len(left) == len(every) - 3
    assert g.policy.blocks_missing(g.blocks_builtin, g.blocks_config) == []
    assert connect(g, "10.0.0.5")[0] == "egress policy: blocked (rule block-10.0.0.0_8 (built-in block))"
    g2 = core.Gateway()  # a restart: nothing is seeded again, nothing is lost
    assert g2.policy.to_dict() == g.policy.to_dict() and g2.seeded_now == []
    # a block you turned into an allow or ask is not a block: it can be unused like any rule of yours
    assert admin(g, "PATCH", "/destinations/block-203.0.113.7_32", {"access": "ask"})[0] == 200
    stale = [r["id"] for r in admin(g, "GET", "/rules/stats")[1]["rules"] if r["stale"]]
    assert stale == ["block-203.0.113.7_32"]
