"""ADR-0019 in a running gateway: what the rule list means for real connections, grants and the API.

Three things are held here that the pure evaluation tests (test_gw_rule_list.py) cannot show:

  * the locked ranges (the stack's own networks, the gateway's own listeners) stay closed on EVERY path that
    can change what the agent reaches: a rule, a grant, deleting the blocks, PUT /policy, import, restore, the
    raw editor;
  * the seeded blocks are ordinary rules whose deletion survives a restart, and a pre-0019 policy.yaml is
    migrated once, with a backup, or the gateway does not start;
  * the connection flow around the list: deciding on the name first, asking, grants as rules at the top.
"""

import asyncio
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from egressgw import core
from egressgw.policy import LOCKED, Rule

from .test_gw_api import admin

TOKEN = "t" * 32
PRESETS = Path(__file__).resolve().parents[2] / "gateway" / "presets"
STACK = "172.31.10.0/24,172.31.11.0/24"
CONTROL, GW_API = "172.31.11.3", "172.31.11.2"  # the control UI and the gateway's management API
PUBLIC = "93.184.216.34"
GRANTS = {
    "byname": {"targets": [{"host": "ctl.example", "port": 8080, "scheme": "http"}], "levels": ["write"]},
    "byip": {"targets": [{"host": CONTROL, "port": 8080, "scheme": "http"}], "levels": ["write"]},
    "pinned": {"targets": [{"host": "pin.example", "port": 8080, "scheme": "http", "address": CONTROL}], "levels": ["write"]},
    "lanip": {"targets": [{"host": "192.168.1.7", "port": 22, "scheme": "tcp"}], "levels": ["write"]},
    "lanpin": {"targets": [{"host": "nas.example", "port": 443, "address": "192.168.1.8"}]},
    "lanname": {"targets": [{"host": "printer.example", "port": 631, "scheme": "http"}]},
    "meta": {"targets": [{"host": "169.254.169.254", "port": 80, "scheme": "http"}]},
}  # fmt: skip


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "PRESET_DIR", PRESETS)
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    monkeypatch.setenv("GW_INTERNAL_NETS", STACK)
    monkeypatch.setenv("GW_API_HOST", GW_API)
    monkeypatch.setenv("GW_LISTEN_HOST", "172.31.10.2")

    def factory(config: dict | None = None, policy: dict | None = None, text: str | None = None) -> core.Gateway:
        (tmp_path / "config.yaml").write_text(yaml.safe_dump(config if config is not None else {"grants": GRANTS}))
        if text is not None:
            (tmp_path / "policy.yaml").write_text(text)
        elif policy is not None:
            (tmp_path / "policy.yaml").write_text(yaml.safe_dump(policy))
        g = core.Gateway()
        g.api_token = TOKEN
        return g

    return factory


def connect(g, host, port=443, ips=(PUBLIC,), mode="regular"):
    """One connection through the real hook. Returns (error or None, names resolved, server address after)."""
    resolved = []

    async def resolve(h, p):
        resolved.append(h)
        if isinstance(ips, Exception):
            raise ips
        return [h.strip("[]")] if core.is_ip(h) else list(ips)

    g.resolve = resolve
    server = SimpleNamespace(address=(host, port), error=None, id=f"s-{host}-{port}", sni=None)
    client = SimpleNamespace(proxy_mode=SimpleNamespace(type_name=mode), peername=("172.31.10.9", 1))
    asyncio.run(asyncio.wait_for(g.server_connect(SimpleNamespace(server=server, client=client)), 10))
    return server.error, resolved, server.address


def refused_as_locked(g, host, port=8081, ips=(CONTROL,)):
    err, _, _ = connect(g, host, port, ips)
    assert err is not None and "locked: " in err and "the tallygate stack itself" in err, err
    assert f"s-{host}-{port}" not in g.verdicts
    return err


def the_stack_is_closed(g):
    """The agent cannot reach the control plane or the gateway API: by IP, by a name that resolves there, on
    any port; and the gateway's own listeners by their address."""
    for host, port, ips in (
        (CONTROL, 8080, (CONTROL,)),
        (GW_API, 8081, (GW_API,)),
        (f"::ffff:{CONTROL}", 8080, ()),
        ("rebind.example", 443, (PUBLIC, CONTROL)),
        ("ok.example", 443, (GW_API,)),
        ("172.31.10.2", 3128, ()),
    ):
        refused_as_locked(g, host, port, ips)
    for ip in (CONTROL, GW_API, "172.31.10.77"):
        assert g.policy.evaluate(ip, 22, []).rule_id == LOCKED
        assert g.policy.evaluate("x.example", 22, [PUBLIC, ip]).rule_id == LOCKED


EVERYTHING = [
    {"id": "v4", "action": "allow", "cidr": "0.0.0.0/0"},
    {"id": "v6", "action": "allow", "cidr": "::/0"},
    {"id": "names", "action": "allow", "host": "*"},
    {"id": "ctl", "action": "allow", "cidr": f"{CONTROL}/32", "port": 8080},
    {"id": "ok", "action": "allow", "host": "ok.example"},
]
OPEN = {"default": "allow", "seeded": [], "rules": EVERYTHING}


# ---------------------------------------------------------------- locked, on every path
def test_locked_with_an_allow_for_everything_at_the_top(make):
    g = make(policy=OPEN)
    assert [r.id for r in g.policy.rules][:5] == ["v4", "v6", "names", "ctl", "ok"]
    the_stack_is_closed(g)
    assert connect(g, "192.168.1.1")[0] is None  # the allow for everything does open the local network ...
    assert g.events.recent(1, action=["allow"])[0]["reason"] == "rule v4"
    # ... also behind a name - one that is allowed by name: the address rule keeps the address open, no more
    assert connect(g, "x.example", ips=("10.0.0.1",))[0] is None
    assert g.events.recent(1, action=["allow"])[0]["reason"] == "rule names"


def test_locked_after_deleting_every_built_in_block(make):
    g = make(policy={"default": "allow", "seeded": [], "rules": []})
    for r in list(g.policy.rules):
        assert admin(g, "DELETE", f"/destinations/{r.id}")[0] == 200
    assert g.policy.rules == [] and g.policy.default == "allow"
    the_stack_is_closed(g)
    assert connect(g, "127.0.0.1", 9999)[0] is None  # nothing else is blocked any more: the operator's choice
    assert core.Gateway().policy.rules == []  # ... which a restart does not undo
    the_stack_is_closed(core.Gateway())


def test_locked_whatever_is_written_through_the_policy_api(make):
    g = make(policy={"default": "ask", "seeded": [], "rules": []})
    every = g.blocks_builtin
    # PUT /policy: a current-form document that claims every block is seeded and allows everything
    status, pol = admin(g, "PUT", "/policy", {"default": "allow", "seeded": every, "rules": EVERYTHING})
    assert status == 200 and [r["id"] for r in pol["rules"]] == ["v4", "v6", "names", "ctl", "ok"]
    the_stack_is_closed(g)
    # the raw editor: GET /policy, edit, PUT it back
    doc = admin(g, "GET", "/policy")[1]
    doc["rules"].insert(0, {"id": "stack", "action": "allow", "cidr": "172.31.0.0/16"})
    assert admin(g, "PUT", "/policy", doc)[0] == 200 and g.policy.rules[0].id == "stack"
    the_stack_is_closed(g)
    # there is nothing in a policy document that names the lock: unknown keys are refused, ids cannot collide
    for body, error in (
        ({**doc, "locked": []}, "unknown policy keys"),
        ({**doc, "locked_nets": []}, "unknown policy keys"),
        ({**doc, "rules": [{"id": "locked", "action": "allow", "cidr": "172.31.0.0/16"}]}, "invalid rule id"),
    ):
        status, err = admin(g, "PUT", "/policy", body)
        assert status == 400 and error in err["error"]
    # a pre-0019 document: hard_deny emptied, the whole floor "opened"
    old = {"default": "allow", "hard_deny": [], "floor_open": [*every, "172.31.11.0/24"], "rules": EVERYTHING}
    assert admin(g, "PUT", "/policy", old)[0] == 200
    assert not any(r.source == "builtin" for r in g.policy.rules)
    the_stack_is_closed(g)
    # import of an export that allows everything
    text = yaml.safe_dump({"tallygate_export": 1, "policy": {"default": "allow", "seeded": every, "rules": EVERYTHING}})
    assert admin(g, "POST", "/policy/import", {"yaml": text, "apply": True})[1]["applied"] is True
    the_stack_is_closed(g)
    # restore of a version that allows everything (stored by any earlier release)
    vid = g.history.record({"default": "allow", "seeded": every, "rules": EVERYTHING}, "x", "open")
    v_old = g.history.record(old, "x", "old and open")
    for v in (vid, v_old):
        assert admin(g, "POST", f"/policy/history/{v}/restore")[0] == 200
        the_stack_is_closed(g)
    # single rules through the destinations API, the mode, a template, an approval
    for match in ({"cidr": f"{CONTROL}/32"}, {"cidr": "172.31.11.0/24"}, {"host": CONTROL}, {"host": "*"}):
        assert admin(g, "POST", "/destinations", {"match": match, "access": "allow"})[0] == 201
    assert admin(g, "PATCH", "/policy", {"default": "allow"})[0] == 200
    assert admin(g, "POST", "/presets/open")[0] == 200
    g.policy.add_rule(core.rule_for_approval(CONTROL, 8080, "always"))
    g.policy.add_rule(core.rule_for_approval("rebind.example", 443, "always"))
    g.save_policy("test", "approvals")
    the_stack_is_closed(g)
    assert admin(g, "POST", "/test", {"host": CONTROL, "port": 8080})[1]["rule_id"] == LOCKED
    assert core.Gateway().policy.to_dict() == g.policy.to_dict()
    the_stack_is_closed(core.Gateway())


def test_locked_for_grants_whatever_the_target_says(make):
    """A grant is rules at the top of the list - and the locked ranges are checked before the list."""
    g = make(policy=OPEN)
    for name in ("byname", "byip", "pinned"):
        g.grants.activate(name, "write", 600, "", "t")
    # only a name, resolving into the stack. The rules allow every name here, so the rules carry it (grants
    # only add access) - and refuse it; where they do not, the grant carries it - and refuses it
    assert f"(locked: {CONTROL} belongs to the tallygate stack itself" in connect(g, "ctl.example", 8080, (CONTROL,))[0]
    g.policy.remove_rule("names")
    g.policy.default = "deny"
    err, _, _ = connect(g, "ctl.example", 8080, (CONTROL,))
    assert (
        err
        == f"egress policy: blocked (grant byname: locked: {CONTROL} belongs to the tallygate stack itself (172.31.11.0/24))"
    )
    err, resolved, _ = connect(g, CONTROL, 8080)  # an IP literal target (a config-file grant: not checked on save)
    assert f"grant byip: locked: {CONTROL} belongs to the tallygate stack itself" in err and resolved == []
    err, resolved, _ = connect(g, "pin.example", 8080)  # a fixed address
    assert f"grant pinned: locked: {CONTROL} belongs" in err and resolved == []
    assert g.verdicts == {}
    # and no such grant can be defined in the UI at all
    target = {"port": 8080, "scheme": "http"}
    for t, error in (
        ({**target, "host": CONTROL}, "belongs to the tallygate stack itself"),
        ({**target, "host": "x.example", "address": GW_API}, "belongs to the tallygate stack itself"),
        ({**target, "host": "172.31.10.2", "port": 3128}, "belongs to the tallygate stack itself"),
    ):
        status, err = admin(g, "PUT", "/destinations/grant/sneaky", {"targets": [t], "levels": ["write"]})
        assert status == 400 and error in err["error"]

    async def into_the_stack(host, port):
        return [PUBLIC, CONTROL]

    g.resolve = into_the_stack  # a name that resolves into the stack now
    status, err = admin(g, "PUT", "/destinations/grant/sneaky", {"targets": [{**target, "host": "ctl2.example"}]})
    assert status == 400 and f"ctl2.example resolves to {CONTROL}; locked: " in err["error"]
    assert "sneaky" not in g.grants.defs


def test_the_own_listener_is_locked_by_its_port_only(make, monkeypatch):
    monkeypatch.setenv("GW_INTERNAL_NETS", "")
    monkeypatch.setenv("GW_API_HOST", "0.0.0.0")  # bound to every address: loopback reaches it
    monkeypatch.setenv("GW_API_PORT", "9081")
    g = make(
        policy={"default": "allow", "seeded": [], "rules": [{"id": "lo", "action": "allow", "cidr": "127.0.0.0/8"}]}
    )
    for host in ("127.0.0.1", "127.9.9.9", "[::1]", "0.0.0.0"):
        err, _, _ = connect(g, host, 9081)
        assert err is not None and ":9081 is the gateway itself" in err, host
    assert connect(g, "localhost.example", 9081, ips=("127.0.0.1",))[0].endswith(
        "127.0.0.1:9081 is the gateway itself)"
    )
    assert connect(g, "127.0.0.1", 9082)[0] is None  # the operator allowed loopback: another port is not the gateway


# ---------------------------------------------------------------- the seeded blocks are rules
def test_a_fresh_install_has_every_block_and_a_deleted_one_stays_deleted_across_restarts(make, tmp_path):
    g = make(config={"never": ["203.0.113.7/32"]})  # no policy.yaml: the first start (preset baseline)
    blocks = [r for r in g.policy.rules if r.source in ("builtin", "config")]
    assert [r.cidr for r in blocks] == [*g.blocks_builtin, "203.0.113.7/32"] and blocks[-1].source == "config"
    assert g.policy.rules[-len(blocks) :] == blocks and g.policy.rules[0].id == "anthropic"  # below the preset
    assert g.history.versions()[0]["what"] == "initial policy (preset baseline)"
    saved = yaml.safe_load((tmp_path / "policy.yaml").read_text())
    assert saved["seeded"] == [*g.blocks_builtin, "203.0.113.7/32"]
    assert not (tmp_path / "policy.yaml.pre-0019").exists()  # nothing was migrated
    assert connect(g, "192.168.1.1")[0] == "egress policy: blocked (rule block-192.168.0.0_16 (built-in block))"
    # delete one built-in block and the config block; edit another
    assert admin(g, "DELETE", "/destinations/block-192.168.0.0_16")[0] == 200
    assert admin(g, "DELETE", "/destinations/block-203.0.113.7_32")[0] == 200
    assert admin(g, "PATCH", "/destinations/block-10.0.0.0_8", {"access": "ask", "note": "my lab"})[0] == 200
    g2 = core.Gateway()
    cidrs = [r.cidr for r in g2.policy.rules if r.cidr]
    assert "192.168.0.0/16" not in cidrs and "203.0.113.7/32" not in cidrs
    ten = next(r for r in g2.policy.rules if r.id == "block-10.0.0.0_8")
    assert (ten.action, ten.note, ten.source) == ("ask", "my lab", "user")  # no longer the block: your rule
    assert g2.policy.to_dict() == g.policy.to_dict() and g2.seeded_now == []
    assert len(g2.history.versions()) == len(g.history.versions())  # a restart is not a change
    # restore: what is missing, or no longer a block, comes back at the bottom
    g2.api_token = TOKEN
    restored = admin(g2, "POST", "/destinations/restore-blocks")[1]
    added = restored["added"]
    assert [r["cidr"] for r in added] == ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.7/32"]
    # the edited rule still stands above the restored block and keeps the range open for an IP literal: said
    assert restored["opened"] == [
        {"rule": "block-10.0.0.0_8", "action": "ask", "cidr": "10.0.0.0/8", "block": "10.0.0.0/8"}
    ]
    assert [r.cidr for r in core.Gateway().policy.rules[-3:]] == ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.7/32"]
    assert connect(core.Gateway(), "192.168.1.1")[0] is not None


def test_a_never_entry_added_to_the_config_later_is_seeded_once(make, tmp_path, caplog):
    g = make(
        config={}, policy={"default": "deny", "seeded": [], "rules": [{"id": "n", "action": "allow", "host": "*"}]}
    )
    n = len(g.policy.rules)
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(config={"never": ["8.8.8.0/24", {"range": "9.9.9.9", "scope": "all+lan"}]})
    assert "blocks seeded as deny rules at the bottom: 8.8.8.0/24, 9.9.9.9/32" in caplog.text
    assert [(r.cidr, r.source) for r in g.policy.rules[n:]] == [("8.8.8.0/24", "config"), ("9.9.9.9/32", "config")]
    assert connect(g, "dns.example", ips=("8.8.8.8",))[0] is not None
    assert "9.9.9.9/32" in yaml.safe_load((tmp_path / "policy.yaml").read_text())["seeded"]  # written at once
    assert admin(g, "DELETE", "/destinations/block-8.8.8.0_24")[0] == 200
    g = make(config={"never": ["8.8.8.0/24", "9.9.9.9"]})
    assert "8.8.8.0/24" not in [r.cidr for r in g.policy.rules] and g.seeded_now == []  # deleted: not again
    g = make(config={"never": ["9.9.9.9"]})  # taken out of the config: its rule stays, the memory goes ...
    g = make(config={"never": ["8.8.8.0/24", "9.9.9.9"]})  # ... so putting it back blocks it again
    assert [r.cidr for r in g.policy.rules[-1:]] == ["8.8.8.0/24"]


# ---------------------------------------------------------------- migration of policy.yaml
PRE_0019 = {
    "default": "ask",
    "ask_timeout": 30,
    "never": [{"range": "203.0.113.7/32", "scope": "all"}],
    "floor_open": ["192.168.0.0/16"],
    "destinations": [
        {"match": {"host": "ok.example"}, "access": "allow", "id": "ok"},
        {"match": {"cidr": "192.168.1.10/32", "port": 8123}, "access": "allow", "id": "ha"},
        {"match": {"cidr": "10.0.0.5/32"}, "access": "allow", "id": "dead"},
        {"match": {"cidr": "8.8.8.0/24"}, "access": "deny", "id": "net", "note": "no dns"},
    ],
}


def test_a_pre_0019_policy_file_is_migrated_once_with_a_backup_and_a_log(make, tmp_path, caplog):
    text = yaml.safe_dump(PRE_0019)
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(config={"never": ["198.18.7.0/24"]}, text=text)
    # the old file is kept, byte for byte
    assert (tmp_path / "policy.yaml.pre-0019").read_text() == text and not (tmp_path / "policy.yaml.pre-0014").exists()
    # CIDR denies on top, then the block an old address allow reaches into (10/8, for `dead`); the hard_deny
    # extra below the rules; every other block at the bottom except the opened range
    ids = [r.id for r in g.policy.rules]
    assert ids[:6] == ["net", "block-10.0.0.0_8", "ok", "ha", "dead", "block-203.0.113.7_32"]
    assert g.policy.rules[1].source == "builtin"
    blocks = [r.cidr for r in g.policy.rules[6:]]
    assert blocks == [c for c in [*g.blocks_builtin, "198.18.7.0/24"] if c not in ("192.168.0.0/16", "10.0.0.0/8")]
    saved = yaml.safe_load((tmp_path / "policy.yaml").read_text())
    assert set(saved) == {"default", "ask_timeout", "seeded", "destinations"} and saved["ask_timeout"] == 30
    assert saved["seeded"][:2] == ["192.168.0.0/16", "10.0.0.0/8"]
    assert set(saved["seeded"]) == {*g.blocks_builtin, "198.18.7.0/24"} and len(saved["seeded"]) == len(blocks) + 2
    assert [d["id"] for d in saved["destinations"]] == ids
    # what was decided before is decided now
    assert connect(g, "8.8.8.8")[0] == "egress policy: blocked (rule net (no dns))"
    assert "inside blocked range 8.8.8.0/24 (rule net)" in connect(g, "ok.example", ips=("8.8.8.8",))[0]
    assert connect(g, "192.168.1.10", 8123)[0] is None  # the range was open and the rule allowed it
    assert "(rule block-203.0.113.7_32)" in connect(g, "ok.example", ips=("203.0.113.7",))[0]
    assert "rule block-10.0.0.0_8" in connect(g, "ok.example", ips=("10.9.9.9",))[0]
    # the old allow inside the blocked range opened nothing before and opens nothing now
    assert connect(g, "10.0.0.5")[0] == "egress policy: blocked (rule block-10.0.0.0_8 (built-in block))"
    assert "rule block-10.0.0.0_8" in connect(g, "ok.example", ips=("10.0.0.5",))[0]
    assert g.opened_above() == []  # nothing is open inside a block in force (192.168/16 is not in force)
    # the log says what changed - in the container log and in the event log the operator reads
    log = caplog.text
    assert "migrated" in log and "to one ordered rule list (ADR-0019); the old file is kept as *.pre-0019" in log
    assert "policy migration: moved 1 CIDR deny rule(s) to the top: net" in log
    assert "policy migration: hard_deny 203.0.113.7/32 is now deny rule block-203.0.113.7_32" in log
    assert "policy migration: not blocked, as before (floor_open): 192.168.0.0/16" in log
    note = (
        "NOTE 1 block(s) stay at the top of the list, above rule(s) dead: these address rules had no effect inside "
        "the blocked ranges and still have none. To open an address, move its rule above the block. "
        "Blocks: 10.0.0.0/8"
    )
    assert f"policy migration: {note}" in log and "it now decides" not in log
    ev = g.events.recent(1, kind=["admin"])[0]
    assert (
        ev["action"] == "policy"
        and "policy.yaml migrated to one ordered rule list (ADR-0019): moved 1 CIDR" in ev["reason"]
        and note in ev["reason"]
    )
    assert g.history.versions()[0]["what"] == "policy migrated to one ordered rule list (ADR-0019)"
    # the second start: nothing to do, the backup is not touched, no second version
    (tmp_path / "policy.yaml.pre-0019").write_text("the first backup")
    caplog.clear()
    with caplog.at_level(logging.WARNING, "egressgw"):
        g2 = core.Gateway()
    assert "migrat" not in caplog.text and "seeded" not in caplog.text
    assert g2.policy.to_dict() == g.policy.to_dict() and len(g2.history.versions()) == 1
    assert (tmp_path / "policy.yaml.pre-0019").read_text() == "the first backup"
    assert g2.events.recent(1, kind=["admin"])[0]["id"] == ev["id"]


def test_the_migration_names_the_grant_targets_that_start_working(make, tmp_path, caplog):
    """A grant target that names an address inside a blocked range and had no `lan` flag was refused before
    and is reachable through its grant now: said in the container log and in the migration's admin event."""
    grants = {
        "nolan": {"targets": [{"host": "192.168.1.7", "port": 22, "scheme": "tcp"}], "levels": ["write"]},
        "waslan": {"targets": [{"host": "192.168.1.8", "port": 22, "scheme": "tcp", "lan": True}], "levels": ["write"]},
        "pinned": {"targets": [{"host": "nas.example", "port": 443, "address": "10.0.0.9"}], "approval": "auto"},
        "byname": {"targets": [{"host": "printer.example", "port": 631, "scheme": "http"}]},
        "open": {"targets": [{"host": "169.254.169.254", "port": 80, "scheme": "http"}]},
    }
    old = {
        "default": "ask",
        "floor_open": ["169.254.0.0/16"],
        "rules": [{"id": "ok", "action": "allow", "host": "ok.example"}],
    }
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(config={"grants": grants}, text=yaml.safe_dump(old))
    nolan = (
        "NOTE grant nolan: target 192.168.1.7:22 names the address 192.168.1.7 inside blocked range 192.168.0.0/16. "
        "It was refused before; now it is reachable while the grant is active. Delete the target if that is not wanted"
    )
    pinned = (
        "NOTE grant pinned: target nas.example:443 names the address 10.0.0.9 inside blocked range 10.0.0.0/8. "
        "It was refused before; now it is reachable while the grant is active (approval for read is automatic). "
        "Delete the target if that is not wanted"
    )
    reason = g.events.recent(1, kind=["admin"])[0]["reason"]
    assert reason == (
        "policy.yaml migrated to one ordered rule list (ADR-0019): not blocked, as before (floor_open): "
        f"169.254.0.0/16; {nolan}; {pinned}"
    )
    assert f"grants: {nolan}" in caplog.text and f"grants: {pinned}" in caplog.text
    for name in ("waslan", "byname", "open"):  # had `lan`; only a name; in a range that was open
        assert f"NOTE grant {name}" not in reason and f"NOTE grant {name}" not in caplog.text
    # the note is true: through the active grant the address is reachable now
    assert "rule block-192.168.0.0_16" in connect(g, "192.168.1.7", 22)[0]
    g.grants.activate("nolan", "write", 600, "", "t")
    assert connect(g, "192.168.1.7", 22)[0] is None
    # the next start has nothing to migrate and says nothing
    caplog.clear()
    with caplog.at_level(logging.WARNING, "egressgw"):
        g2 = core.Gateway()
    assert "NOTE grant" not in caplog.text and g2.events.recent(1, kind=["admin"])[0]["reason"] == reason


def test_a_start_without_the_stacks_networks_is_a_warning_in_the_log(make, monkeypatch, caplog):
    monkeypatch.setenv("GW_INTERNAL_NETS", "")
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(policy={"default": "allow", "seeded": [], "rules": []})
    errors = [
        r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "GW_INTERNAL_NETS" in r.getMessage()
    ]
    assert len(errors) == 1 and errors[0].startswith("GW_INTERNAL_NETS is empty: no network of the stack is locked.")
    assert g.policy.locked_nets == []
    # what the message warns of: only the block stands in the way, and it can be deleted
    assert "rule block-172.16.0.0_12" in connect(g, CONTROL, 8080)[0]
    assert admin(g, "DELETE", "/destinations/block-172.16.0.0_12")[0] == 200
    assert connect(g, CONTROL, 8080)[0] is None
    assert ":8081 is the gateway itself" in connect(g, GW_API, 8081)[0]  # the own listeners stay locked


def test_a_pre_0014_file_goes_through_both_migrations(make, tmp_path):
    old = {
        "default": "deny",
        "hard_deny": ["203.0.113.7/32", "10.0.0.0/8"],
        "rules": [
            {"id": "gh", "action": "allow", "host": "*.github.com"},
            {"id": "d", "action": "deny", "cidr": "140.82.112.0/20"},
        ],
    }
    g = make(config={}, text=yaml.safe_dump(old))
    assert (tmp_path / "policy.yaml.pre-0014").exists() and (tmp_path / "policy.yaml.pre-0019").exists()
    assert [r.id for r in g.policy.rules][:3] == ["d", "gh", "block-203.0.113.7_32"]
    assert [r.cidr for r in g.policy.rules[3:]] == g.blocks_builtin
    # the CIDR deny wins against the name allow as before; the reason now names both rules
    assert connect(g, "api.github.com", ips=("140.82.112.3",))[0] == (
        "egress policy: blocked (name allowed by rule gh, but it resolves to 140.82.112.3, inside blocked range "
        "140.82.112.0/20 (rule d): add an allow for the address above that rule)"
    )
    assert connect(g, "140.82.112.3")[0] == "egress policy: blocked (rule d)"


@pytest.mark.parametrize(
    "text, error",
    [
        (yaml.safe_dump({"default": "ask", "hard_deny": ["nope"]}), "hard_deny: invalid CIDR"),
        (yaml.safe_dump({**PRE_0019, "floor_open": "192.168.0.0/16"}), "floor_open: expected a list"),
        (yaml.safe_dump({**PRE_0019, "never": [{"scope": "all"}]}), "hard_deny: invalid CIDR None"),
        (yaml.safe_dump({**PRE_0019, "bogus": 1}), "unknown policy keys"),
        (yaml.safe_dump({"default": "ask", "seeded": ["x"], "destinations": []}), "seeded: invalid CIDR"),
        (yaml.safe_dump({"default": "ask", "rules": [{"action": "deny", "cidr": "10.0.0.0/33"}]}), "invalid cidr"),
        (yaml.safe_dump(["not", "a", "policy"]), "expected a mapping"),
        ("default: [unclosed", "while parsing"),
    ],
)
def test_a_policy_that_cannot_be_migrated_stops_the_gateway_and_is_left_alone(make, tmp_path, text, error):
    """Fail closed (ADR-0014 §5): no half-migrated policy, no start with a default policy instead."""
    with pytest.raises((ValueError, yaml.YAMLError), match=error):
        make(config={}, text=text)
    assert (tmp_path / "policy.yaml").read_text() == text
    assert not (tmp_path / "policy.yaml.pre-0019").exists()


def test_a_backup_that_cannot_be_written_stops_the_gateway_before_anything_changes(make, tmp_path, monkeypatch):
    text = yaml.safe_dump(PRE_0019)

    def no_space(path, data):
        raise OSError("No space left on device")

    monkeypatch.setattr(core, "atomic_write", no_space)
    with pytest.raises(OSError, match="No space left"):
        make(config={}, text=text)
    assert (tmp_path / "policy.yaml").read_text() == text


# ---------------------------------------------------------------- grants as rules at the top
def test_grants_with_ip_pinned_and_name_only_local_targets(make):
    g = make(policy={"default": "deny", "seeded": [], "rules": []})
    for name in ("lanip", "lanpin", "lanname", "meta"):
        g.grants.activate(name, "write" if name == "lanip" else "read", 600, "", "t")
    # an IP literal target: an address rule at the top - the local address is reachable through the grant
    err, resolved, addr = connect(g, "192.168.1.7", 22)
    assert err is None and resolved == [] and addr == ("192.168.1.7", 22)
    assert g.events.recent(1)[0]["reason"] == "grant lanip (write)"
    assert "rule block-192.168.0.0_16" in connect(g, "192.168.1.7", 23)[0]  # only that port
    assert "rule block-192.168.0.0_16" in connect(g, "192.168.1.9", 22)[0]  # only that address
    # a fixed address: the same, and the name is never resolved
    err, resolved, addr = connect(g, "nas.example", 443, ips=("8.8.8.8",))
    assert err is None and resolved == [] and addr == ("192.168.1.8", 443)
    # only a name: a name rule at the top - it cannot open the blocked range it resolves into
    err, resolved, _ = connect(g, "printer.example", 631, ips=("192.168.1.50",))
    assert resolved == ["printer.example"] and err == (
        "egress policy: blocked (grant lanname: name allowed by the grant, but it resolves to 192.168.1.50, inside "
        "blocked range 192.168.0.0/16 (rule block-192.168.0.0_16): set a fixed address on the grant target)"
    )
    assert connect(g, "printer.example", 631, ips=(PUBLIC,))[0] is None  # a public address: fine
    assert connect(g, "printer.example", 631, ips=(PUBLIC, "10.0.0.1"))[0] is not None  # one blocked address is enough
    # an address ask above the block opens nothing for a name (it is a question about the IP literal) ...
    g.policy.add_rule(Rule(action="ask", cidr="192.168.1.50/32", id="q"))
    assert "rule block-192.168.0.0_16" in connect(g, "printer.example", 631, ips=("192.168.1.50",))[0]
    # ... an address allow above the block does: the first address rule with allow or deny says the address is
    # open, for a name-only grant target as for a name rule
    g.policy.add_rule(Rule(action="allow", cidr="192.168.1.50/32", port=631, id="p"), top=False)
    assert connect(g, "printer.example", 631, ips=("192.168.1.50",))[0] is None
    assert "rule block-192.168.0.0_16" in connect(g, "printer.example", 631, ips=("192.168.1.50", "192.168.1.51"))[0]
    # a block ABOVE that allow closes it again: the first of the two decides
    g.policy.add_rule(Rule(action="deny", cidr="192.168.1.48/29", id="cam"))
    assert "(rule cam)" in connect(g, "printer.example", 631, ips=("192.168.1.50",))[0]
    assert g.policy.remove_rule("cam") and g.policy.remove_rule("p")
    assert connect(g, "printer.example", 631, ips=("192.168.1.50",))[0] is not None
    # deleting the block opens it for the name too
    g.policy.remove_rule("block-192.168.0.0_16")
    assert connect(g, "printer.example", 631, ips=("192.168.1.50",))[0] is None
    # an address target reaches what the built-in blocks close for everything else, metadata included: that is
    # what "handled like any other address" means, and why defining a grant needs the UI session or the file
    assert connect(g, "169.254.169.254", 80)[0] is None
    assert connect(g, "169.254.169.254", 8080)[0] is not None
    # without the active grant nothing of this is reachable
    for a in list(g.grants.active.values()):
        g.grants.revoke(a.id)
    for host, port in (("192.168.1.7", 22), ("nas.example", 443), ("169.254.169.254", 80)):
        assert connect(g, host, port, ips=("192.168.1.8",))[0] is not None


def test_saving_a_name_only_target_that_resolves_into_a_block_is_refused_with_the_address_to_pin(make):
    g = make(config={}, policy={"default": "ask", "seeded": [], "rules": []})
    answers = {"ha.lan": ["192.168.1.20"], "api.example": [PUBLIC], "two.example": [PUBLIC, "10.0.0.9"]}

    async def resolve(host, port):
        if host not in answers:
            raise OSError("nxdomain")
        return answers[host]

    g.resolve = resolve
    ha = {"targets": [{"host": "ha.lan", "port": 8123, "scheme": "http"}]}
    status, err = admin(g, "PUT", "/destinations/grant/ha", ha)
    assert status == 400 and err["error"] == (
        "grant ha: ha.lan resolves to 192.168.1.20, inside blocked range 192.168.0.0/16 (rule block-192.168.0.0_16). "
        "A target that is only a name cannot open a blocked range: set the fixed address 192.168.1.20 on this target "
        "(or use the IP as its host)"
    )
    assert "ha" not in g.grants.defs and not (core.DATA_DIR / "grants.yaml").exists()
    # the same through the other two ways to define a grant
    dest = {"match": {"host": "ha.lan", "port": 8123}, "access": "request", "scheme": "http", "request": {"name": "ha"}}
    assert "set the fixed address 192.168.1.20" in admin(g, "POST", "/destinations", dest)[1]["error"]
    doc = yaml.safe_dump({"tallygate_export": 1, "policy": admin(g, "GET", "/policy")[1], "grants": {"ha": ha}})
    status, err = admin(g, "POST", "/policy/import", {"yaml": doc, "apply": True})
    assert status == 400 and "set the fixed address 192.168.1.20" in err["error"] and "ha" not in g.grants.defs
    status, err = admin(g, "PUT", "/destinations/grant/two", {"targets": [{"host": "two.example", "port": 443}]})
    assert status == 400 and "two.example resolves to 10.0.0.9, inside blocked range 10.0.0.0/8" in err["error"]
    # doing what the message says works: the fixed address, or the IP as the host
    pinned = {"targets": [{"host": "ha.lan", "port": 8123, "scheme": "http", "address": "192.168.1.20"}]}
    assert admin(g, "PUT", "/destinations/grant/ha", pinned)[0] == 200
    lit = {"targets": [{"host": "192.168.1.20", "port": 8123, "scheme": "http"}]}
    assert admin(g, "PUT", "/destinations/grant/ha2", lit)[0] == 200
    local = {d["name"]: [t["local"] for t in d["targets"]] for d in admin(g, "GET", "/grants")[1]["defs"]}
    assert local == {"ha": [True], "ha2": [True]} and "lan_allow_ui" not in admin(g, "GET", "/grants")[1]
    # editing it back to a name only is refused as well (PATCH), and the stored grant stays
    edit = {**dest, "request": {"name": "ha", "levels": ["read"]}}
    status, err = admin(g, "PATCH", "/destinations/grant:ha", edit)
    assert status == 400 and "set the fixed address" in err["error"] and g.grants.defs["ha"].targets[0].address
    # names that resolve to public addresses, that do not resolve now, and wildcards are accepted: every
    # connection is checked again when it is made
    for name, host in (("pub", "api.example"), ("later", "not-yet.example"), ("wild", "*.lan.example")):
        assert admin(g, "PUT", f"/destinations/grant/{name}", {"targets": [{"host": host, "port": 443}]})[0] == 200
    # once the operator deleted the block, the name is fine
    g.policy.remove_rule("block-192.168.0.0_16")
    assert admin(g, "PUT", "/destinations/grant/ha3", ha)[0] == 200
    # import: the grants are checked against the policy that is being imported, not the one in force
    g.grants.delete_ui("ha3")
    status, _ = admin(g, "POST", "/policy/import", {"yaml": doc, "apply": True})  # that export has the block
    assert status == 400 and "ha" in g.grants.defs and "ha3" not in g.grants.defs


# ---------------------------------------------------------------- the connection flow around the list
def test_denied_and_unapproved_names_are_not_resolved_and_allowed_ones_are_checked_by_address(make):
    g = make(config={}, policy={
        "default": "deny", "seeded": [],
        "rules": [
            {"id": "bad", "action": "deny", "host": "*.evil.example"},
            {"id": "ok", "action": "allow", "host": "ok.example"},
        ],
    })  # fmt: skip
    err, resolved, _ = connect(g, "x.evil.example")
    assert err == "egress policy: blocked (rule bad (not resolved))" and resolved == []
    err, resolved, _ = connect(g, "new.example")
    assert err == "egress policy: blocked (default (not resolved))" and resolved == []
    err, resolved, addr = connect(g, "ok.example")
    assert err is None and resolved == ["ok.example"] and addr == (PUBLIC, 443)  # pinned to the checked address
    # the name is allowed, the address is not: denied with the reason that says why and what to do
    err, _, _ = connect(g, "ok.example", ips=(PUBLIC, "192.168.1.10"))
    assert err == (
        "egress policy: blocked (name allowed by rule ok, but it resolves to 192.168.1.10, inside blocked range "
        "192.168.0.0/16 (rule block-192.168.0.0_16): add an allow for the address above that rule)"
    )
    ev = g.events.recent(1)[0]
    assert ev["action"] == "deny" and ev["reason"] == err[len("egress policy: blocked (") : -1]  # in the log too
    assert g.shadow_stats()["ok"]["count"] == 1 and g.hits["block-192.168.0.0_16"][0] == 1
    # doing what it says: the address is allowed for that port. That opens the address for the name that is
    # allowed by name - and for no other name: those are still decided before they are resolved (amendment)
    assert (
        admin(g, "POST", "/destinations", {"match": {"cidr": "192.168.1.10/32", "port": 443}, "access": "allow"})[0]
        == 201
    )
    assert connect(g, "ok.example", ips=("192.168.1.10",))[0] is None
    assert g.events.recent(1, action=["allow"])[0]["reason"] == "rule ok"
    assert connect(g, "192.168.1.10")[0] is None  # ... and for the IP literal
    err, resolved, _ = connect(g, "new.example", ips=("192.168.1.10",))
    assert err == "egress policy: blocked (default (not resolved))" and resolved == []
    err, resolved, _ = connect(g, "x.evil.example", ips=("192.168.1.10",))
    assert err == "egress policy: blocked (rule bad (not resolved))" and resolved == []
    assert connect(g, "new.example", 8443)[1] == []  # on other ports nothing changed either
    assert connect(g, "ok.example", ips=OSError("nxdomain"))[0] == "egress policy: blocked (dns failure: nxdomain)"
    assert connect(g, "ok.example", ips=())[0] == "egress policy: blocked (no address)"


def test_after_an_ip_literal_was_approved_denied_and_unknown_names_are_still_not_resolved(make):
    """ADR-0011, the finding of the security review: one address allow for a port at the top must not make the
    gateway resolve every name the agent asks for on that port (DNS exfiltration)."""
    g = make(config={}, policy={
        "default": "ask", "ask_timeout": 5, "seeded": [],
        "rules": [{"id": "bad", "action": "deny", "host": "*.evil.example"}],
    })  # fmt: skip
    err, _, seen = connect_and_answer(g, "140.82.112.3")  # the operator approves one IP literal on 443
    top = g.policy.rules[0]
    assert err is None and seen[0]["ips"] == ["140.82.112.3"]
    assert (top.action, top.cidr, top.port, top.source) == ("allow", "140.82.112.3/32", 443, "approval")
    # a denied name: refused on the name, never resolved - also when it would resolve to the approved address
    err, resolved, _ = connect(g, "secret-data.evil.example", ips=("140.82.112.3",))
    assert err == "egress policy: blocked (rule bad (not resolved))" and resolved == []
    # an unknown name: asked about on the name alone, and not resolved when the answer is no
    err, resolved, seen = connect_and_answer(g, "secret-data.unknown.example", ips=("140.82.112.3",), scope="deny")
    assert seen[0]["ips"] == [] and resolved == []
    assert err == "egress policy: blocked (deny by web:admin (not resolved))"
    # in deny mode nobody is asked, and nothing is resolved
    assert admin(g, "PATCH", "/policy", {"default": "deny"})[0] == 200
    err, resolved, _ = connect(g, "other.unknown.example", ips=("140.82.112.3",))
    assert err == "egress policy: blocked (default (not resolved))" and resolved == [] and g.pending == {}
    # the same with an allow for every address on every port at the top
    g.policy.add_rule(Rule(action="allow", cidr="0.0.0.0/0", id="v4"))
    for name, reason in (("a.evil.example", "rule bad"), ("b.unknown.example", "default")):
        err, resolved, _ = connect(g, name, 8443)
        assert err == f"egress policy: blocked ({reason} (not resolved))" and resolved == [], name
    r = admin(g, "POST", "/test", {"host": "b.unknown.example"})[1]  # "Test a destination" agrees
    assert (r["action"], r["reason"], r["ips"]) == ("deny", "default (not resolved)", [])


def test_a_name_that_resolves_into_an_address_allow_is_decided_by_its_name(make):
    """ADR-0013: an approved address is not an approval of every name that resolves to it."""
    g = make(config={}, policy={
        "default": "ask", "ask_timeout": 5, "seeded": [],
        "rules": [
            {"id": "ip", "action": "allow", "cidr": f"{PUBLIC}/32"},
            {"id": "ha", "action": "allow", "cidr": "192.168.1.10/32"},  # above the block: opens the address
            {"id": "q", "action": "ask", "cidr": "192.168.1.20/32"},  # a question about the literal only
            {"id": "ok", "action": "allow", "host": "ok.example"},
            {"id": "bad", "action": "deny", "host": "bad.example"},  # below the address allow: wins anyway
        ],
    })  # fmt: skip
    assert connect(g, PUBLIC)[0] is None and g.events.recent(1)[0]["reason"] == "rule ip"
    # default ask: the name is asked about (on the name, not resolved); the address allow answered nothing
    err, resolved, seen = connect_and_answer(g, "other-site.example", scope="deny")
    assert len(seen) == 1 and seen[0]["ips"] == [] and resolved == [] and "deny by web:admin" in err
    # a name deny below the address allow wins
    err, resolved, _ = connect(g, "bad.example")
    assert err == "egress policy: blocked (rule bad (not resolved))" and resolved == []
    assert g.policy.evaluate("bad.example", 443, [PUBLIC]).rule_id == "bad"  # ... also with the address known
    # an allowed name + an address allow above a block: allowed, by the name rule
    err, resolved, addr = connect(g, "ok.example", ips=("192.168.1.10",))
    assert err is None and resolved == ["ok.example"] and addr == ("192.168.1.10", 443)
    assert g.events.recent(1)[0]["reason"] == "rule ok"
    # an allowed name + an address ASK above a block: still blocked, and nobody is asked
    err, _, _ = connect(g, "ok.example", ips=("192.168.1.20",))
    assert err == (
        "egress policy: blocked (name allowed by rule ok, but it resolves to 192.168.1.20, inside blocked range "
        "192.168.0.0/16 (rule block-192.168.0.0_16): add an allow for the address above that rule)"
    )
    assert g.pending == {}
    err, _, seen = connect_and_answer(g, "192.168.1.20", scope="once")  # the literal is asked about
    assert err is None and seen[0]["ips"] == ["192.168.1.20"]
    # deny mode: the address allow lets no name through
    assert admin(g, "PATCH", "/policy", {"default": "deny"})[0] == 200
    err, resolved, _ = connect(g, "third-site.example")
    assert err == "egress policy: blocked (default (not resolved))" and resolved == []


def approve_when_asked(g, scope="always"):
    """Answer the next pending approval like the UI does; returns the pendings seen."""
    seen = []

    async def answer():
        for _ in range(200):
            await asyncio.sleep(0.01)
            if g.pending:
                p = next(iter(g.pending.values()))
                seen.append(p.to_dict())
                g.answer(p.id, scope, "web:admin")
                return

    return seen, answer


def connect_and_answer(g, host, port=443, ips=(PUBLIC,), scope="always"):
    seen, answer = approve_when_asked(g, scope)
    resolved = []

    async def resolve(h, p):
        resolved.append(h)
        return list(ips)

    g.resolve = resolve
    server = SimpleNamespace(address=(host, port), error=None, id="s1", sni=None)
    client = SimpleNamespace(proxy_mode=SimpleNamespace(type_name="regular"), peername=("172.31.10.9", 1))

    async def go():
        await asyncio.gather(g.server_connect(SimpleNamespace(server=server, client=client)), answer())

    asyncio.run(asyncio.wait_for(go(), 10))
    return server.error, resolved, seen


def test_an_approval_never_opens_a_blocked_range(make):
    g = make(config={}, policy={"default": "ask", "ask_timeout": 5, "seeded": [], "rules": []})
    # asked on the name alone (not resolved yet), approved, and then the address decides
    err, resolved, seen = connect_and_answer(g, "nas.example", ips=("192.168.1.10",))
    assert seen and seen[0]["ips"] == [] and resolved == ["nas.example"]
    rule = g.policy.rules[0]
    assert (rule.host, rule.source) == ("nas.example", "approval")  # the approval is a name rule at the top
    assert err == (
        f"egress policy: blocked (name allowed by rule {rule.id}, but it resolves to 192.168.1.10, inside blocked "
        "range 192.168.0.0/16 (rule block-192.168.0.0_16): add an allow for the address above that rule)"
    )
    assert g.shadow_stats()[rule.id]["address"] == "192.168.1.10"
    # with a public address the same approval is all it takes
    err, _, seen = connect_and_answer(g, "web.example")
    assert err is None and len(seen) == 1
    # approving an IP literal adds an address rule for exactly that address and port
    err, _, seen = connect_and_answer(g, "1.2.3.4", 8080)
    top = g.policy.rules[0]
    assert err is None and seen[0]["ips"] == ["1.2.3.4"] and (top.cidr, top.port) == ("1.2.3.4/32", 8080)
    # an address in a blocked range is never asked about: the block is the first match and it is final
    err, _, seen = connect_and_answer(g, "192.168.1.30", 8080)
    assert err == "egress policy: blocked (rule block-192.168.0.0_16 (built-in block))" and seen == []


def test_an_approval_is_given_on_the_name_and_checked_against_the_addresses_afterwards(make):
    """Also with address rules for the port, a name is asked about before it is resolved (amendment). Your
    answer adds a name rule at the top; what it means for the addresses is decided by the list - not assumed."""
    g = make(config={}, policy={
        "default": "ask", "ask_timeout": 5, "seeded": [],
        "rules": [
            {"id": "ipq", "action": "ask", "cidr": "8.8.8.0/24"},  # ask about this range (IP literals) ...
            {"id": "blk", "action": "deny", "cidr": "8.8.8.8/32"},  # ... a block below it: still blocks for a name
            {"id": "one", "action": "allow", "cidr": "9.9.9.9/32"},
        ],
    })  # fmt: skip
    err, resolved, seen = connect_and_answer(g, "dns.example", ips=("8.8.8.8",))
    assert seen[0]["ips"] == [] and resolved == ["dns.example"]  # asked on the name, resolved after the answer
    rule = g.policy.rules[0]
    assert rule.host == "dns.example" and f"name allowed by rule {rule.id}, but it resolves to 8.8.8.8" in err
    assert "(rule blk)" in err and "s1" not in g.verdicts
    # where nothing blocks the address the approval is the decision: one question, the address ask adds none
    err, _, seen = connect_and_answer(g, "dns2.example", ips=("8.8.8.9",))
    rule = g.policy.rules[0]
    assert err is None and len(seen) == 1 and rule.host == "dns2.example" and g.pending == {}
    assert g.events.recent(1)[0]["reason"] == f"rule {rule.id} (approved via always)"
    # a denial is a denial, and the name is not resolved
    err, resolved, _ = connect_and_answer(g, "dns3.example", ips=("8.8.8.9",), scope="deny_always")
    assert err == "egress policy: blocked (deny_always by web:admin (not resolved))" and resolved == []
    # an IP literal in the asked range: asked with its address, and the approval (an address rule at the top)
    # is checked against the list again
    err, _, seen = connect_and_answer(g, "8.8.8.9")
    assert err is None and seen[0]["ips"] == ["8.8.8.9"] and g.policy.rules[0].cidr == "8.8.8.9/32"
    assert g.events.recent(1)[0]["reason"] == "always by web:admin"


def test_a_grant_hint_refuses_without_asking_also_when_the_name_had_to_be_resolved(make):
    g = make(policy={"default": "ask", "ask_timeout": 5, "seeded": [], "rules": []})
    err, resolved, _ = connect(g, "printer.example", 631)  # a grant is defined, not active: use it, no prompt
    assert err.startswith("egress policy: blocked (default; available via grant lanname") and resolved == []
    # an address allow for the port changes nothing: the name is not allowed, and it is not resolved
    g.policy.add_rule(Rule(action="allow", cidr="192.168.1.50/32", port=631, id="p"))
    for ips in ((PUBLIC,), ("192.168.1.50",)):
        err, resolved, _ = connect(g, "printer.example", 631, ips=ips)
        assert err.startswith("egress policy: blocked (default; available via grant lanname") and resolved == []
    assert g.pending == {}
    # a name the rules allow is resolved; where its address is blocked the hint is given too, without a prompt
    g.policy.add_rule(Rule(action="allow", host="printer.example", id="n"))
    err, resolved, _ = connect(g, "printer.example", 631, ips=("192.168.1.51",))
    assert resolved == ["printer.example"] and g.pending == {}
    assert "name allowed by rule n, but it resolves to 192.168.1.51" in err
    assert err.endswith("; available via grant lanname (agent: tallygate request lanname))")
    assert connect(g, "printer.example", 631, ips=("192.168.1.50",))[0] is None  # name allowed, address open


def test_service_exceptions_in_the_gateway(make):
    g = make(
        config={"services": [{"listen": 15432, "target": "192.168.1.10:5432", "allow_private": True},
                             {"listen": 18080, "target": f"{CONTROL}:8080", "allow_private": True}]},
        policy={"default": "allow", "seeded": [], "rules": []},
    )  # fmt: skip
    assert connect(g, "192.168.1.10", 5432, mode="reverse")[0] is None
    assert "rule block-192.168.0.0_16" in connect(g, "192.168.1.10", 5432, mode="regular")[0]
    assert "locked: " in connect(g, CONTROL, 8080, mode="reverse")[0]  # an exception never reaches the stack


def test_test_a_destination_shows_the_deciding_rule_and_the_shadowing(make):
    g = make(config={}, policy={
        "default": "ask", "seeded": [],
        "rules": [{"id": "nas", "action": "allow", "host": "nas.example", "note": "the NAS"}],
    })  # fmt: skip

    async def resolve(host, port):
        return [host] if core.is_ip(host) else {"nas.example": ["192.168.1.10"]}.get(host, [PUBLIC])

    g.resolve = resolve
    r = admin(g, "POST", "/test", {"host": "nas.example", "port": 443})[1]
    assert r["action"] == "deny" and r["ips"] == ["192.168.1.10"] and r["rule_id"] == "block-192.168.0.0_16"
    assert r["rule"]["cidr"] == "192.168.0.0/16" and g.policy.rules[r["pos"] - 1].id == r["rule_id"]
    assert r["shadow"] == {
        "rule": "nas",
        "address": "192.168.1.10",
        "by": "block-192.168.0.0_16",
        "range": "192.168.0.0/16",
    }
    assert r["reason"].startswith("name allowed by rule nas, but it resolves to 192.168.1.10, inside blocked range")
    assert g.shadows == {} and g.hits == {}  # a test is not traffic
    r = admin(g, "POST", "/test", {"host": "new.example"})[1]
    assert (r["action"], r["reason"], r["ips"], r["rule"], r["pos"]) == (
        "ask",
        "default (not resolved)",
        [],
        None,
        None,
    )
    g.policy.add_rule(Rule(action="allow", cidr="192.168.1.10/32", id="dev"))
    r = admin(g, "POST", "/test", {"host": "nas.example"})[1]  # the address is open now: the name rule decides
    assert (r["action"], r["rule_id"], r["pos"], r["shadow"]) == ("allow", "nas", 2, None)
    r = admin(g, "POST", "/test", {"host": "new.example"})[1]  # still not resolved: no address rule lets a name in
    assert (r["action"], r["reason"], r["ips"]) == ("ask", "default (not resolved)", [])
    r = admin(g, "POST", "/test", {"host": "192.168.1.10"})[1]  # the literal is decided by the address rule
    assert (r["action"], r["rule_id"], r["pos"]) == ("allow", "dev", 1)
    r = admin(g, "POST", "/test", {"host": CONTROL, "port": 8080})[1]
    assert (r["action"], r["rule_id"], r["rule"], r["pos"]) == ("deny", LOCKED, None, None) and "locked: " in r[
        "reason"
    ]


def test_unused_blocks_are_never_offered_for_cleanup(make):
    """A block that never matched has done its job. If it counted as a stale rule, "remove unused rules" would
    open the local network."""
    g = make(config={"never": ["203.0.113.7/32"]}, policy={
        "default": "ask", "seeded": [], "rules": [{"id": "idle", "action": "allow", "host": "idle.example"}],
    })  # fmt: skip
    g.flush_hits()
    g.events.db.execute("UPDATE rule_hits SET since = 1")
    stats = admin(g, "GET", "/rules/stats")[1]["rules"]
    assert [r["id"] for r in stats if r["stale"]] == ["idle"] and len(stats) == len(g.policy.rules)
    blocks = [r.id for r in g.policy.rules if r.source in ("builtin", "config")]
    status, r = admin(g, "POST", "/rules/cleanup", {"ids": ["idle", *blocks]})
    assert status == 200 and r == {"removed": ["idle"], "kept": blocks}
    assert [x.id for x in g.policy.rules] == blocks
