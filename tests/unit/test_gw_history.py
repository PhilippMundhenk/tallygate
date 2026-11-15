"""Policy history (#71): versions, diff, restore, export and import (store + management API in-process)."""

import json
import sqlite3
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw import history
from egressgw.history import PolicyHistory, diff, export_doc, parse_import

BASE = {
    "default": "ask",
    "ask_timeout": 60,
    "hard_deny": [],
    "rules": [{"id": "a", "action": "allow", "host": "a.example"}],
}


def test_versions_are_deduplicated_capped_and_listed_newest_first(tmp_path):
    h = PolicyHistory(tmp_path / "h.db", keep=3)
    assert h.keep == 10 and h.latest is None  # at least 10 versions are kept
    assert h.record(BASE, "web:admin", "first") == 1
    assert h.record(json.loads(json.dumps(BASE)), "web:admin", "same again") is None
    for i in range(12):
        h.record({**BASE, "ask_timeout": 100 + i}, "api", f"change {i}")
    vs = h.versions(limit=100)
    assert len(vs) == 10 and vs[0]["what"] == "change 11" and vs[0]["rules"] == 1 and vs[0]["default"] == "ask"
    assert [v["id"] for v in h.versions(limit=2, before=vs[0]["id"])] == [vs[1]["id"], vs[2]["id"]]
    assert h.get(1) is None and h.get(vs[0]["id"])["policy"]["ask_timeout"] == 111
    again = PolicyHistory(tmp_path / "h.db")  # the latest version survives a restart: no duplicate
    assert again.record({**BASE, "ask_timeout": 111}, "gateway", "start") is None


def test_diff_lists_mode_rule_and_order_changes():
    new = {
        "default": "deny",
        "ask_timeout": 30,
        "rules": [
            {"id": "b", "action": "deny", "host": "b.example"},
            {"id": "a", "action": "allow", "host": "a.example", "port": 443},
            {"id": "block-10.0.0.0_8", "action": "deny", "cidr": "10.0.0.0/8", "source": "builtin"},
        ],
    }
    d = diff(BASE, new)
    assert d["default"] == ["ask", "deny"] and d["ask_timeout"] == [60, 30]
    assert "hard_deny" not in d  # ADR-0019: a block is a rule, added and removed like one
    assert [r["id"] for r in d["rules"]["added"]] == ["b", "block-10.0.0.0_8"] and d["rules"]["removed"] == []
    assert d["rules"]["changed"][0]["after"]["port"] == 443 and not d["identical"]
    assert "reordered" not in d  # a and b: only one rule in common
    back = diff(new, BASE)
    assert [r["id"] for r in back["rules"]["removed"]] == ["b", "block-10.0.0.0_8"]
    # the order is what is decided now: moving a block above an allow is a change the diff must show
    swapped = {**new, "rules": list(reversed(new["rules"]))}
    assert diff(new, swapped) == {"reordered": True, "identical": False}
    assert diff(BASE, BASE) == {"identical": True}


def test_export_has_policy_and_ui_grants_but_never_secrets():
    text = export_doc(
        BASE, {"nas": {"name": "nas", "source": "ui", "inject": [{"value": "${tok}"}], "levels": ["read"]}}
    )
    doc = yaml.safe_load(text)
    assert doc["tallygate_export"] == 1 and doc["policy"] == BASE and doc["grants"] == {"nas": {"levels": ["read"]}}
    assert "tok" not in text


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("", "expected the exported YAML"),
        (None, "expected the exported YAML"),
        ("a: [", "not valid YAML"),
        ("- 1", "not a tallygate export"),
        ("tallygate_export: 2\npolicy: {}", "not a tallygate export"),
        ("tallygate_export: 1\npolicy: {}\nsecrets: {}", "unknown keys"),
        ("tallygate_export: 1\npolicy: []", "policy: expected a mapping"),
        ("tallygate_export: 1\npolicy: {}\ngrants: [a]", "grants: expected a mapping"),
        ("tallygate_export: 1\npolicy: {}\ngrants: {a: 1}", "grants: expected a mapping"),
    ],
)
def test_import_structure_is_checked(text, error):
    with pytest.raises(ValueError, match=error):
        parse_import(text)


def test_import_of_an_old_export_and_of_lan_grants_is_announced():
    text = (
        "tallygate_export: 1\npolicy: {default: deny, hard_deny_floor: [], hard_deny: [203.0.113.7/32]}\n"
        "grants: {cam: {targets: [{host: cam.lan, port: 80, lan: true}]}}\n"
    )
    pol, grants, warnings = parse_import(text)
    # handed on as it is: the gateway migrates it (it knows the built-in and config blocks)
    assert pol == {"default": "deny", "hard_deny_floor": [], "hard_deny": ["203.0.113.7/32"]} and set(grants) == {"cam"}
    assert "export from before ADR-0019" in warnings[0] and "grant cam: `lan` is ignored" in warnings[1]
    assert parse_import("tallygate_export: 1\npolicy: {default: deny, seeded: []}\n")[2] == []
    assert history.EXPORT_FORMAT == 1


# ------------------------------------------------------------------ management API and gateway
pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from egressgw import core  # noqa: E402

from .test_gw_api import admin, call, gw  # noqa: E402, F401  (fixture)

TOKEN = "t" * 32


def test_every_policy_change_is_a_version_with_who_and_what(gw):  # noqa: F811
    from egressgw import api

    first = gw.history.versions()
    assert len(first) == 1 and first[0]["by"] == "gateway" and first[0]["what"] == "policy at gateway start"
    assert first[0]["rules"] == 1 + len(gw.blocks_builtin)  # the seeded blocks are part of every version
    app = api.build_app(gw)
    status, created = call(
        app, "POST", "/destinations", {"match": {"host": "n.example"}, "access": "allow"},
        headers={"X-Tallygate-By": "web:admin"},
    )  # fmt: skip
    assert status == 201
    rid = created["id"]
    assert admin(gw, "PATCH", "/policy", {"default": "deny"})[0] == 200
    assert admin(gw, "DELETE", f"/destinations/{rid}")[0] == 200
    vs = admin(gw, "GET", "/policy/history?limit=10")[1]
    assert vs["keep"] == 500
    assert [(v["by"], v["what"]) for v in vs["versions"][:3]] == [
        ("api", f"rule {rid} removed"),
        ("api", "mode deny, approval timeout 60 s"),
        ("web:admin", f"rule {rid} added (allow n.example)"),
    ]
    one = admin(gw, "GET", f"/policy/history/{vs['versions'][2]['id']}")[1]
    assert [r["id"] for r in one["policy"]["rules"]][:2] == [rid, "ok"]
    assert set(one["policy"]) == {"default", "ask_timeout", "seeded", "rules"}
    assert admin(gw, "GET", "/policy/history/999") == (404, {"error": "no policy version 999"})


def test_diff_and_restore(gw):  # noqa: F811
    v1 = gw.history.versions()[0]["id"]
    admin(gw, "PUT", "/policy", {"default": "deny", "rules": []})
    v2 = gw.history.versions()[0]["id"]
    d = admin(gw, "GET", f"/policy/diff?from={v1}")[1]
    assert d["default"] == ["ask", "deny"] and d["rules"]["removed"][0]["id"] == "ok"
    assert admin(gw, "GET", f"/policy/diff?from={v1}&to={v2}")[1] == d
    assert admin(gw, "GET", "/policy/diff")[0] == 400
    assert admin(gw, "GET", "/policy/diff?from=x")[0] == 400
    assert admin(gw, "GET", f"/policy/diff?from={v1}&to=999")[0] == 404
    gw.grants.suspend_auto("test")  # as after an emergency stop: a mode change by restore resumes it
    status, pol = admin(gw, "POST", f"/policy/history/{v1}/restore")
    assert status == 200 and pol["default"] == "ask" and [r["id"] for r in pol["rules"] if "source" not in r] == ["ok"]
    assert set(pol) == {"default", "ask_timeout", "seeded", "rules"} and not gw.grants.auto_suspended
    assert gw.history.versions()[0]["what"] == f"version {v1} restored"
    assert "restored; grant auto-approval resumed" in gw.events.recent(1)[0]["reason"]
    assert admin(gw, "POST", "/policy/history/999/restore")[0] == 404
    assert admin(gw, "GET", f"/policy/diff?from={v1}")[1] == {"identical": True}


def test_a_pre_0019_version_is_migrated_when_it_is_compared_or_restored(gw):  # noqa: F811
    """A version stored by an older release has hard_deny / floor_open and no blocks among its rules."""
    old = {
        "default": "allow",
        "ask_timeout": 60,
        "hard_deny": ["203.0.113.7/32"],
        "floor_open": ["192.168.0.0/16"],
        "rules": [
            {"id": "ok", "action": "allow", "host": "ok.example"},
            {"id": "net", "action": "deny", "cidr": "8.8.8.0/24"},
        ],
    }
    vid = gw.history.record(old, "web:admin", "an old version")
    gw.history.record(gw.policy.to_dict(), "gateway", "back to now")
    d = admin(gw, "GET", f"/policy/diff?from={vid}")[1]  # what restoring it would undo, in today's terms
    assert d["default"] == ["allow", "ask"]
    assert [r["id"] for r in d["rules"]["removed"]] == ["net", "block-203.0.113.7_32"]
    assert [r["id"] for r in d["rules"]["added"]] == ["block-192.168.0.0_16"]  # it had that range open
    status, pol = admin(gw, "POST", f"/policy/history/{vid}/restore")
    assert status == 200 and [r["id"] for r in pol["rules"]][:3] == ["net", "ok", "block-203.0.113.7_32"]
    assert "192.168.0.0/16" in pol["seeded"] and not any(r.get("cidr") == "192.168.0.0/16" for r in pol["rules"])
    assert len(pol["rules"]) == 3 + len(gw.blocks_builtin) - 1
    assert gw.policy.evaluate("x.example", 443, ["192.168.1.1"]).action == "allow"  # as that version decided
    assert gw.policy.evaluate("x.example", 443, ["10.0.0.1"]).rule_id == "block-10.0.0.0_8"
    assert admin(gw, "GET", f"/policy/diff?from={vid}")[1] == {"identical": True}
    # a version that cannot be translated is refused, the policy in force stays
    bad = gw.history.record({"default": "ask", "hard_deny": ["nope"], "rules": []}, "x", "broken")
    status, err = admin(gw, "POST", f"/policy/history/{bad}/restore")
    assert status == 400 and "hard_deny: invalid CIDR" in err["error"] and gw.policy.default == "allow"


def test_export_import_roundtrip_validates_everything_first(gw):  # noqa: F811
    gw.grants.upsert_ui("cam", {"targets": [{"host": "cam.example", "port": 443}]})
    exp = admin(gw, "GET", "/policy/export")[1]
    assert exp["filename"].startswith("tallygate-policy-") and exp["filename"].endswith(".yaml")
    doc = yaml.safe_load(exp["yaml"])
    assert set(doc["grants"]) == {"cam"}  # config grants are not exported
    assert set(doc["policy"]) == {"default", "ask_timeout", "seeded", "rules"}
    assert len(doc["policy"]["rules"]) == 1 + len(gw.blocks_builtin)  # the blocks are exported as the rules they are
    # an import with a broken rule or a grant that injects a secret changes nothing
    bad_rule = {**doc, "policy": {**doc["policy"], "rules": [{"action": "allow"}]}}
    assert admin(gw, "POST", "/policy/import", {"yaml": yaml.safe_dump(bad_rule), "apply": True})[0] == 400
    inject = {
        **doc,
        "grants": {
            "x": {"targets": [{"host": "x.example", "port": 443}], "inject": [{"host": "x.example", "value": "${tok}"}]}
        },
    }
    status, body = admin(gw, "POST", "/policy/import", {"yaml": yaml.safe_dump(inject), "apply": True})
    assert status == 400 and "credential injection" in body["error"] and "x" not in gw.grants.defs
    config_name = {**doc, "grants": {"nas": {"targets": [{"host": "nas2.example", "port": 443}]}}}
    assert admin(gw, "POST", "/policy/import", {"yaml": yaml.safe_dump(config_name)})[0] == 400
    assert admin(gw, "POST", "/policy/import", ["x"])[0] == 400
    # preview, then apply
    doc["policy"]["default"] = "deny"
    doc["grants"]["cam"]["description"] = "camera"
    doc["grants"]["new"] = {"targets": [{"host": "new.example", "port": 443}]}
    text = yaml.safe_dump(doc)
    status, prev = admin(gw, "POST", "/policy/import", {"yaml": text})
    assert status == 200 and prev["applied"] is False and prev["diff"]["default"] == ["ask", "deny"]
    assert prev["grants"] == {"added": ["new"], "changed": ["cam"]} and prev["warnings"] == []
    assert set(prev["diff"]) == {"default", "identical"}  # the same rules in the same order: nothing else changes
    assert gw.policy.default == "ask" and "new" not in gw.grants.defs
    rules = [r.to_dict() for r in gw.policy.rules]
    status, done = admin(gw, "POST", "/policy/import", {"yaml": text, "apply": True})
    assert status == 200 and done["applied"] is True
    assert gw.policy.default == "deny" and gw.grants.defs["cam"].description == "camera" and "new" in gw.grants.defs
    assert [r.to_dict() for r in gw.policy.rules] == rules and gw.history.versions()[0]["what"] == "policy imported"
    # an import without grants leaves the UI grants alone
    status, done = admin(
        gw, "POST", "/policy/import", {"yaml": "tallygate_export: 1\npolicy: {default: ask}\n", "apply": True}
    )
    # ... and a policy that says nothing about blocks (a pre-0019 document) gets every block: never fewer
    assert status == 200 and "cam" in gw.grants.defs and done["warnings"]
    assert [r.cidr for r in gw.policy.rules] == gw.blocks_builtin and gw.policy.seeded == gw.blocks_builtin


def test_import_of_a_pre_0019_export_is_migrated_and_previewed_as_it_will_be(gw):  # noqa: F811
    old = {
        "tallygate_export": 1,
        "policy": {
            "default": "ask",
            "ask_timeout": 60,
            "hard_deny": ["203.0.113.7/32"],
            "floor_open": ["10.0.0.0/8"],
            "hard_deny_floor": ["junk"],
            "rules": [
                {"id": "ok", "action": "allow", "host": "ok.example"},
                {"id": "net", "action": "deny", "cidr": "8.8.8.0/24"},
            ],
        },
        "grants": {"cam": {"targets": [{"host": "192.168.1.9", "port": 80, "scheme": "http", "lan": True}]}},
    }
    text = yaml.safe_dump(old)
    status, prev = admin(gw, "POST", "/policy/import", {"yaml": text})
    assert status == 200 and len(prev["warnings"]) == 2 and not prev["applied"]
    assert [r["id"] for r in prev["diff"]["rules"]["added"]] == ["net", "block-203.0.113.7_32"]
    assert [r["id"] for r in prev["diff"]["rules"]["removed"]] == ["block-10.0.0.0_8"]
    assert "block-10.0.0.0_8" in [r.id for r in gw.policy.rules]  # a preview changes nothing
    status, done = admin(gw, "POST", "/policy/import", {"yaml": text, "apply": True})
    assert status == 200 and done["applied"]
    ids = [r.id for r in gw.policy.rules]
    assert ids[:3] == ["net", "ok", "block-203.0.113.7_32"] and "block-10.0.0.0_8" not in ids
    assert set(gw.policy.seeded) == set(gw.blocks_builtin)  # 10/8 is remembered: it stays open after a restart
    assert [r.id for r in core.Gateway().policy.rules] == ids
    assert gw.grants.defs["cam"].targets[0].fixed() == "192.168.1.9" and not hasattr(
        gw.grants.defs["cam"].targets[0], "lan"
    )
    for broken in ({"hard_deny": "x"}, {"floor_open": ["nope"]}, {"hard_deny": [], "bogus": 1}):
        doc = yaml.safe_dump({"tallygate_export": 1, "policy": broken})
        assert admin(gw, "POST", "/policy/import", {"yaml": doc, "apply": True})[0] == 400
    assert [r.id for r in gw.policy.rules] == ids


def test_approvals_expiry_and_emergency_stop_are_attributed(gw, monkeypatch):  # noqa: F811
    from egressgw.core import Pending

    p = Pending(host="new.example", port=443, ips=[], proto="regular", client="c", timeout=30)
    gw.pending[("new.example", 443)] = p
    import asyncio

    async def go():
        p.future = asyncio.get_running_loop().create_future()
        gw.answer(p.id, "once", "telegram:op")

    asyncio.run(go())
    assert gw.history.versions()[0]["by"] == "telegram:op"
    assert gw.history.versions()[0]["what"] == "approval once for new.example:443"
    gw.policy.rules[0].expires = 1
    gw._housekeep()
    assert gw.history.versions()[0]["what"] == "expired rules removed"
    admin(gw, "POST", "/emergency-stop", {"by": "web:admin"})
    v = gw.history.versions()[0]
    assert v["by"] == "web:admin" and v["what"] == "emergency stop: mode deny"


def test_a_broken_history_does_not_break_policy_writes(gw, caplog):  # noqa: F811
    gw.history.db.close()
    assert admin(gw, "PATCH", "/policy", {"default": "deny"})[0] == 200
    assert gw.policy.default == "deny" and "version not stored" in caplog.text
    with pytest.raises(sqlite3.ProgrammingError):
        gw.history.versions()


def test_history_survives_a_restart_and_notices_offline_edits(gw):  # noqa: F811
    before = len(gw.history.versions())
    assert len(core.Gateway().history.versions()) == before  # same policy: no new version
    doc = {"default": "deny", "seeded": gw.blocks_builtin, "destinations": []}  # every block deleted, by hand
    (core.DATA_DIR / "policy.yaml").write_text(yaml.safe_dump(doc))
    g = core.Gateway()
    v = g.history.versions()[0]
    assert v["what"] == "policy.yaml changed while the gateway was stopped" and v["default"] == "deny"
    assert g.policy.rules == [] and not (core.DATA_DIR / "policy.yaml.pre-0019").exists()
    # a file in a pre-0019 form (somebody put an old backup back) is migrated and recorded as that
    (core.DATA_DIR / "policy.yaml").write_text(yaml.safe_dump({"default": "ask", "rules": []}))
    g = core.Gateway()
    assert g.history.versions()[0]["what"] == "policy migrated to one ordered rule list (ADR-0019)"
    assert [r.cidr for r in g.policy.rules] == g.blocks_builtin and (core.DATA_DIR / "policy.yaml.pre-0019").exists()
    assert "migrated to one ordered rule list" in g.events.recent(1)[0]["reason"]


def test_first_start_records_the_initial_preset(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "PRESET_DIR", Path(__file__).resolve().parents[2] / "gateway" / "presets")
    v = core.Gateway().history.versions()
    assert len(v) == 1 and v[0]["what"] == "initial policy (preset baseline)"
