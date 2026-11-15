"""Policy history, diff, rollback and export/import through the control plane (#71)."""

from __future__ import annotations

import pytest
import yaml

from .conftest import CONTROL_PASSWORD, start_control
from .helpers import Api

CONFIG = {"hard_deny_floor": ["10.0.0.0/8"]}
BLOCK = {
    "id": "block-10.0.0.0_8",
    "action": "deny",
    "cidr": "10.0.0.0/8",
    "note": "never (gateway config)",
    "source": "config",
}
POLICY = {"default": "ask", "ask_timeout": 30, "rules": [{"id": "keep", "action": "allow", "host": "keep.test"}]}


@pytest.fixture
def stack(make_gateway, tmp_path):
    gw = make_gateway(CONFIG, POLICY, GW_TEST_FLOOR_REPLACE="1", GW_INTERNAL_NETS="172.31.99.0/24")
    proc, port = start_control(tmp_path, gw, {})
    ui = Api(f"http://127.0.0.1:{port}", csrf_header="X-Tallygate")
    assert ui.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    yield gw, ui
    proc.terminate()
    proc.wait(10)


def test_changes_from_the_ui_are_versions_of_the_session_user_and_can_be_rolled_back(stack):
    gw, ui = stack
    assert ui.call("POST", "/api/gw/destinations", {"id": "oops", "access": "allow", "match": {"host": "*"}})[0] == 201
    assert ui.call("PATCH", "/api/gw/policy", {"default": "allow"})[0] == 200
    _, h, _ = ui.call("GET", "/api/gw/policy/history")
    by_what = [(v["by"], v["what"]) for v in h["versions"]]
    assert by_what[:2] == [
        ("web:admin", "mode allow, approval timeout 30 s"),
        ("web:admin", "rule oops added (allow *)"),
    ]
    start = h["versions"][-1]["id"]
    _, d, _ = ui.call("GET", f"/api/gw/policy/diff?from={start}&to=current")
    assert d["default"] == ["ask", "allow"] and [r["id"] for r in d["rules"]["added"]] == ["oops"]
    status, pol, _ = ui.call("POST", f"/api/gw/policy/history/{start}/restore")
    assert status == 200 and pol["default"] == "ask" and [r["id"] for r in pol["rules"]] == ["keep", BLOCK["id"]]
    assert pol["seeded"] == ["10.0.0.0/8"] and "hard_deny_floor" not in pol
    _, h, _ = ui.call("GET", "/api/gw/policy/history")
    assert (h["versions"][0]["by"], h["versions"][0]["what"]) == ("web:admin", f"version {start} restored")
    _, ev, _ = gw["api"].call("GET", "/events?limit=1")
    assert ev[0]["kind"] == "admin" and ev[0]["reason"] == f"policy version {start} restored"
    _, v, _ = ui.call("GET", f"/api/gw/policy/history/{start}")
    assert v["policy"]["rules"] == [*POLICY["rules"], BLOCK]  # the block is a rule of every version


def test_export_and_import_move_policy_and_ui_grants_without_secrets(stack):
    gw, ui = stack
    assert ui.call("PUT", "/api/gw/secrets/ha_token", {"value": "s3cr3t-value"})[0] == 200
    grant = {"targets": [{"scheme": "http", "host": "ha.test", "port": 8123, "paths": ["/api/*"]}], "levels": ["read"]}
    assert ui.call("PUT", "/api/gw/destinations/grant/ha", grant)[0] == 200
    _, exp, _ = ui.call("GET", "/api/gw/policy/export")
    assert "s3cr3t-value" not in exp["yaml"] and "ha_token" not in exp["yaml"]
    doc = yaml.safe_load(exp["yaml"])
    assert doc["policy"]["rules"] == [*POLICY["rules"], BLOCK] and doc["grants"]["ha"]["levels"] == ["read"]
    assert doc["policy"]["seeded"] == ["10.0.0.0/8"]
    doc["policy"]["rules"].insert(0, {"id": "pypi", "action": "allow", "host": "pypi.test", "port": 443})
    # a grant in an import is checked like one saved in the UI: a target that names the stack itself is refused
    # (nothing is applied), one that names another local address is accepted - `lan` is read and ignored
    stack_ip = {"targets": [{"scheme": "http", "host": "nas.test", "port": 80, "address": "172.31.99.9"}]}
    status, err, _ = ui.call(
        "POST", "/api/gw/policy/import", {"yaml": yaml.safe_dump({**doc, "grants": {"nas": stack_ip}}), "apply": True}
    )
    assert status == 400 and "172.31.99.9 belongs to the tallygate stack itself" in err["error"]
    assert [r["id"] for r in gw["api"].call("GET", "/policy")[1]["rules"]] == ["keep", BLOCK["id"]]
    doc["grants"]["nas"] = {
        "targets": [{"scheme": "http", "host": "nas.test", "port": 80, "lan": True, "address": "192.168.9.9"}]
    }
    status, prev, _ = ui.call("POST", "/api/gw/policy/import", {"yaml": yaml.safe_dump(doc)})
    assert status == 200 and [r["id"] for r in prev["diff"]["rules"]["added"]] == ["pypi"] and not prev["applied"]
    assert prev["warnings"] == ["grant nas: `lan` is ignored; a local target needs an IP or a fixed address"]
    status, done, _ = ui.call("POST", "/api/gw/policy/import", {"yaml": yaml.safe_dump(doc), "apply": True})
    assert status == 200 and done["applied"]
    _, pol, _ = gw["api"].call("GET", "/policy")
    assert [r["id"] for r in pol["rules"]] == ["pypi", "keep", BLOCK["id"]]
    nas = next(d for d in gw["api"].call("GET", "/grants")[1]["defs"] if d["name"] == "nas")
    assert (
        nas["targets"][0]["address"] == "192.168.9.9" and nas["targets"][0]["local"] and "lan" not in nas["targets"][0]
    )
    # an export from before ADR-0019 is migrated on import: its hard_deny is a deny rule, the config block comes back
    old = {"default": "ask", "hard_deny": ["203.0.113.9/32"], "floor_open": [], "rules": POLICY["rules"]}
    text = yaml.safe_dump({"tallygate_export": 1, "policy": old})
    status, done, _ = ui.call("POST", "/api/gw/policy/import", {"yaml": text, "apply": True})
    assert status == 200 and done["applied"] and "export from before ADR-0019" in done["warnings"][0]
    _, pol, _ = gw["api"].call("GET", "/policy")
    assert [r["id"] for r in pol["rules"]] == ["keep", "block-203.0.113.9_32", BLOCK["id"]]
    _, h, _ = ui.call("GET", "/api/gw/policy/history")
    assert (h["versions"][0]["by"], h["versions"][0]["what"]) == ("web:admin", "policy imported")
