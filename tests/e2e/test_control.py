"""control plane end-to-end: auth, CSRF, gateway relay allowlist, approvals via UI API, web console."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from .conftest import CONTROL_PASSWORD, free_port
from .helpers import Api, http_via_proxy
from .test_gateway import in_thread


@pytest.fixture
def ui(control):
    api = Api(control["base"], csrf_header="X-Tallygate")
    status, _, headers = api.call("POST", "/login", form={"password": CONTROL_PASSWORD})
    assert status == 302 and headers["Location"].endswith("/")
    return api


def test_unauthenticated_access_is_refused(control):
    anon = Api(control["base"])
    assert anon.call("GET", "/api/gw/policy")[0] == 401
    status, _, headers = anon.call("GET", "/")
    assert status == 302 and headers["Location"].endswith("/login")
    assert anon.call("GET", "/term/bash/")[0] == 401


def test_wrong_password_redirects_with_failure(control):
    status, _, headers = Api(control["base"]).call("POST", "/login", form={"password": "nope"})
    assert status == 302 and "failed=1" in headers["Location"]


def test_security_headers(ui):
    _, _, headers = ui.call("GET", "/")
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'self'" in csp
    assert headers["X-Frame-Options"] == "SAMEORIGIN" and headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store" and headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_csrf_protection(ui):
    no_header = Api(ui.base)
    no_header.jar = ui.jar
    no_header.opener = ui.opener
    assert no_header.call("POST", "/api/gw/test", {"host": "x.org"})[1] == {"error": "csrf check failed"}
    status, data, _ = ui.call("POST", "/api/gw/test", {"host": "x.org"}, headers={"Origin": "https://evil.example"})
    assert status == 403 and data["error"] == "csrf check failed"


def test_relay_only_allows_listed_gateway_paths(ui):
    assert ui.call("GET", "/api/gw/stream")[0] == 404
    assert ui.call("GET", "/api/gw/../health")[0] in (404, 400)
    status, data, _ = ui.call("GET", "/api/gw/policy")
    assert status == 200 and "rules" in data


def test_approve_from_ui_records_user(ui, gateway):
    port = free_port()
    t, _ = in_thread(http_via_proxy, gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    deadline = time.time() + 4
    pending = []
    while not pending and time.time() < deadline:
        pending = [p for p in ui.call("GET", "/api/gw/pending")[1] if p["port"] == port]
        time.sleep(0.1)
    assert pending
    status, _data, _ = ui.call("POST", f"/api/gw/pending/{pending[0]['id']}/decide", {"scope": "hour", "by": "spoofed"})
    assert status == 200
    t.join(10)
    ev = ui.call("GET", "/api/gw/events?limit=5")[1]
    assert any(e["port"] == port and e["reason"] == "hour by web:admin" for e in ev)  # 'by' cannot be spoofed


def test_secret_is_write_only_through_ui(ui):
    assert ui.call("PUT", "/api/gw/secrets/github_token", {"value": "ghp_UI"})[0] == 200
    _, data, _ = ui.call("GET", "/api/gw/secrets")
    assert "ghp_UI" not in json.dumps(data)


def test_web_console_roundtrip(ui, control):
    if not control["ttyd"]:
        pytest.skip("ttyd not installed")
    import aiohttp

    async def run():
        cookies = {c.name: c.value for c in ui.jar}
        origin = control["base"]
        async with aiohttp.ClientSession(cookies=cookies, trust_env=False) as s:
            with pytest.raises(aiohttp.WSServerHandshakeError):
                async with s.ws_connect(
                    f"{origin.replace('http', 'ws')}/term/bash/ws",
                    protocols=("tty",),
                    headers={"Origin": "https://evil.example"},
                ):
                    pass
            async with s.ws_connect(
                f"{origin.replace('http', 'ws')}/term/bash/ws", protocols=("tty",), headers={"Origin": origin}
            ) as ws:
                # no credential from the browser: the control plane adds it
                await ws.send_str(json.dumps({"columns": 80, "rows": 24}))
                await ws.send_bytes(b"0echo tally-$((6*7))\r")
                out = b""
                while b"tally-42" not in out:
                    msg = await asyncio.wait_for(ws.receive(), 5)
                    data = msg.data if isinstance(msg.data, bytes) else str(msg.data).encode()
                    assert data[:1] == b"0"  # only terminal output is relayed (TG-01)
                    out += data[1:]
                return out

    assert b"tally-42" in asyncio.run(run())


def test_learning_mode_leads_quick_settings_and_setup_has_no_policy_step(ui):
    """#200/#197: the unknown-destination step is gone from Setup ("ask" is the default; the mode is under
    Settings); learning mode is the first card of Quick settings and is started (and confirmed) there."""
    page = ui.call("GET", "/")[1]
    assert b'id="st-policy"' not in page and b'id="wzLearn"' not in page
    assert page.index(b'id="learnCard"') < page.index(b'id="qaTemplates"')
    js = ui.call("GET", "/static/wizard.js")[1]
    assert b'gw("POST", "/learning"' not in js


def test_what_the_agent_can_reach_is_one_table(ui):
    """#121: each destination once, with the rule, the per-request limits and the grants that apply."""
    status, view, _ = ui.call("GET", "/api/gw/access")
    assert status == 200 and view["default"] in ("ask", "deny", "allow")
    rows = {r["host"]: r for r in view["rows"]}
    assert rows["ro.test"]["read_only"] is not None and rows["ro.test"]["access"] == "allow"  # rule + read-only
    assert rows["gh.test"]["credentials"] is True  # rule + added credentials
    assert rows["sec.test"]["grants"][0]["name"] == "sec" and rows["sec.test"]["grants"][0]["credentials"] is True
    lan = rows["lanecho.test"]
    assert lan["access"] == "request" and {g["name"] for g in lan["grants"]} == {"lanhttp", "nolan"}
    # The separate "What the agent can reach" card was removed as redundant (#176); the reachability
    # the /api/gw/access view computes is to be folded into the one rules table (#177).


def test_the_rule_list_with_blocks_locked_rows_and_order_through_the_control_plane(ui, gateway):
    """ADR-0019: the blocked ranges are rules in the one Destinations table (moved, edited, deleted, restored
    there); the stack's own networks are listed as locked; the floor card, the hard-deny textarea and the
    unblock button are gone."""
    status, model, _ = ui.call("GET", "/api/gw/model")
    assert status == 200 and set(model) == {"default", "destinations", "locked"}
    rules = [d for d in model["destinations"] if d.get("access") in ("allow", "ask", "deny")]
    _, pol, _ = ui.call("GET", "/api/gw/policy")
    assert [d["id"] for d in rules] == [r["id"] for r in pol["rules"]]  # evaluation order
    blocks = [d for d in rules if d["source"] == "config"]
    assert {d["match"]["cidr"] for d in blocks} >= {"192.168.0.0/16", "169.254.0.0/16"}  # the e2e config's never keys
    assert all(set(row) == {"range", "source", "reason"} for row in model["locked"])
    assert ui.call("GET", "/api/gw/never-reachable")[1] == model["locked"]
    assert any(row["range"] == f"127.0.0.1:{gateway['ports']['api']}" for row in model["locked"])
    # move, through the control relay: a rule id with a dot and a colon, then back
    first, second = rules[0]["id"], rules[1]["id"]
    status, moved, _ = ui.call("POST", f"/api/gw/destinations/{second}/move", {"before": first})
    assert status == 200 and moved["order"][:2] == [second, first]
    assert ui.call("POST", f"/api/gw/destinations/{first}/move", {"before": second})[1]["order"][:2] == [first, second]
    assert ui.call("POST", f"/api/gw/destinations/{first}/move", {"before": "nope"})[0] == 400
    assert ui.call("POST", "/api/gw/destinations/nope/move", {"before": first})[0] == 404
    # a block is deleted and restored like any rule
    block = next(d for d in blocks if d["match"]["cidr"] == "169.254.0.0/16")
    assert ui.call("DELETE", f"/api/gw/destinations/{block['id']}")[0] == 200
    status, restored, _ = ui.call("POST", "/api/gw/destinations/restore-blocks")
    assert status == 200 and [r["cidr"] for r in restored["added"]] == ["169.254.0.0/16"]
    assert "opened" in restored  # address rules above the blocks that keep part of a range open (amendment)
    assert ui.call("POST", "/api/gw/destinations/restore-blocks")[1]["added"] == []
    # the page and the scripts
    page = ui.call("GET", "/")[1]
    assert b'id="neverBody"' not in page and b'id="hardDeny"' not in page and b'id="neverCard"' not in page
    assert b"loadNever" not in ui.call("GET", "/static/app.js")[1]
    dest_js = ui.call("GET", "/static/destinations.js")[1]
    assert b"floor_open" not in dest_js and b"Unblock" not in dest_js and b"model.never" not in dest_js
    assert b'mkbtn("Move up"' in dest_js and b'mkbtn("Move down"' in dest_js and b'id="dRestore"' in dest_js
    assert b'<span class="status off">locked</span>' in dest_js and b"blocked by a range rule</div>" in dest_js
    assert b"DNS rebinding" in dest_js and b"Still open by rules above the blocks" in dest_js
    # deleting a block lowers security: confirmed, naming the range and the consequence (docs/ux-concept.md)
    assert b"confirmClick(del, block ? `Delete the block of ${label}? The agent will be able to reach" in dest_js


def test_grant_editor_has_the_simple_form_and_keeps_every_setting_under_advanced(ui):
    """#121: name, address, type, access and duration; the full editor is under Advanced. ADR-0019: no
    "local network" checkbox - a target is local when it names a local address."""
    page = ui.call("GET", "/")[1].decode()
    simple = page.index('id="geSimple"')
    advanced = page.index('<details id="geAdvanced"')
    end = page.index('id="geSave"')
    for field in ('id="geAddr"', 'id="geKind"', 'id="geAccess"', 'id="geDur"'):
        assert simple < page.index(field) < advanced, field
    for field in ('id="geRead"', 'id="geApprWrite"', 'id="geMaxTtl"', 'id="geTargets"', 'id="geAddTarget"'):
        assert advanced < page.index(field) < end, field
    assert page.index("</details>", advanced) < end  # Save stays outside the folded part
    app = ui.call("GET", "/static/app.js")[1]
    assert b"function grantSimpleToAdvanced()" in app and b"function grantAdvancedToSimple()" in app
    assert (
        'id="geLan"' not in page and b"t-lan" not in app and b"lan_allow" not in app and "grants_lan_allow" not in page
    )
    # Quick settings: the local-network form is always there, and has a place for the gateway's explanation
    assert '<form id="qaLanForm" class="lan-form">' in page and 'id="qaLanError" class="alert bad hidden"' in page


def test_console_page_is_served_by_control_not_the_agent(ui):
    """TG-01: no agent-supplied HTML/JS may be served on the control origin."""
    status, body, headers = ui.call("GET", "/term/bash/")
    assert status == 200 and b"/static/term.js" in body
    assert "script-src 'self'" in headers.get("Content-Security-Policy", "")
    for path in ("/term/bash/token", "/term/bash/index.html", "/term/bash/auth_token.js"):
        assert ui.call("GET", path)[0] in (404, 405)
    assert ui.call("GET", "/term/nope/")[0] == 404


def test_logout_invalidates_the_session_server_side(control):
    """TG-12: a copied cookie must not survive logout."""
    from .helpers import Api

    a = Api(control["base"], csrf_header="X-Tallygate")
    a.call("POST", "/login", form={"password": CONTROL_PASSWORD})
    cookie = {c.name: c.value for c in a.jar}
    assert a.call("GET", "/api/meta")[0] == 200
    a.call("POST", "/logout", headers={"Origin": control["base"]})
    replay = Api(control["base"])
    status, _, _ = replay.call("GET", "/api/meta", headers={"Cookie": "; ".join(f"{k}={v}" for k, v in cookie.items())})
    assert status == 401


def test_forged_cookie_and_proxy_header_are_rejected(control):
    """TG-07: TRUST_PROXY_AUTH_HEADER is unset here, and even when set only TRUSTED_PROXIES may use it."""
    from .helpers import Api

    anon = Api(control["base"])
    assert anon.call("GET", "/api/meta", headers={"Remote-User": "admin", "X-Forwarded-For": "127.0.0.1"})[0] == 401
    assert anon.call("GET", "/api/meta", headers={"Cookie": "tallygate_session=abc.def"})[0] == 401


def test_cross_origin_login_is_refused(control):
    from .helpers import Api

    a = Api(control["base"])
    status, _, _ = a.call(
        "POST", "/login", form={"password": CONTROL_PASSWORD}, headers={"Origin": "https://evil.example"}
    )
    assert status == 403


def test_ui_can_apply_and_undo_templates(ui):
    """#34: the UI relays preset details, apply and undo (DELETE /presets/<name>) to the gateway."""
    status, details, _ = ui.call("GET", "/api/gw/presets?details=1")
    assert status == 200 and any(p["name"] == "node" and p["category"] == "template" for p in details)
    assert ui.call("POST", "/api/gw/presets/node", {})[0] == 200
    assert ui.call("DELETE", "/api/gw/destinations/node:dist")[0] == 200  # one template rule, id <preset>:<id>
    status, data, _ = ui.call("DELETE", "/api/gw/presets/node")
    assert status == 200 and "node:npm" in data["removed"] and "node:dist" not in data["removed"]
