"""Overview tab (#68) end to end: the event summary and disk use through control's relay."""

from __future__ import annotations

from .helpers import http_via_proxy
from .test_setup_wizard import login


def test_summary_and_disk_use_through_the_relay(agent_control, gateway, upstream):
    ui = login(agent_control["base"])
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{upstream['http']}/overview")
    assert status == 200
    status, s, _ = ui.call("GET", "/api/gw/events/summary")
    assert status == 200 and s["counts"]["allow"] >= 1
    assert any(t["host"] == "127.0.0.1" and t["port"] == upstream["http"] for t in s["top"])
    info = ui.call("GET", "/api/gw/info")[1]
    assert info["data_disk"]["total"] > 0 and info["events_db_bytes"] > 0
    st = ui.call("GET", "/api/agent/status")[1]
    assert st["workspace_disk"]["total"] > 0


def test_overview_is_the_start_page(agent_control):
    ui = login(agent_control["base"])
    page = ui.call("GET", "/")[1]
    assert b'data-tab="overview"' in page and b'src="/static/overview.js"' in page
    status, js, _ = ui.call("GET", "/static/app.js")
    assert status == 200 and b'showTab(location.hash.slice(1) || "overview")' in js
