"""Keyboard shortcuts and compact approval list (#79): the page loads keys.js, and the decision buttons carry
the data attributes keys.js uses. The behaviour itself is checked in a browser (docs/development.md)."""

from __future__ import annotations

from .test_setup_wizard import login


def test_keys_script_and_hooks_are_served(agent_control):
    ui = login(agent_control["base"])
    page = ui.call("GET", "/")[1]
    assert b'src="/static/keys.js"' in page and b'id="approvalOpts"' in page
    app = ui.call("GET", "/static/app.js")[1]
    assert b"b.dataset.scope = scope" in app and b"b.dataset.decision = decision" in app
    # three choices first, the other scopes behind "More" (#121): hidden by CSS, so the keys still reach them
    assert b'["once", "Allow once", "", false], ["always", "Always allow", "", false], ["deny", "Deny"' in app
    css = ui.call("GET", "/static/style.css")[1]
    assert b".pending:not(.more-open) .btns .extra{display:none}" in css
    status, js, headers = ui.call("GET", "/static/keys.js")
    assert status == 200 and headers["Content-Type"].startswith(("application/javascript", "text/javascript"))
    assert b'"jkahd"' in js
