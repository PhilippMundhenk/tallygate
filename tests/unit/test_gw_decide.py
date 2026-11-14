"""ADR-0014 step 2 (shadow): deciding a destination's limits from the model must equal the current path.

`decide.host_limits(translate(gw), host)` must give exactly what `gw.access.host_limits(host)` gives today,
for every host the config touches and a few that it does not. This is the regression net that lets a later
change switch enforcement to the model.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from egressgw import core, decide
from egressgw.destinations import translate

CONFIG = {
    "inject": [
        {"host": "api.example", "header": "X-Token", "value": "Bearer ${tok}"},
        {"host": "api.example", "header": "X-Extra", "value": "${tok}"},  # two creds on one host
        {"host": "git.example", "value": "Bearer ${gh}"},  # credentials AND repository host
    ],
    "inject_strip_headers": ["Authorization", "Cookie"],
    "readonly": [
        "ro.example",
        {"host": "*.oci.example", "post_is_write": True, "read_posts": ["/q/*", "/batch"]},
    ],
    "github_repos": ["me/app"],
    "github_hosts": ["git.example", "api.github.example"],
    "grants": {
        "ha": {"targets": [{"host": "ha.example", "port": 443, "paths": ["/api/*"]}], "levels": ["read", "write"]},
    },
}
POLICY = {"default": "deny", "rules": [{"id": "ok", "action": "allow", "host": "ok.example"}]}

PROBES = [
    "ok.example",  # nothing
    "ro.example",  # read-only, no POST-as-write
    "x.oci.example",  # read-only wildcard, POST is a write, with read_posts
    "deep.sub.oci.example",  # wildcard covers deeper subdomains
    "oci.example",  # the bare domain is NOT covered by *.oci.example
    "api.example",  # two injected credentials
    "git.example",  # repository scope AND a credential
    "api.github.example",  # repository scope, no credential
    "other.example",  # matches nothing
    "ha.example",  # only reachable via a grant: it has no host limits of its own
]


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(CONFIG))
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(POLICY))
    return core.Gateway()


def test_model_host_limits_equal_the_current_path_for_every_probe(gw):
    model = translate(gw)
    for host in PROBES:
        assert decide.host_limits(model, host, gw.strip_headers) == gw.access.host_limits(host), host


def test_a_probe_actually_exercises_each_property(gw):
    # guard against the equivalence test passing only because every probe is empty
    model = translate(gw)
    by = {h: decide.host_limits(model, h, gw.strip_headers) for h in PROBES}
    assert by["ro.example"].no_writes and not by["ro.example"].post_is_write
    assert by["x.oci.example"].post_is_write and by["x.oci.example"].read_posts == ("/q/*", "/batch")
    assert by["deep.sub.oci.example"].no_writes and by["oci.example"].no_writes  # *.oci.example covers the apex too
    assert by["api.example"].add == (("X-Token", "Bearer ${tok}"), ("X-Extra", "${tok}"))
    assert by["api.example"].strip == ("X-Token", "X-Extra", "Authorization", "Cookie")
    assert by["git.example"].repos and by["git.example"].add == (("Authorization", "Bearer ${gh}"),)
    assert by["api.github.example"].repos and not by["api.github.example"].add
    assert not by["ok.example"].any and not by["other.example"].any
