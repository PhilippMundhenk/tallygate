"""tools/pin_compose.py and the compose files: a release's compose.yaml is tied to that release's images
(#232), and the UI is published on loopback unless the operator chooses otherwise (#231)."""

import importlib.util
import re
import runpy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "compose.yaml").read_text(encoding="utf-8")
D = {name: "sha256:" + c * 64 for name, c in (("gateway", "a"), ("control", "b"), ("agent", "c"))}


@pytest.fixture(scope="module")
def pc():
    spec = importlib.util.spec_from_file_location("pin_compose", ROOT / "tools" / "pin_compose.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pin_compose"] = mod
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------ the compose files themselves
def test_every_image_of_compose_yaml_takes_its_tag_from_tallygate_version():
    services = yaml.safe_load(COMPOSE)["services"]
    assert {s: v["image"] for s, v in services.items()} == {
        "egress-gw": "ghcr.io/philippmundhenk/tallygate-gateway:${TALLYGATE_VERSION:-latest}",
        "control": "ghcr.io/philippmundhenk/tallygate-control:${TALLYGATE_VERSION:-latest}",
        "agent": "ghcr.io/philippmundhenk/tallygate-agent:${TALLYGATE_VERSION:-latest}",
    }


def test_the_ui_is_published_on_loopback_by_default_and_nothing_else_is_published():
    """#231: plain HTTP must not be on every interface unless the operator sets CONTROL_PUBLISH knowingly."""
    published = {}
    for name in ("compose.yaml", "compose.build.yaml"):
        for service, spec in yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))["services"].items():
            if "ports" in spec:
                published[(name, service)] = spec["ports"]
            assert spec.get("network_mode") != "host", (name, service)
    assert published == {("compose.yaml", "control"): ["${CONTROL_PUBLISH:-127.0.0.1:8080}:8080"]}
    # the documented default is the same one
    assert "# CONTROL_PUBLISH=127.0.0.1:8080 " in (ROOT / ".env.example").read_text(encoding="utf-8")
    row = re.search(r"^\| `CONTROL_PUBLISH` \| `([^`]+)` \|", (ROOT / "docs/configuration.md").read_text(), re.M)
    assert row and row[1] == "127.0.0.1:8080"


def test_compose_always_gives_the_gateway_its_networks_to_lock():
    """An empty GW_INTERNAL_NETS stops the gateway (#232): compose.yaml lists exactly its own subnets."""
    doc = yaml.safe_load(COMPOSE)
    subnets = sorted(n["ipam"]["config"][0]["subnet"] for n in doc["networks"].values())
    assert sorted(doc["services"]["egress-gw"]["environment"]["GW_INTERNAL_NETS"].split(",")) == subnets
    for spec in doc["services"].values():
        assert not any(k.startswith("GW_TEST_") for k in spec.get("environment", {}))


def test_no_service_writes_core_dumps_or_forwards_packets():
    """#233: a core dump would go to the host's handler (core_pattern is not namespaced), and a container with
    a leg on agent-net and one on a network with a way out must not be a router. Both come from the hardening
    anchor; a service with its own `ulimits:` or `sysctls:` replaces the anchor's map, so every service is
    checked as compose will see it (PyYAML resolves `<<` the same way)."""
    no_forwarding = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.forwarding": "0",
        "net.ipv4.conf.default.forwarding": "0",
        "net.ipv4.conf.all.proxy_arp": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
    }
    no_ipv6 = {"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}
    services = yaml.safe_load(COMPOSE)["services"]
    assert set(services) == {"egress-gw", "control", "agent"}
    for name, spec in services.items():
        assert spec["ulimits"] == {"core": 0}, name
        assert spec["cap_drop"] == ["ALL"] and spec["security_opt"] == ["no-new-privileges:true"], name
        extra = {"net.ipv4.ip_unprivileged_port_start": "53"} if name == "egress-gw" else {}
        assert spec["sysctls"] == {**no_ipv6, **no_forwarding, **extra}, name
        # nothing that would need or allow routing
        assert not spec.get("privileged") and "cap_add" not in spec and "network_mode" not in spec, name
    # the build override must not replace either map
    for spec in yaml.safe_load((ROOT / "compose.build.yaml").read_text(encoding="utf-8"))["services"].values():
        assert not {"ulimits", "sysctls", "cap_add", "security_opt"} & set(spec)
    # the authoritative test checks the same on the running stack
    bypass = (ROOT / "tests/integration/bypass.sh").read_text(encoding="utf-8")
    assert "core=0:0" in bypass and "/proc/sys/net/ipv4/$f" in bypass and "net.ipv4.ip_forward:0" in bypass


def test_bypass_runs_python_in_the_agent_in_isolated_mode():
    """#234: the agent owns ~/.local and its environment; `python3 -I` ignores user site-packages and PYTHON*."""
    bypass = (ROOT / "tests/integration/bypass.sh").read_text(encoding="utf-8")
    in_agent = re.findall(r'docker exec "\$AGENT" (python3\S*(?: -\S+)*)', bypass)
    assert len(in_agent) == 2 and all(cmd.startswith("python3 -I") for cmd in in_agent), in_agent
    # the probe containers run the trusted image's interpreter the same way
    assert bypass.count('--entrypoint python "$GW_IMAGE"') == 3
    assert bypass.count('"$GW_IMAGE" -I -c') == 2 and "  -I -u -c" in bypass


# ------------------------------------------------------------------ pin()
def test_pin_changes_the_three_defaults_and_nothing_else(pc):
    pinned = pc.pin(COMPOSE, "0.4.1")
    before, after = COMPOSE.splitlines(keepends=True), pinned.splitlines(keepends=True)
    changed = [(a, b) for a, b in zip(before, after, strict=True) if a != b]
    assert len(changed) == 3
    for a, b in changed:
        assert a.replace("${TALLYGATE_VERSION:-latest}", "${TALLYGATE_VERSION:-0.4.1}") == b
    assert "latest}" not in pinned.replace("# ", "")  # no image default is left on :latest
    images = {s: v["image"] for s, v in yaml.safe_load(pinned)["services"].items()}
    assert images == {
        "egress-gw": "ghcr.io/philippmundhenk/tallygate-gateway:${TALLYGATE_VERSION:-0.4.1}",
        "control": "ghcr.io/philippmundhenk/tallygate-control:${TALLYGATE_VERSION:-0.4.1}",
        "agent": "ghcr.io/philippmundhenk/tallygate-agent:${TALLYGATE_VERSION:-0.4.1}",
    }
    # everything but the image lines parses to the same document
    a, b = yaml.safe_load(COMPOSE), yaml.safe_load(pinned)
    for doc in (a, b):
        for spec in doc["services"].values():
            del spec["image"]
    assert a == b


def test_pin_is_idempotent_and_can_repin(pc):
    once = pc.pin(COMPOSE, "0.4.1")
    assert pc.pin(once, "0.4.1") == once
    assert pc.pin(once, "0.5.0") == pc.pin(COMPOSE, "0.5.0")
    assert pc.pin(COMPOSE, "1.0.0-rc.1").count("${TALLYGATE_VERSION:-1.0.0-rc.1}") == 3


def test_pin_keeps_line_endings_comments_and_trailing_bytes(pc):
    text = (
        "# image: ghcr.io/x/tallygate-agent:${TALLYGATE_VERSION:-latest} (a comment, not a line)\r\n"
        "services:\r\n"
        "  a:\r\n    image: ghcr.io/x/tallygate-gateway:${TALLYGATE_VERSION:-latest}  \r\n"
        "  b:   # note\n    image:  ghcr.io/x/tallygate-control:${TALLYGATE_VERSION:-}\n"
        "  c:\n      image: ghcr.io/x/tallygate-agent:${TALLYGATE_VERSION:-0.1.0}"  # no newline at the end
    )
    assert pc.pin(text, "2.0.0") == (
        "# image: ghcr.io/x/tallygate-agent:${TALLYGATE_VERSION:-latest} (a comment, not a line)\r\n"
        "services:\r\n"
        "  a:\r\n    image: ghcr.io/x/tallygate-gateway:${TALLYGATE_VERSION:-2.0.0}  \r\n"
        "  b:   # note\n    image:  ghcr.io/x/tallygate-control:${TALLYGATE_VERSION:-2.0.0}\n"
        "  c:\n      image: ghcr.io/x/tallygate-agent:${TALLYGATE_VERSION:-2.0.0}"
    )
    assert [(r["service"], r["name"], r["default"]) for r in pc.image_lines(text)] == [
        ("a", "gateway", "latest"),
        ("b", "control", ""),
        ("c", "agent", "0.1.0"),
    ]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (("tallygate-agent:${TALLYGATE_VERSION:-latest}", "tallygate-agent:latest"), "line 1"),
        (("tallygate-agent:${TALLYGATE_VERSION:-latest}", "tallygate-agent:${OTHER:-latest}"), "an image that is not"),
        (("ghcr.io/philippmundhenk/tallygate-control:", "docker.io/library/caddy:"), "an image that is not"),
        (("tallygate-control:", "tallygate-gateway:"), "found: agent, gateway, gateway"),
        (("tallygate-control:", "tallygate-proxy:"), "found: agent, gateway, proxy"),
        (("    image: ghcr.io/philippmundhenk/tallygate-agent:${TALLYGATE_VERSION:-latest}\n", ""), "found: control,"),
        (("${TALLYGATE_VERSION:-latest}", "${TALLYGATE_VERSION:-la test}"), "an image that is not"),
        (("services:", "x-services:"), "an image that is not"),
    ],
)
def test_pin_refuses_a_file_it_does_not_understand(pc, change, message):
    broken = COMPOSE.replace(*change)
    assert broken != COMPOSE
    with pytest.raises(pc.PinError, match=re.escape(message)):
        pc.pin(broken, "0.4.1")


def test_pin_refuses_a_file_without_images(pc):
    with pytest.raises(pc.PinError, match="found: none"):
        pc.pin("services: {}\n", "0.4.1")


@pytest.mark.parametrize("version", ["", "v0.4.1", "0.4", "latest", "0.4.1 ", "0.4.1}", "0.4.1\n", "1.2.3-", "main"])
def test_pin_refuses_what_is_not_a_release_version(pc, version):
    with pytest.raises(pc.PinError, match=r"version must look like 1\.2\.3"):
        pc.pin(COMPOSE, version)


# ------------------------------------------------------------------ digests_override()
def test_digest_override_pins_each_service_to_its_own_image(pc):
    out = pc.digests_override(pc.pin(COMPOSE, "0.4.1"), "0.4.1", D)
    assert yaml.safe_load(out) == {
        "services": {
            "egress-gw": {"image": f"ghcr.io/philippmundhenk/tallygate-gateway:0.4.1@{D['gateway']}"},
            "control": {"image": f"ghcr.io/philippmundhenk/tallygate-control:0.4.1@{D['control']}"},
            "agent": {"image": f"ghcr.io/philippmundhenk/tallygate-agent:0.4.1@{D['agent']}"},
        }
    }
    assert out.startswith("# tallygate 0.4.1: the images of this release by digest.") and out.endswith("\n")
    assert "$" not in out  # no variable is left that could move an image
    assert out == pc.digests_override(COMPOSE, "0.4.1", D)  # the same from the file on main


@pytest.mark.parametrize(
    ("digests", "message"),
    [
        ({}, "need a digest for each of gateway, control, agent; got: none"),
        ({k: v for k, v in D.items() if k != "agent"}, "got: control, gateway"),
        ({**D, "proxy": D["agent"]}, "got: agent, control, gateway, proxy"),
        ({**D, "agent": ""}, "digest of agent must be sha256:"),
        ({**D, "agent": "sha256:" + "A" * 64}, "digest of agent must be sha256:"),
        ({**D, "control": "sha256:" + "a" * 63}, "digest of control must be sha256:"),
        ({**D, "gateway": D["gateway"] + "\n"}, "digest of gateway must be sha256:"),
    ],
)
def test_digest_override_refuses_missing_or_malformed_digests(pc, digests, message):
    with pytest.raises(pc.PinError, match=re.escape(message)):
        pc.digests_override(COMPOSE, "0.4.1", digests)


# ------------------------------------------------------------------ command line (as the release job calls it)
def args(tmp_path, *extra):
    return ["0.4.1", "--compose", str(ROOT / "compose.yaml"), "--out", str(tmp_path / "dist" / "compose.yaml"), *extra]


def test_cli_writes_the_pinned_file_and_the_digest_override(pc, tmp_path, capsys):
    digests = [x for name in D for x in ("--digest", f"{name}={D[name]}")]
    out = tmp_path / "dist"
    assert pc.main(args(tmp_path, *digests, "--digests-out", str(out / "compose.digests.yaml"))) == 0
    assert (out / "compose.yaml").read_bytes() == pc.pin(COMPOSE, "0.4.1").encode()
    assert (out / "compose.digests.yaml").read_text() == pc.digests_override(COMPOSE, "0.4.1", D)
    assert "images default to 0.4.1" in capsys.readouterr().out
    assert (ROOT / "compose.yaml").read_text(encoding="utf-8") == COMPOSE  # the source is untouched
    # in place and again: nothing changes
    assert pc.main(["0.4.1", "--compose", str(out / "compose.yaml"), "--out", str(out / "compose.yaml")]) == 0
    assert (out / "compose.yaml").read_bytes() == pc.pin(COMPOSE, "0.4.1").encode()


def test_cli_without_digests_writes_only_the_compose_file(pc, tmp_path):
    assert pc.main(args(tmp_path)) == 0
    assert sorted(p.name for p in (tmp_path / "dist").iterdir()) == ["compose.yaml"]


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--digest", f"gateway={D['gateway']}"], "--digest and --digests-out belong together"),
        (["--digests-out", "x.yaml"], "--digest and --digests-out belong together"),
        (["--digest", "gateway", "--digests-out", "x.yaml"], "--digest takes NAME=sha256"),
        (
            ["--digest", f"gateway={D['gateway']}", "--digest", f"gateway={D['agent']}", "--digests-out", "x.yaml"],
            "once per image",
        ),
        (["--digest", f"gateway={D['gateway']}", "--digests-out", "x.yaml"], "need a digest for each of"),
        (
            ["--digest", "gateway=", "--digest", "control=", "--digest", "agent=", "--digests-out", "x.yaml"],
            "digest of",
        ),
    ],
)
def test_cli_writes_nothing_when_something_is_wrong(pc, tmp_path, capsys, monkeypatch, extra, message):
    """E.g. an empty job output for a digest: the release job fails instead of attaching a half-pinned file."""
    monkeypatch.chdir(tmp_path)
    assert pc.main(args(tmp_path, *extra)) == 1
    assert message in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_cli_fails_on_a_bad_version_a_missing_or_a_foreign_file(pc, tmp_path, capsys):
    out = ["--out", str(tmp_path / "o.yaml")]
    assert pc.main(["v0.4.1", "--compose", str(ROOT / "compose.yaml"), *out]) == 1
    assert "version must look like 1.2.3" in capsys.readouterr().err
    assert pc.main(["0.4.1", "--compose", str(tmp_path / "missing.yaml"), *out]) == 1
    assert "missing.yaml" in capsys.readouterr().err
    assert pc.main(["0.4.1", "--compose", str(ROOT / "compose.build.yaml"), *out]) == 1  # :local images
    assert "an image that is not" in capsys.readouterr().err
    (tmp_path / "bin.yaml").write_bytes(b"\xff\xfe")
    assert pc.main(["0.4.1", "--compose", str(tmp_path / "bin.yaml"), *out]) == 1
    assert not (tmp_path / "o.yaml").exists()


def test_runs_as_a_script(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["pin_compose.py", *args(tmp_path)])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(str(ROOT / "tools" / "pin_compose.py"), run_name="__main__")
    assert e.value.code == 0 and (tmp_path / "dist" / "compose.yaml").exists()


def test_the_release_job_attaches_the_pinned_files_not_the_one_from_the_checkout():
    """The workflow cannot run here; at least its wiring is checked: pin with the tag's version and the three
    digests of the images job, attach dist/compose.yaml, sign only what was pushed."""
    wf = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = wf["jobs"]
    assert wf["permissions"] == {"contents": "read"}
    pushed = "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"
    # only the images job may ask for an OIDC token, and it signs only where it pushes
    assert [j for j, spec in jobs.items() if "id-token" in (spec.get("permissions") or {})] == ["images"]
    assert jobs["images"]["permissions"] == {"contents": "read", "packages": "write", "id-token": "write"}
    steps = jobs["images"]["steps"]
    cosign = [s for s in steps if "cosign" in (s.get("uses", "") + s.get("run", ""))]
    assert len(cosign) == 2 and all(s["if"] == pushed for s in cosign)
    assert re.fullmatch(r"sigstore/cosign-installer@[0-9a-f]{40}", cosign[0]["uses"])
    assert 'cosign sign --yes "${IMAGE,,}@${DIGEST}"' in cosign[1]["run"]
    assert steps.index(cosign[1]) > next(i for i, s in enumerate(steps) if s.get("id") == "build")
    assert set(jobs["images"]["outputs"]) == {"gateway", "control", "agent"}
    assert sorted(m["key"] for m in jobs["images"]["strategy"]["matrix"]["include"]) == ["agent", "control", "gateway"]
    release = jobs["release"]
    assert release["if"] == "startsWith(github.ref, 'refs/tags/v')" and "images" in release["needs"]
    pin_step = next(s for s in release["steps"] if "pin_compose.py" in s.get("run", ""))
    for name in ("gateway", "control", "agent"):
        assert pin_step["env"][name.upper()] == f"${{{{ needs.images.outputs.{name} }}}}"
        assert f'--digest "{name}=${name.upper()}"' in pin_step["run"]
    files = next(s for s in release["steps"] if "action-gh-release" in s.get("uses", ""))["with"]["files"].split()
    assert "dist/compose.yaml" in files and "dist/compose.digests.yaml" in files and "compose.yaml" not in files
    for spec in jobs.values():  # every action is pinned by commit
        for s in spec["steps"]:
            assert "uses" not in s or re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", s["uses"]), s["uses"]
