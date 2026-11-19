"""What the images are built from and how CI treats it (#234): hashed lock files for pip, an npm lock file for
Claude Code, the pinned GitHub CLI keyring, no expression pasted into a workflow script, a blocking image scan.

Docker and GitHub Actions cannot run in the unit tests, so these check the wiring; the image builds and the
workflow runs prove the rest."""

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
LOCKS = {
    "gateway/requirements.txt": "gateway/requirements.in",
    "control/requirements.txt": "control/requirements.in",
    "requirements-dev.txt": "requirements-dev.in",
}
ENTRY = re.compile(r"^([A-Za-z0-9._-]+)==([^\s;\\]+)[^\n]*\\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", re.M)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def pins(path: str) -> dict[str, str]:
    return {name.lower(): version for name, version, _ in ENTRY.findall(read(path))}


def workflows() -> dict[str, dict]:
    return {p.name: yaml.safe_load(p.read_text(encoding="utf-8")) for p in (ROOT / ".github/workflows").glob("*.yml")}


# ------------------------------------------------------------------ pip
@pytest.mark.parametrize("lock", LOCKS)
def test_every_package_in_a_lock_file_has_a_version_and_hashes(lock):
    text = read(lock)
    assert "--universal" in text.splitlines()[1] and "--generate-hashes" in text.splitlines()[1]
    # every requirement line is one the pattern understands: name==version, then only sha256 hashes
    requirement_lines = [line for line in text.splitlines() if line and not line.startswith(("#", " "))]
    assert len(requirement_lines) == len(ENTRY.findall(text)) > 5
    assert not re.search(
        r"^\s*(-e|--index-url|--extra-index-url|--find-links|--trusted-host|git\+|https?:)", text, re.M
    )


@pytest.mark.parametrize("lock", LOCKS)
def test_a_lock_file_carries_the_pins_of_its_in_file(lock):
    locked = pins(lock)
    direct = re.findall(r"^([A-Za-z0-9._-]+)==(\S+)$", read(LOCKS[lock]), re.M)
    assert direct
    for name, version in direct:
        assert locked[name.lower()] == version, (lock, name)


def test_the_dev_lock_installs_what_the_images_install():
    """Tests run against requirements-dev.txt, the images are built from the other two: same versions."""
    dev = pins("requirements-dev.txt")
    assert "-r gateway/requirements.in" in read("requirements-dev.in")
    assert "-r control/requirements.in" in read("requirements-dev.in")
    for lock in ("gateway/requirements.txt", "control/requirements.txt"):
        for name, version in pins(lock).items():
            assert dev.get(name) == version, (lock, name)


def test_pip_only_installs_with_required_hashes():
    for dockerfile in ("gateway/Dockerfile", "control/Dockerfile"):
        installs = re.findall(r"pip install[^\n]*", read(dockerfile))
        assert installs and all("--require-hashes -r /app/requirements.txt" in i for i in installs), dockerfile
    assert "pip install --require-hashes -r requirements-dev.txt" in read("Makefile")
    ci = read(".github/workflows/ci.yml")
    installs = re.findall(r"pip install[^\n]*", ci)
    assert len(installs) == 2 and all("--require-hashes" in i for i in installs), installs
    dependabot = yaml.safe_load(read(".github/dependabot.yml"))["updates"]
    python = [u for u in dependabot if u["package-ecosystem"] in ("pip", "uv")]
    assert [u["package-ecosystem"] for u in python] == ["uv"]  # the one that recompiles `uv pip compile` files
    assert sorted(python[0]["directories"]) == ["/", "/control", "/gateway"]


def test_the_lint_job_takes_ruff_and_shellcheck_with_their_hashes_from_the_lock():
    """The awk line of the lint job, done here: exactly the two entries, each with its hashes."""
    out, take = [], False
    for line in read("requirements-dev.txt").splitlines():
        take = take or bool(re.match(r"(ruff|shellcheck-py)==", line))
        if take:
            out.append(line)
            take = line.endswith("\\")
    assert [line.split("==")[0] for line in out if not line.startswith(" ")] == ["ruff", "shellcheck-py"]
    assert all(line.startswith("    --hash=sha256:") for line in out if line.startswith(" ")) and len(out) > 4


# ------------------------------------------------------------------ Claude Code (npm)
def test_claude_code_is_locked_with_integrity_hashes():
    package = json.loads(read("agent/claude-code/package.json"))
    lock = json.loads(read("agent/claude-code/package-lock.json"))
    version = package["dependencies"]["@anthropic-ai/claude-code"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", version) and list(package["dependencies"]) == ["@anthropic-ai/claude-code"]
    assert lock["lockfileVersion"] == 3
    assert lock["packages"][""]["dependencies"] == package["dependencies"]
    packages = {k: v for k, v in lock["packages"].items() if k}
    assert "node_modules/@anthropic-ai/claude-code" in packages and len(packages) >= 3
    for name, spec in packages.items():
        assert name.startswith("node_modules/@anthropic-ai/claude-code"), name
        assert spec["version"] == version, name
        assert re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", spec["integrity"]), name
        assert spec["resolved"].startswith("https://registry.npmjs.org/@anthropic-ai/"), name
    for arch in ("linux-x64", "linux-arm64"):  # the platforms the image is built for
        assert f"node_modules/@anthropic-ai/claude-code-{arch}" in packages


def test_the_agent_image_installs_claude_code_from_the_lock():
    dockerfile = read("agent/Dockerfile")
    assert 'ARG CLAUDE_VERSION=""' in dockerfile
    assert "COPY claude-code/package.json claude-code/package-lock.json /usr/local/lib/claude-code/" in dockerfile
    assert "(cd /usr/local/lib/claude-code && npm ci --no-fund --no-audit --omit=dev)" in dockerfile
    # the only install by version is the operator's explicit override, and it says what it is
    by_version = [line for line in dockerfile.splitlines() if "npm install" in line]
    assert len(by_version) == 1 and '"@anthropic-ai/claude-code@${CLAUDE_VERSION}"' in by_version[0]
    assert "WITHOUT a pinned hash" in dockerfile


def test_the_update_workflow_bumps_the_lock_and_checks_it():
    run = "\n".join(s.get("run", "") for s in workflows()["claude-code.yml"]["jobs"]["bump"]["steps"])
    assert "agent/claude-code/package.json" in run and "npm install --package-lock-only --ignore-scripts" in run
    assert "--save-exact" in run and 'startswith("sha512-")' in run and "git add agent/claude-code" in run
    assert "ARG CLAUDE_VERSION" not in run


# ------------------------------------------------------------------ GitHub CLI keyring
def test_the_github_cli_keyring_is_pinned_as_a_file_and_as_a_set_of_keys():
    dockerfile = read("agent/Dockerfile")
    sha = re.search(r"^ARG GH_ARCHIVE_GPG_SHA256=([0-9a-f]{64})$", dockerfile, re.M)
    fprs = re.search(r'^ARG GH_ARCHIVE_SIGNERS="((?:[0-9A-F]{40} ?)+)"$', dockerfile, re.M)
    assert sha and fprs
    assert fprs[1].split() == sorted(fprs[1].split()) and len(set(fprs[1].split())) == 2  # compared sorted
    assert (
        '[ "$(sha256sum "$k" | cut -d\' \' -f1)" = "${GH_ARCHIVE_GPG_SHA256}" ] && [ "$fprs" = "${GH_ARCHIVE_SIGNERS}" ]'
        in dockerfile
    )
    assert "grep -q" not in dockerfile  # "contains the pinned key" was the hole


# ------------------------------------------------------------------ workflows
def test_no_workflow_script_contains_an_expression():
    """`${{ … }}` in a `run:` is pasted into the script before the shell sees it; a tag or branch name with
    shell syntax in it would run. Values reach scripts through `env:` or the runner's own variables."""
    seen = 0
    for name, wf in workflows().items():
        for job, spec in wf["jobs"].items():
            for step in spec["steps"]:
                seen += "run" in step
                assert "${{" not in step.get("run", ""), (name, job, step.get("name") or step.get("id"))
    assert seen > 10
    consistency = workflows()["ci.yml"]["jobs"]["consistency"]["steps"][-1]["run"]
    assert '--version "$GITHUB_REF_NAME"' in consistency and "$GITHUB_REF == refs/tags/v*" in consistency


def test_a_critical_finding_in_an_image_blocks_the_release():
    jobs = workflows()["ci.yml"]["jobs"]
    assert {"images", "image-scan", "consistency"} <= set(jobs["release"]["needs"])
    scan = jobs["image-scan"]
    assert scan["needs"] == ["images"] and scan["strategy"]["fail-fast"] is False
    assert scan["if"] == "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"
    assert "continue-on-error" not in scan
    trivy = [s for s in scan["steps"] if "trivy-action" in s.get("uses", "")]
    report, gate = trivy
    assert report["with"]["exit-code"] == "0" and report["with"]["severity"] == "CRITICAL,HIGH"
    assert gate["with"] == {
        "image-ref": "${{ steps.ref.outputs.image }}",
        "severity": "CRITICAL",
        "ignore-unfixed": True,
        "trivyignores": ".trivyignore",
        "exit-code": "1",
    }
    assert not any("continue-on-error" in s for s in scan["steps"])
    # every accepted finding has a comment above it
    lines = read(".trivyignore").splitlines()
    for i, line in enumerate(lines):
        if line.strip() and not line.startswith("#"):
            assert re.fullmatch(r"(CVE-\d{4}-\d+|GHSA(-[0-9a-z]{4}){3})", line.strip()), line
            assert i > 0 and lines[i - 1].startswith("# ") and len(lines[i - 1]) > 30, line


# ------------------------------------------------------------------ docs
def test_documented_commands_over_the_volumes_use_a_pinned_image_and_private_archives():
    """The backup holds the GitHub token, the CA key and the Claude login: never world-readable, and no
    unpinned image runs as root over a volume."""
    ops = read("docs/operations.md")
    # pinned by digest. It was the agent image's base when written; it need not follow every base image bump
    # (an older digest stays pullable), so this does not compare it with agent/Dockerfile.
    pinned = re.findall(r"^IMG=(\S+)$", ops, re.M)
    assert len(pinned) == 2 and len(set(pinned)) == 1
    assert re.fullmatch(r"docker\.io/library/debian:trixie-slim@sha256:[0-9a-f]{64}", pinned[0])
    backup = ops[ops.index("## Backup and restore") : ops.index("## Resetting the agent after a compromise")]
    assert backup.index("umask 077") < backup.index("tar czf")
    assert '-v "$PWD":/b' not in ops  # the archive is written by the caller's shell, not by root in a container
    for line in ops.splitlines():
        if "docker run" in line and "tallygate_" in line:
            assert '"$IMG"' in line and "--network none" in line, line
    assert not re.search(r"\sdebian (tar|sh)\b", ops)


def test_the_reset_procedure_is_documented_and_linked():
    ops = read("docs/operations.md")
    assert "- [Resetting the agent after a compromise](#resetting-the-agent-after-a-compromise)" in ops
    reset = ops[ops.index("\n## Resetting the agent after a compromise") : ops.index("\n## Monitoring")]
    for needle in (
        "~/.local/tallygate/root",
        "~/.claude",
        "~/.gitconfig",
        "~/.bashrc",
        "tallygate-rc-pointer.json",
        "docker volume rm tallygate_agent-home",
        "tallygate install --reset",
        "GitHub token",
        "Claude login",
        "[First-time setup](#first-time-setup)",
    ):
        assert needle in reset, needle
    # what the procedure names is what the agent really uses
    assert ".local/tallygate/root" in read("agent/profile.d-tallygate-install.sh")
    assert "$HOME/.claude/tallygate-rc-pointer.json" in read("agent/rc-loop.sh")
    threat = read("docs/threat-model.md")
    assert "(operations.md#resetting-the-agent-after-a-compromise)" in threat
    for number in ("T56", "T57", "T58"):
        assert len(re.findall(rf"^\| {number} \|", threat, re.M)) == 1
