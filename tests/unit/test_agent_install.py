"""agent/tallygate-cli.py `tallygate install`: rootless apt/dpkg into a home-volume prefix.

apt-get and dpkg are replaced by a fake that simulates resolving, downloading and unpacking .debs, so the
flow is tested without a real Debian archive or root. The real thing runs inside the agent image.
Exit codes: 0 ok, 1 install failed, 2 usage/environment error.
"""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[2] / "agent" / "tallygate-cli.py"


def load():
    spec = importlib.util.spec_from_file_location("tallygate_cli_install", CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeApt:
    """Simulates apt-get (resolve + download) and dpkg (-f, -X) against a test-defined package world."""

    def __init__(self, mod, resolve, files, versions=None):
        self.mod = mod
        self.resolve = resolve  # top-level package -> list of .deb package names (itself + deps)
        self.files = files  # package name -> list of ./relative paths it ships
        self.versions = versions or {}
        self.calls: list[list[str]] = []
        self.update_rc = 0
        self.install_rc = 0
        self.fail_extract: set[str] = set()  # package names whose `dpkg -X` should fail

    def _deb(self, pkg: str) -> Path:
        return self.mod.APT_CACHE / "archives" / f"{pkg}_{self.versions.get(pkg, '1.0')}_amd64.deb"

    def run(self, cmd, timeout=600):
        self.calls.append(cmd)

        def done(rc=0, out="", err=""):
            return subprocess.CompletedProcess(cmd, rc, out, err)

        if cmd[0] == "apt-get" and cmd[-1] == "update":
            return done(self.update_rc, err="" if self.update_rc == 0 else "could not reach deb.debian.org")
        if cmd[0] == "apt-get" and "install" in cmd:
            if self.install_rc != 0:
                return done(self.install_rc, err="unable to locate package")
            top = cmd[cmd.index("install") + 1 :]
            for pkg in dict.fromkeys(p for t in top for p in self.resolve.get(t, [t])):
                deb = self._deb(pkg)
                deb.parent.mkdir(parents=True, exist_ok=True)
                deb.write_bytes(b"")  # a placeholder archive; dpkg -X below knows its contents
            return done()
        if cmd[0] == "dpkg-deb" and cmd[1] == "-f":
            return done(out=Path(cmd[2]).name.split("_")[0] + "\n")
        if cmd[0] == "dpkg" and cmd[1] == "-X":
            pkg = Path(cmd[2]).name.split("_")[0]
            if pkg in self.fail_extract:
                return done(2, err="dpkg-deb: error: archive is corrupt")
            placed = []
            for rel in self.files.get(pkg, []):
                target = self.mod.INSTALL_ROOT / rel[2:]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(pkg)
                placed.append(rel)
            return done(out="\n".join(placed) + "\n")
        return done(127, err=f"unexpected command {cmd!r}")


@pytest.fixture
def cli(monkeypatch, tmp_path):
    mod = load()
    home = tmp_path / "home"
    monkeypatch.setattr(mod, "HOME_DIR", home)
    monkeypatch.setattr(mod, "APT_STATE", home / ".local/share/tallygate/apt")
    monkeypatch.setattr(mod, "APT_CACHE", home / ".cache/tallygate/apt")
    monkeypatch.setattr(mod, "INSTALL_ROOT", home / ".local/tallygate/root")
    monkeypatch.setattr(mod, "MANIFEST", home / ".local/share/tallygate/apt/installed.json")
    monkeypatch.setattr(mod, "DPKG_STATUS", home / ".local/share/tallygate/apt/dpkg-status")
    monkeypatch.setattr(mod, "IMAGE_DPKG_STATUS", tmp_path / "no-such-status")  # forces the empty-status path
    monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/x")  # apt-get/dpkg present
    return mod


def fake(cli, resolve, files, **kw):
    f = FakeApt(cli, resolve, files, **kw)
    cli._sh = f.run  # type: ignore[assignment]
    return f


# ---------------------------------------------------------------- install
def test_install_resolves_downloads_and_unpacks(cli, capsys):
    fake(cli, {"jq": ["jq", "libjq1"]}, {"jq": ["./usr/bin/jq"], "libjq1": ["./usr/lib/libjq.so.1"]})
    assert cli.main(["install", "jq"]) == 0
    assert (cli.INSTALL_ROOT / "usr/bin/jq").read_text() == "jq"
    assert (cli.INSTALL_ROOT / "usr/lib/libjq.so.1").exists()
    manifest = json.loads(cli.MANIFEST.read_text())
    assert manifest["requested"] == ["jq"]
    assert set(manifest["debs"]) == {"jq_1.0_amd64.deb", "libjq1_1.0_amd64.deb"}
    out = capsys.readouterr().out
    assert "installed jq" in out and "2 package(s) unpacked" in out


def test_install_update_failure_points_at_the_template(cli, capsys):
    f = fake(cli, {}, {})
    f.update_rc = 100
    assert cli.main(["install", "jq"]) == 1
    err = capsys.readouterr().err
    assert "apt-get update" in err and "Debian/apt template" in err


def test_install_download_failure_is_reported(cli, capsys):
    f = fake(cli, {}, {})
    f.install_rc = 100
    assert cli.main(["install", "nope"]) == 1
    assert "could not resolve or download" in capsys.readouterr().err


def test_install_extraction_already_present_is_skipped(cli, capsys):
    f = fake(cli, {"jq": ["jq"]}, {"jq": ["./usr/bin/jq"]})
    assert cli.main(["install", "jq"]) == 0
    before = len(f.calls)
    # second run: the .deb is cached and recorded, so no new extraction happens
    assert cli.main(["install", "jq"]) == 0
    assert "0 package(s) unpacked" in capsys.readouterr().out
    assert any(c[0] == "apt-get" for c in f.calls[before:])  # apt still ran


def test_install_requires_a_package_or_a_flag(cli, capsys):
    assert cli.main(["install"]) == 2
    assert "name at least one package" in capsys.readouterr().err


def test_install_without_apt_is_an_environment_error(cli, capsys, monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)
    assert cli.main(["install", "jq"]) == 2
    assert "apt-get/dpkg not found" in capsys.readouterr().err


# ---------------------------------------------------------------- list
def test_list_is_empty_before_anything(cli, capsys):
    assert cli.main(["install", "--list"]) == 0
    assert "no packages installed" in capsys.readouterr().out


def test_list_shows_requested_and_total(cli, capsys):
    fake(cli, {"jq": ["jq", "libjq1"]}, {"jq": ["./usr/bin/jq"], "libjq1": ["./usr/lib/libjq.so.1"]})
    cli.main(["install", "jq"])
    capsys.readouterr()
    assert cli.main(["install", "--list"]) == 0
    out = capsys.readouterr().out
    assert "requested with 'tallygate install' (1)" in out
    assert "  jq" in out
    assert "2 package(s)" in out


# ---------------------------------------------------------------- remove
def test_remove_deletes_own_files_but_keeps_shared_dependencies(cli, capsys):
    # jq and xmlstarlet both pull in libcommon; removing jq must not delete the shared library.
    fake(
        cli,
        {"jq": ["jq", "libcommon"], "xmlstarlet": ["xmlstarlet", "libcommon"]},
        {
            "jq": ["./usr/bin/jq"],
            "xmlstarlet": ["./usr/bin/xmlstarlet"],
            "libcommon": ["./usr/lib/libcommon.so.1"],
        },
    )
    cli.main(["install", "jq"])
    cli.main(["install", "xmlstarlet"])
    capsys.readouterr()
    assert cli.main(["install", "--remove", "jq"]) == 0
    assert not (cli.INSTALL_ROOT / "usr/bin/jq").exists()
    assert (cli.INSTALL_ROOT / "usr/bin/xmlstarlet").exists()
    assert (cli.INSTALL_ROOT / "usr/lib/libcommon.so.1").exists()  # still needed by xmlstarlet
    manifest = json.loads(cli.MANIFEST.read_text())
    assert manifest["requested"] == ["xmlstarlet"]
    assert "jq_1.0_amd64.deb" not in manifest["debs"]
    assert "removed jq" in capsys.readouterr().out


def test_remove_unknown_package_reports_and_exits_1(cli, capsys):
    assert cli.main(["install", "--remove", "ghost"]) == 1
    assert "ghost is not installed" in capsys.readouterr().err


# ---------------------------------------------------------------- reset
def test_reset_clears_the_prefix(cli, capsys):
    fake(cli, {"jq": ["jq"]}, {"jq": ["./usr/bin/jq"]})
    cli.main(["install", "jq"])
    assert (cli.INSTALL_ROOT / "usr/bin/jq").exists()
    capsys.readouterr()
    assert cli.main(["install", "--reset"]) == 0
    assert not cli.INSTALL_ROOT.exists()
    assert not cli.APT_STATE.exists()
    assert "removed every" in capsys.readouterr().out


def test_remove_keeps_a_file_a_retained_package_also_ships(cli, capsys):
    # jq and jqdoc both ship the same man page; removing jq must leave it for jqdoc.
    man = "./usr/share/man/man1/jq.1"
    fake(cli, {"jq": ["jq", "jqdoc"]}, {"jq": ["./usr/bin/jq", man], "jqdoc": [man]})
    cli.main(["install", "jq"])
    capsys.readouterr()
    assert cli.main(["install", "--remove", "jq"]) == 0
    assert not (cli.INSTALL_ROOT / "usr/bin/jq").exists()
    assert (cli.INSTALL_ROOT / man[2:]).exists()  # kept: jqdoc still provides it


# ---------------------------------------------------------------- extraction failures
def test_extraction_failure_is_reported_and_manifest_saved(cli, capsys):
    f = fake(cli, {"jq": ["jq"]}, {"jq": ["./usr/bin/jq"]})
    f.fail_extract = {"jq"}
    assert cli.main(["install", "jq"]) == 1
    assert "could not unpack" in capsys.readouterr().err
    assert cli.MANIFEST.exists()  # partial manifest is persisted so a retry resumes


# ---------------------------------------------------------------- helpers
def test_prune_empty_dirs_tolerates_a_missing_prefix(cli):
    cli._prune_empty_dirs(cli.INSTALL_ROOT)  # does not raise when nothing was installed


def test_sh_runs_a_real_command(cli):
    r = cli._sh(["true"])
    assert r.returncode == 0


# ---------------------------------------------------------------- path safety
def test_prefix_path_rejects_escapes(cli):
    assert cli._prefix_path("./usr/bin/jq") == cli.INSTALL_ROOT / "usr/bin/jq"
    assert cli._prefix_path("../../etc/passwd") is None
    assert cli._prefix_path("./../outside") is None
