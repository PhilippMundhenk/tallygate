"""agent/status.py workspace files (#76): strictly inside the workspace, no traversal, no symlink escapes,
regular files only, uploads through a temporary file."""

import http.client
import importlib.util
import io
import json
import os
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

STATUS = Path(__file__).resolve().parents[2] / "agent" / "status.py"


@pytest.fixture
def st(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("agent_status_files", STATUS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(mod, "WORKSPACE", ws)
    return mod


@pytest.fixture
def ws(st):
    return st.WORKSPACE


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, ""), ("", ""), ("a", "a"), ("a//b/", "a/b"), ("dir/ü file.txt", "dir/ü file.txt"), ("x" * 255, "x" * 255)],
)
def test_rel_path_normalises(st, raw, expected):
    assert st.rel_path(raw) == expected


@pytest.mark.parametrize(
    "raw", ["/etc/passwd", "..", "a/../b", "./a", "a/.", "a\\b", "a\x00b", "a\nb", "x" * 256, "a/" * 600]
)
def test_rel_path_refuses_traversal_and_odd_names(st, raw):
    with pytest.raises(st.SetupError, match="invalid path") as e:
        st.rel_path(raw)
    assert e.value.status == 400


def test_symlinks_must_stay_inside(st, ws, tmp_path):
    (tmp_path / "secret").write_text("outside")
    (ws / "out").symlink_to(tmp_path / "secret")
    (ws / "outdir").symlink_to(tmp_path)
    (ws / "in").symlink_to(ws / "real")
    (ws / "real").write_text("inside")
    for rel in ("out", "outdir", "outdir/secret"):
        with pytest.raises(st.SetupError, match="outside the workspace") as e:
            st.inside(rel)
        assert e.value.status == 403
    assert st.inside("in") == Path(os.path.realpath(ws / "real"))
    assert st.inside("") == Path(os.path.realpath(ws))


def test_list_dirs_first_with_types(st, ws, monkeypatch):
    (ws / "b.txt").write_bytes(b"12345")
    (ws / "A-dir").mkdir()
    (ws / "c-link").symlink_to(ws / "b.txt")
    os.mkfifo(ws / "d-fifo")
    os.close(os.open(os.path.join(os.fsencode(ws), b"bad-\xff"), os.O_CREAT | os.O_WRONLY))  # not UTF-8: skipped
    r = st.files_list({})
    assert r["path"] == "" and r["truncated"] is False
    assert [(e["name"], e["type"]) for e in r["entries"]] == [
        ("A-dir", "dir"),
        ("b.txt", "file"),
        ("c-link", "link"),
        ("d-fifo", "other"),
    ]
    assert r["entries"][1]["size"] == 5 and r["entries"][1]["mtime"] > 0
    assert st.files_list({"path": "A-dir"}) == {"path": "A-dir", "entries": [], "truncated": False}
    for path, code in (("b.txt", 404), ("missing", 404), ("../x", 400)):
        with pytest.raises(st.SetupError) as e:
            st.files_list({"path": path})
        assert e.value.status == code
    monkeypatch.setattr(st, "FILES_MAX_ENTRIES", 2)
    r = st.files_list({})
    assert len(r["entries"]) == 2 and r["truncated"] is True


def test_list_skips_entries_that_vanish(st, ws, monkeypatch):
    (ws / "x").write_text("x")
    real = os.scandir

    class Gone:
        name = "gone"

        def stat(self, follow_symlinks=True):
            raise FileNotFoundError

    def scandir(path):
        it = real(path)

        class Wrap:
            def __enter__(self):
                return iter([Gone(), *it])

            def __exit__(self, *a):
                it.close()

        return Wrap()

    monkeypatch.setattr(st.os, "scandir", scandir)
    assert [e["name"] for e in st.files_list({})["entries"]] == ["x"]


def test_open_regular_files_only(st, ws, tmp_path):
    (ws / "f").write_text("data")
    (ws / "d").mkdir()
    os.mkfifo(ws / "p")
    (ws / "loop").symlink_to(ws / "loop")
    fd = st.open_regular("f")
    assert os.read(fd, 10) == b"data"
    os.close(fd)
    for rel, code in (("", 400), ("missing", 404), ("d", 400), ("p", 400), ("loop", 403)):
        with pytest.raises(st.SetupError) as e:
            st.open_regular(rel)
        assert e.value.status == code, rel


def test_write_upload(st, ws):
    data = b"x" * 200_000
    assert st.write_upload("new.bin", len(data), io.BytesIO(data).read, False) == {"path": "new.bin", "size": 200_000}
    assert (ws / "new.bin").read_bytes() == data
    with pytest.raises(st.SetupError, match="a file of this name exists") as e:
        st.write_upload("new.bin", 1, io.BytesIO(b"y").read, False)
    assert e.value.status == 409
    st.write_upload("new.bin", 1, io.BytesIO(b"y").read, True)
    assert (ws / "new.bin").read_bytes() == b"y"
    (ws / "d").mkdir()
    (ws / "l").symlink_to(ws / "new.bin")
    for rel in ("d", "l"):
        with pytest.raises(st.SetupError, match="folder or link") as e:
            st.write_upload(rel, 1, io.BytesIO(b"y").read, True)
        assert e.value.status == 409
    with pytest.raises(st.SetupError, match="no such folder"):
        st.write_upload("missing/x", 1, io.BytesIO(b"y").read, False)
    with pytest.raises(st.SetupError, match="no file name"):
        st.write_upload("", 1, io.BytesIO(b"y").read, False)
    with pytest.raises(st.SetupError, match="ended early"):
        st.write_upload("d/short", 10, io.BytesIO(b"abc").read, False)
    assert os.listdir(ws / "d") == []  # the temporary file is gone
    st.write_upload("d/empty", 0, io.BytesIO(b"").read, False)
    assert (ws / "d" / "empty").read_bytes() == b""


def test_delete_files_folders_and_links(st, ws):
    (ws / "f.txt").write_text("x")
    (ws / "d" / "sub").mkdir(parents=True)
    (ws / "d" / "sub" / "deep.txt").write_text("y")
    assert st.delete_path({"path": "f.txt"}) == {"path": "f.txt", "type": "file"}
    assert not (ws / "f.txt").exists()
    assert st.delete_path({"path": "d/sub/deep.txt"}) == {"path": "d/sub/deep.txt", "type": "file"}
    (ws / "d" / "sub" / "again.txt").write_text("z")
    assert st.delete_path({"path": "d//"}) == {"path": "d", "type": "dir"}
    assert not (ws / "d").exists() and ws.is_dir()


def test_delete_never_leaves_the_workspace(st, ws, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    (outside / "secret").write_text("secret")
    (ws / "out").symlink_to(outside / "secret")
    (ws / "outdir").symlink_to(outside)
    (ws / "tree").mkdir()
    (ws / "tree" / "inner").symlink_to(outside)
    (ws / "self").symlink_to(ws)
    # through a link that leaves the workspace: refused, nothing touched
    with pytest.raises(st.SetupError, match="outside the workspace") as e:
        st.delete_path({"path": "outdir/keep.txt"})
    assert e.value.status == 403
    # a link itself is removed, never its target
    assert st.delete_path({"path": "out"}) == {"path": "out", "type": "file"}
    assert st.delete_path({"path": "outdir"}) == {"path": "outdir", "type": "file"}
    assert st.delete_path({"path": "self"}) == {"path": "self", "type": "file"}
    # a folder is removed without descending into the links in it
    assert st.delete_path({"path": "tree"}) == {"path": "tree", "type": "dir"}
    assert sorted(os.listdir(outside)) == ["keep.txt", "secret"] and (outside / "secret").read_text() == "secret"
    assert os.listdir(ws) == []


def test_delete_refusals(st, ws, monkeypatch):
    (ws / "f").write_text("x")
    for path in ("", None):
        with pytest.raises(st.SetupError, match="the workspace itself cannot be deleted") as e:
            st.delete_path({"path": path})
        assert e.value.status == 400
    cases = (("/", 400), ("../x", 400), ("a/../f", 400), ("/etc/passwd", 400), ("missing", 404), ("f/below", 404))
    for path, code in cases:
        with pytest.raises(st.SetupError) as e:
            st.delete_path({"path": path})
        assert e.value.status == code, path
    assert (ws / "f").read_text() == "x" and ws.is_dir()

    def denied(*a, **k):
        raise PermissionError("read-only")

    monkeypatch.setattr(st.os, "unlink", denied)
    with pytest.raises(st.SetupError, match="cannot delete this") as e:
        st.delete_path({"path": "f"})
    assert e.value.status == 403


# ---------------------------------------------------------------- HTTP
@pytest.fixture
def server(st):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), st.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def request(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, dict(r.getheaders()), data


def test_http_list_download_upload(st, ws, server, monkeypatch):
    (ws / "sub").mkdir()
    (ws / "sub" / "r.txt").write_bytes(b"result")
    status, _, data = request(server, "GET", "/files?path=sub")
    assert status == 200 and json.loads(data)["entries"][0]["name"] == "r.txt"
    status, headers, data = request(server, "GET", "/files/download?path=sub/r.txt")
    assert status == 200 and data == b"result"
    assert headers["Content-Type"] == "application/octet-stream" and headers["Content-Length"] == "6"
    status, _, data = request(server, "GET", "/files/download?path=../etc/passwd")
    assert status == 400 and json.loads(data) == {"error": "invalid path"}
    status, _, data = request(server, "PUT", "/files?path=sub/up.txt", b"hello", {"Content-Length": "5"})
    assert status == 200 and json.loads(data) == {"path": "sub/up.txt", "size": 5}
    assert (ws / "sub" / "up.txt").read_bytes() == b"hello"
    status, _, data = request(server, "PUT", "/files?path=sub/up.txt", b"again", {"Content-Length": "5"})
    assert status == 409
    status, _, _ = request(server, "PUT", "/files?path=sub/up.txt&overwrite=1", b"again", {"Content-Length": "5"})
    assert status == 200 and (ws / "sub" / "up.txt").read_bytes() == b"again"
    assert request(server, "PUT", "/other", b"x", {"Content-Length": "1"})[0] == 404
    monkeypatch.setattr(st, "FILES_HARD_MAX", 3)
    assert request(server, "PUT", "/files?path=big", b"toolong", {"Content-Length": "7"})[0] == 413


def test_http_upload_needs_a_length(st, server):
    c = http.client.HTTPConnection("127.0.0.1", server, timeout=5)
    c.putrequest("PUT", "/files?path=x")
    c.putheader("Transfer-Encoding", "chunked")
    c.endheaders()
    c.send(b"1\r\nx\r\n0\r\n\r\n")
    r = c.getresponse()
    assert r.status == 411
    c.close()


def test_http_delete(st, ws, server, tmp_path):
    (ws / "sub").mkdir()
    (ws / "sub" / "r.txt").write_bytes(b"result")
    (tmp_path / "secret").write_text("outside")
    (ws / "esc").symlink_to(tmp_path)
    status, _, data = request(server, "DELETE", "/files?path=sub/r.txt")
    assert status == 200 and json.loads(data) == {"path": "sub/r.txt", "type": "file"}
    status, _, data = request(server, "DELETE", "/files?path=sub/r.txt")
    assert status == 404 and json.loads(data) == {"error": "no such file or folder"}
    status, _, data = request(server, "DELETE", "/files?path=sub")
    assert status == 200 and json.loads(data) == {"path": "sub", "type": "dir"} and not (ws / "sub").exists()
    assert request(server, "DELETE", "/files?path=../x")[0] == 400
    assert request(server, "DELETE", "/files")[0] == 400  # the workspace itself
    assert request(server, "DELETE", "/files?path=esc/secret")[0] == 403
    assert request(server, "DELETE", "/other?path=x")[0] == 404
    assert (tmp_path / "secret").read_text() == "outside" and ws.is_dir()
