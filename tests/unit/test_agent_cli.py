"""agent/tallygate-cli.py (`tallygate` in the agent) against a fake gateway grant API.

Exit codes are the contract with the agent: 0 granted, 1 denied/expired, 2 usage/connection error.
"""

import importlib.util
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[2] / "agent" / "tallygate-cli.py"


class FakeGateway:
    """Answers each (method, path) with the next scripted (status, body); records the requests."""

    def __init__(self) -> None:
        self.script: dict[tuple[str, str], list[tuple[int, object]]] = {}
        self.seen: list[tuple[str, str, dict | None, dict]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                fake.seen.append((self.command, self.path, body, dict(self.headers)))
                replies = fake.script.get((self.command, self.path)) or [(404, {"error": "unknown"})]
                status, payload = replies.pop(0) if len(replies) > 1 else replies[0]
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = _any

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def on(self, method: str, path: str, *replies):
        self.script[(method, path)] = list(replies)


def load(monkeypatch, url: str):
    monkeypatch.setenv("TALLYGATE_URL", url)
    spec = importlib.util.spec_from_file_location("tallygate_cli", CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def fake():
    f = FakeGateway()
    yield f
    f.srv.shutdown()


@pytest.fixture
def cli(fake, monkeypatch):
    # The agent's environment points every client at the egress proxy: the CLI must ignore it.
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    return load(monkeypatch, fake.url + "/")


def req(rid="r1", status="pending", level="read", granted=None, ttl=3600, name="svc"):
    return {"id": rid, "status": status, "grant": name, "level": level, "granted_level": granted or level, "ttl": ttl}


# ---------------------------------------------------------------- configuration
@pytest.mark.parametrize("url", ["file:///etc/passwd", "172.31.10.2:8079", "ftp://gw"])
def test_non_http_url_is_refused_at_start(monkeypatch, url):
    with pytest.raises(SystemExit, match="must be an http"):
        load(monkeypatch, url)


def test_unreachable_gateway_is_a_clean_error(monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # closed again: nothing listens there
    mod = load(monkeypatch, f"http://127.0.0.1:{port}")
    with pytest.raises(SystemExit, match="cannot reach the gateway"):
        mod.main(["grants"])


def test_usage_errors_exit_2(cli, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["request", "svc"])  # --reason is required
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 2


# ---------------------------------------------------------------- grants
def test_grants_lists_active_and_inactive(cli, fake, capsys, monkeypatch):
    monkeypatch.setattr(cli.time, "time", lambda: 1000.0)
    grant = {"levels": ["read", "write"], "default_ttl": "1h", "max_ttl": "8h"}
    fake.on(
        "GET",
        "/v1/grants",
        (
            200,
            {
                "grants": [
                    {**grant, "name": "svc", "description": "echo API", "targets": ["http://svc.test/api/*"]},
                    {
                        **grant,
                        "name": "lan",
                        "description": "",
                        "targets": [],
                        "active": {"level": "write", "expires": 1000 + 25 * 60 + 30},
                    },
                    {
                        **grant,
                        "name": "old",
                        "description": "",
                        "targets": [],
                        "active": {"level": "read", "expires": 1},
                    },
                ]
            },
        ),
    )
    assert cli.main(["grants"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "svc  [inactive]  levels: read, write  default 1h, max 8h"
    assert out[1:3] == ["    echo API", "    - http://svc.test/api/*"]
    assert out[3].startswith("lan  [ACTIVE (write, 25 min left)]")
    assert out[4].startswith("old  [ACTIVE (read, 0 min left)]")  # never negative
    assert len(out) == 5  # empty descriptions print nothing (and the proxy env was ignored, or this had failed)


def test_grants_none_defined(cli, fake, capsys):
    fake.on("GET", "/v1/grants", (200, {"grants": []}))
    assert cli.main(["grants"]) == 0
    assert "No grants are defined" in capsys.readouterr().out


def test_grants_error_from_the_gateway(cli, fake):
    fake.on("GET", "/v1/grants", (429, {"error": "rate limited"}))
    with pytest.raises(SystemExit, match="tallygate: rate limited"):
        cli.main(["grants"])


def test_non_json_error_body_falls_back_to_the_http_reason(cli, fake):
    fake.on("GET", "/v1/grants", (502, b"<html>bad gateway</html>"))
    with pytest.raises(SystemExit, match="tallygate: Bad Gateway"):
        cli.main(["grants"])


# ---------------------------------------------------------------- request
def test_request_sends_level_ttl_and_reason_and_reports_auto_approval(cli, fake, capsys):
    fake.on("POST", "/v1/grants/svc/request", (200, req(status="approved", ttl=1800)))
    assert cli.main(["request", "svc", "--ttl", "30m", "--reason", "read states"]) == 0
    assert fake.seen[0][2] == {"level": "read", "reason": "read states", "ttl": "30m"}
    assert capsys.readouterr().out == "granted: svc (read) for 30 min\n"


def test_request_without_ttl_leaves_it_to_the_grant(cli, fake):
    fake.on("POST", "/v1/grants/svc/request", (200, req(status="approved", level="write")))
    assert cli.main(["request", "svc", "--write", "--reason", "x"]) == 0
    assert fake.seen[0][2] == {"level": "write", "reason": "x"}


def test_request_refused_by_the_gateway_exits_2(cli, fake, capsys):
    fake.on("POST", "/v1/grants/nope/request", (404, {"error": "no such grant"}))
    assert cli.main(["request", "nope", "--reason", "x"]) == 2
    assert "tallygate: no such grant" in capsys.readouterr().err


def test_request_no_wait_prints_the_id(cli, fake, capsys):
    fake.on("POST", "/v1/grants/svc/request", (202, req(rid="abc")))
    assert cli.main(["request", "svc", "--write", "--reason", "x", "--no-wait"]) == 0
    assert "check with: tallygate status abc" in capsys.readouterr().out
    assert len(fake.seen) == 1  # did not poll


def test_request_waits_and_reports_a_downgrade(cli, fake, capsys):
    fake.on("POST", "/v1/grants/svc/request", (202, req(level="write")))
    fake.on(
        "GET",
        "/v1/requests/r1?wait=50",
        (200, req(level="write")),
        (200, req(status="approved", level="write", granted="read", ttl=600)),
    )
    assert cli.main(["request", "svc", "--write", "--reason", "x"]) == 0
    out, err = capsys.readouterr()
    assert "waiting for a human to approve grant 'svc' (write)" in err
    assert out.splitlines() == [
        "granted: svc (read) for 10 min",
        "note: you asked for write but were granted read only",
    ]
    assert [s[1] for s in fake.seen].count("/v1/requests/r1?wait=50") == 2


def test_request_denied_exits_1(cli, fake, capsys):
    fake.on("POST", "/v1/grants/svc/request", (202, req(level="write")))
    fake.on("GET", "/v1/requests/r1?wait=50", (200, req(status="denied", level="write")))
    assert cli.main(["request", "svc", "--write", "--reason", "x"]) == 1
    assert capsys.readouterr().out == "denied: svc (write)\n"


def test_request_gives_up_after_the_timeout(cli, fake, capsys):
    fake.on("POST", "/v1/grants/svc/request", (202, req()))
    fake.on("GET", "/v1/requests/r1?wait=50", (200, req()))
    assert cli.main(["request", "svc", "--reason", "x", "--timeout", "0"]) == 1
    assert capsys.readouterr().out == "pending: svc (read)\n"


def test_request_wait_error_exits(cli, fake):
    fake.on("POST", "/v1/grants/svc/request", (202, req()))
    fake.on("GET", "/v1/requests/r1?wait=50", (404, {"error": "unknown request"}))
    with pytest.raises(SystemExit, match="tallygate: unknown request"):
        cli.main(["request", "svc", "--reason", "x"])


# ---------------------------------------------------------------- status
@pytest.mark.parametrize(("state", "code"), [("approved", 0), ("pending", 0), ("denied", 1), ("expired", 1)])
def test_status_exit_codes(cli, fake, capsys, state, code):
    fake.on("GET", "/v1/requests/r9", (200, req(rid="r9", status=state)))
    assert cli.main(["status", "r9"]) == code
    out = capsys.readouterr().out
    assert out.startswith("granted: svc (read)" if state == "approved" else f"{state}: svc (read)")


def test_status_unknown_request(cli, fake):
    fake.on("GET", "/v1/requests/zz", (404, {}))
    with pytest.raises(SystemExit, match="tallygate: 404"):
        cli.main(["status", "zz"])


# ---------------------------------------------------------------- operator away / quiet hours (#73)
def test_grants_shows_when_the_operator_is_away(cli, fake, capsys):
    msg = "operator away: unknown destinations are refused without asking"
    fake.on("GET", "/v1/grants", (200, {"grants": [], "operator": {"state": "away", "message": msg}}))
    assert cli.main(["grants"]) == 0
    assert capsys.readouterr().out.startswith(f"note: {msg}\n")


def test_request_while_away_is_a_denial_not_an_error(cli, fake, capsys):
    fake.on("POST", "/v1/grants/svc/request", (503, {"error": "quiet hours until 07:00: ...", "status": "denied"}))
    assert cli.main(["request", "svc", "--reason", "x"]) == 1
    assert "denied: quiet hours until 07:00" in capsys.readouterr().out
