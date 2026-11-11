"""End-to-end fixtures: real egress-gw (mitmdump) and control processes on localhost, local upstream
echo servers (HTTP + HTTPS with a throwaway CA), and a mock Telegram/Matrix server.

No Docker and no root needed. Runs in CI and on a laptop:  pytest tests/e2e
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from .helpers import Api, wait_http

ROOT = Path(__file__).resolve().parents[2]
API_TOKEN = "e2e-token-e2e-token-e2e-token"
CONTROL_PASSWORD = "e2e-password"
TTYD_CREDENTIAL = "agent:e2e-ttyd"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def clean_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env.update({k: str(v) for k, v in extra.items()})
    return env


# ------------------------------------------------------------------ certificates
def make_cert(tmp: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gh.test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("gh.test"), x509.DNSName("other.test"), x509.DNSName("ro.test"), x509.DNSName("sec.test")]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_p, key_p = tmp / "upstream.pem", tmp / "upstream.key"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_p, key_p


# ------------------------------------------------------------------ upstream echo servers
class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Content-Length"):
            self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps(
            {
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "host": self.headers.get("Host"),
                "method": self.command,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_GET

    def log_message(self, *a):
        pass


def start_echo(tls: tuple[Path, Path] | None = None, bind: str = "127.0.0.1") -> int:
    port = free_port()
    srv = ThreadingHTTPServer((bind, port), Echo)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(tls[0]), str(tls[1]))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return port


@pytest.fixture(scope="session")
def upstream(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("upstream")
    cert = make_cert(tmp)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    return {
        "fingerprint": x509.load_pem_x509_certificate(cert[0].read_bytes()).fingerprint(hashes.SHA256()).hex(),
        "lan": start_echo(bind="127.0.0.2"),
        "http": start_echo(),
        "http2": start_echo(),
        "https": start_echo(cert),
        "cert": cert[0],
        "closed": free_port(),
    }


# ------------------------------------------------------------------ gateway
@pytest.fixture(scope="session")
def gateway(tmp_path_factory, upstream):
    if not shutil.which("mitmdump"):
        pytest.skip("mitmproxy not installed (pip install -r gateway/requirements.txt)")
    pytest.importorskip("aiohttp", reason="the gateway API needs aiohttp (pip install -r gateway/requirements.txt)")
    data = tmp_path_factory.mktemp("gw-data")
    ca_dir = tmp_path_factory.mktemp("gw-ca")
    ports = {k: free_port() for k in ("http", "socks", "dns", "api", "svc", "grants")}
    http_t = {"scheme": "http", "port": upstream["http"]}
    https_t = {"scheme": "https", "port": upstream["https"]}
    (data / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "inject": [
                    {"host": "gh.test", "header": "Authorization", "value": "Bearer ${github_token}"},
                    {"host": "badcert.test", "header": "Authorization", "value": "Bearer ${github_token}"},
                ],
                "services": [{"name": "echo", "listen": ports["svc"], "target": f"127.0.0.1:{upstream['http']}"}],
                # tests talk to 127.0.0.1 upstreams, so the floor is narrowed here (static config only)
                "hard_deny_floor": ["192.168.0.0/16", "10.0.0.0/8", "127.0.0.2/32"],
                "readonly": ["ro.test"],
                "max_pending": 3,
                # 127.0.0.2 plays the LAN: hard-denied by the floor, reachable only via a lan grant
                "grants_never": ["169.254.0.0/16"],
                "grants_lan_allow": ["127.0.0.2/32"],
                "grant_api_rate": 1000,
                "grants": {
                    "svc": {
                        "description": "echo API",
                        "targets": [{"host": "svc.test", "paths": ["/api/*"], **http_t}],
                        "levels": ["read", "write"],
                        "approval": {"read": "auto", "write": "ask"},
                    },
                    "sec": {
                        "description": "TLS service with injected token",
                        "targets": [{"host": "sec.test", **https_t}],
                        "levels": ["read", "write"],
                        "inject": [{"host": "sec.test", "header": "Authorization", "value": "Bearer ${grant_token}"}],
                    },
                    "lanhttp": {
                        "targets": [{"host": "lanecho.test", "scheme": "http", "port": upstream["lan"], "lan": True}],
                        "levels": ["write"],
                    },
                    "nolan": {
                        "targets": [{"host": "lanecho.test", "scheme": "http", "port": upstream["lan"]}],
                        "levels": ["write"],
                    },
                    "pinned": {
                        "targets": [{"host": "pin.test", "tls_fingerprint": upstream["fingerprint"], **https_t}],
                        "approval": "auto",
                    },
                    "badpin": {
                        "targets": [{"host": "badpin.test", "tls_fingerprint": "00" * 32, **https_t}],
                        "approval": "auto",
                    },
                    "raw": {
                        "targets": [{"host": "raw.test", "scheme": "tcp", "port": upstream["http2"]}],
                        "levels": ["write"],
                    },
                },
            }
        )
    )
    (data / "policy.yaml").write_text(
        yaml.safe_dump(
            {
                "default": "ask",
                "ask_timeout": 5,
                "hard_deny": ["192.168.0.0/16", "10.0.0.0/8"],
                "rules": [
                    {"id": "echo", "action": "allow", "cidr": "127.0.0.1/32", "port": [upstream["http"]]},
                    {"id": "gh", "action": "allow", "host": "gh.test", "port": upstream["https"]},
                    {"id": "other", "action": "allow", "host": "other.test", "port": upstream["https"]},
                    {"id": "badcert", "action": "allow", "host": "badcert.test", "port": upstream["https"]},
                    {"id": "ro", "action": "allow", "host": "ro.test", "port": upstream["https"]},
                    {"id": "denied", "action": "deny", "host": "*.denied.test"},
                    {"id": "lan", "action": "allow", "host": "lan.test"},
                ],
            }
        )
    )
    env = clean_env(
        DATA_DIR=data,
        CA_EXPORT_DIR=ca_dir,
        GW_LISTEN_HOST="127.0.0.1",
        GW_HTTP_PORT=ports["http"],
        GW_SOCKS_PORT=ports["socks"],
        GW_DNS_PORT=ports["dns"],
        GW_API_HOST="127.0.0.1",
        GW_API_PORT=ports["api"],
        GW_API_TOKEN=API_TOKEN,
        PRESET_DIR=ROOT / "gateway" / "presets",
        GW_TEST_STATIC_HOSTS="gh.test=127.0.0.1,other.test=127.0.0.1,badcert.test=127.0.0.1,lan.test=192.168.99.99,ro.test=127.0.0.1,"
        "svc.test=127.0.0.1,sec.test=127.0.0.1,lanecho.test=127.0.0.2,pin.test=127.0.0.1,badpin.test=127.0.0.1,raw.test=127.0.0.1",
        GW_GRANTS_PORT=ports["grants"],
        GW_EXTRA_ARGS=f"--set ssl_verify_upstream_trusted_ca={upstream['cert']}",
    )
    log = open(data / "gateway.log", "w")
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "gateway" / "run.py")], env=env, stdout=log, stderr=subprocess.STDOUT
    )
    try:
        wait_http(f"http://127.0.0.1:{ports['api']}/health")
        for _ in range(50):  # CA export happens in `running`
            if (ca_dir / "egress-gw-ca.pem").exists():
                break
            time.sleep(0.1)
        yield {
            "ports": ports,
            "api": Api(f"http://127.0.0.1:{ports['api']}", token=API_TOKEN),
            "agent": Api(f"http://127.0.0.1:{ports['grants']}"),
            "ca": str(ca_dir / "egress-gw-ca.pem"),
            "log": data / "gateway.log",
            "data": data,
        }
    finally:
        proc.terminate()
        proc.wait(10)


# ------------------------------------------------------------------ control
@pytest.fixture(scope="session")
def mockbots():
    pytest.importorskip("aiohttp", reason="the mock bot APIs need aiohttp (pip install -r control/requirements.txt)")
    from .mockbots import MockBots

    m = MockBots()
    m.start()
    yield m
    m.stop()


@pytest.fixture(scope="session")
def ttyd_port(tmp_path_factory):
    if not shutil.which("ttyd"):
        yield None
        return
    port = free_port()
    proc = subprocess.Popen(
        ["ttyd", "-p", str(port), "-W", "-c", TTYD_CREDENTIAL, "-b", "/term/bash", "bash", "--norc"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=clean_env(),
    )
    time.sleep(0.5)
    yield port
    proc.terminate()


def start_control(tmp: Path, gateway: dict, extra: dict, ttyd_port: int | None = None):
    pytest.importorskip("aiohttp", reason="control needs aiohttp (pip install -r control/requirements.txt)")
    port = free_port()
    env = clean_env(
        GW_URL=f"http://127.0.0.1:{gateway['ports']['api']}",
        GW_API_TOKEN=API_TOKEN,
        CONTROL_BIND_HOST="127.0.0.1",
        CONTROL_PORT=port,
        CONTROL_PASSWORD=CONTROL_PASSWORD,
        SESSION_SECRET="e2e",
        COOKIE_SECURE="0",
        AGENT_HOST="127.0.0.1",
        AGENT_STATUS_PORT=free_port(),
        TTYD_CREDENTIAL=TTYD_CREDENTIAL,
        TERMINALS=f"bash:{ttyd_port or free_port()}",
        PYTHONPATH=ROOT / "control",
        **extra,
    )
    log = open(tmp / f"control-{port}.log", "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.main"], cwd=ROOT / "control", env=env, stdout=log, stderr=subprocess.STDOUT
    )
    wait_http(f"http://127.0.0.1:{port}/healthz")
    time.sleep(0.5)  # let the gateway event subscription come up
    return proc, port


@pytest.fixture(scope="session")
def control(tmp_path_factory, gateway, ttyd_port):
    tmp = tmp_path_factory.mktemp("control")
    proc, port = start_control(tmp, gateway, {}, ttyd_port)
    yield {"port": port, "base": f"http://127.0.0.1:{port}", "ttyd": ttyd_port}
    proc.terminate()
    proc.wait(10)


@pytest.fixture
def control_with(tmp_path, gateway):
    procs = []

    def factory(**extra):
        proc, port = start_control(tmp_path, gateway, extra)
        procs.append(proc)
        return f"http://127.0.0.1:{port}"

    yield factory
    for p in procs:
        p.terminate()
        p.wait(10)
