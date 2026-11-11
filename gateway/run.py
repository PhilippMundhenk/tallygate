#!/usr/bin/env python3
"""Build the mitmdump command line from config and exec it."""

import os
import secrets
import sys
from pathlib import Path

import yaml

data = Path(os.environ.get("DATA_DIR", "/data"))

# Management API token. Zero-config default: created on first start in a volume that only the gateway
# (read-write) and the control plane (read-only) mount - never the agent. GW_API_TOKEN wins when set.
if not os.environ.get("GW_API_TOKEN"):
    token_file = Path(os.environ.get("GW_API_TOKEN_FILE", "/run/tallygate/gw/api-token"))
    if not token_file.exists():
        token_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = token_file.with_suffix(".tmp")
        tmp.write_text(secrets.token_urlsafe(32))
        tmp.chmod(0o644)  # the control plane runs as another uid; the volume itself is not shared with the agent
        tmp.replace(token_file)
        print(f"egress-gw: created API token in {token_file}", flush=True)
    os.environ["GW_API_TOKEN"] = token_file.read_text().strip()
cfg_path = Path(os.environ.get("GW_CONFIG", data / "config.yaml"))
cfg = (yaml.safe_load(cfg_path.read_text()) if cfg_path.exists() else {}) or {}
listen = os.environ.get("GW_LISTEN_HOST")
if not listen:
    sys.exit("GW_LISTEN_HOST must be set to the gateway's IP on the agent network")

modes = [
    f"regular@{listen}:{os.environ.get('GW_HTTP_PORT', '3128')}",
    f"socks5@{listen}:{os.environ.get('GW_SOCKS_PORT', '1080')}",
    f"dns@{listen}:{os.environ.get('GW_DNS_PORT', '53')}",
]
for s in cfg.get("services") or []:
    modes.append(f"reverse:tcp://{s['target']}@{listen}:{int(s['listen'])}")

args = ["mitmdump", "-q", "-s", str(Path(__file__).parent / "egressgw" / "addon.py")]
for m in modes:
    args += ["--mode", m]
for opt in (
    f"confdir={data / 'mitmproxy'}",
    "connection_strategy=eager",
    "stream_large_bodies=1m",
    "flow_detail=0",
    "termlog_verbosity=warn",
    "ssl_insecure=false",
    "upstream_cert=true",
    "dns_use_hosts_file=false",
    "onboarding=false",  # no built-in mitm.it pages: every request goes through the policy
):
    args += ["--set", opt]
args += os.environ.get("GW_EXTRA_ARGS", "").split()
(data / "mitmproxy").mkdir(parents=True, exist_ok=True)
print("egress-gw:", " ".join(args), flush=True)
os.execvp(args[0], args)  # noqa: S606 - replace this process with mitmdump (fixed argv)
