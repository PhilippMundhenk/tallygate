#!/usr/bin/env python3
"""Build the mitmdump command line from config and exec it."""

import os
import sys
from pathlib import Path

import yaml

data = Path(os.environ.get("DATA_DIR", "/data"))
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
):
    args += ["--set", opt]
args += os.environ.get("GW_EXTRA_ARGS", "").split()
(data / "mitmproxy").mkdir(parents=True, exist_ok=True)
print("egress-gw:", " ".join(args), flush=True)
os.execvp(args[0], args)  # noqa: S606 - replace this process with mitmdump (fixed argv)
