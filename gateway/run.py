#!/usr/bin/env python3
"""Build the mitmdump command line from config and exec it."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import yaml


def ensure_api_token(env: dict) -> str:
    """Management API token. Zero-config default: created on first start in a volume that only the gateway
    (read-write) and the control plane (read-only) mount - never the agent. GW_API_TOKEN wins when set."""
    if env.get("GW_API_TOKEN"):
        return env["GW_API_TOKEN"]
    token_file = Path(env.get("GW_API_TOKEN_FILE", "/run/tallygate/gw/api-token"))
    if not token_file.exists():
        token_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = token_file.with_suffix(".tmp")
        tmp.write_text(secrets.token_urlsafe(32))
        tmp.chmod(0o644)  # the control plane runs as another uid; the volume itself is not shared with the agent
        tmp.replace(token_file)
        print(f"egress-gw: created API token in {token_file}", flush=True)
    return token_file.read_text().strip()


def build_args(env: dict, data: Path) -> list[str]:
    """The mitmdump argv for this environment and static config."""
    cfg_path = Path(env.get("GW_CONFIG", data / "config.yaml"))
    cfg = (yaml.safe_load(cfg_path.read_text()) if cfg_path.exists() else {}) or {}
    listen = env.get("GW_LISTEN_HOST")
    if not listen:
        raise SystemExit("GW_LISTEN_HOST must be set to the gateway's IP on the agent network")
    modes = [
        f"regular@{listen}:{env.get('GW_HTTP_PORT', '3128')}",
        f"socks5@{listen}:{env.get('GW_SOCKS_PORT', '1080')}",
        f"dns@{listen}:{env.get('GW_DNS_PORT', '53')}",
    ]
    for s in cfg.get("services") or []:
        modes.append(f"reverse:tcp://{s['target']}@{listen}:{int(s['listen'])}")
    # no -q: it forces termlog_verbosity=error over the --set below and hides the security warnings
    # (test-only switches active, API disabled); flow_detail=0 keeps per-flow output off
    args = ["mitmdump", "-s", str(Path(__file__).parent / "egressgw" / "addon.py")]
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
    return args + env.get("GW_EXTRA_ARGS", "").split()


def main() -> None:  # pragma: no cover - process wrapper: exec()s mitmdump; the functions above are tested
    data = Path(os.environ.get("DATA_DIR", "/data"))
    os.environ["GW_API_TOKEN"] = ensure_api_token(dict(os.environ))
    args = build_args(dict(os.environ), data)
    (data / "mitmproxy").mkdir(parents=True, exist_ok=True)
    print("egress-gw:", " ".join(args), flush=True)
    os.execvp(args[0], args)  # noqa: S606 - replace this process with mitmdump (fixed argv)


if __name__ == "__main__":
    main()
