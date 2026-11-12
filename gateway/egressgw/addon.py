"""mitmproxy script entry point (thin loader; logic lives in egressgw.core)."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class RefuseAll:
    """Startup failed. mitmdump exits because of the logged error, but its proxy ports may already be
    open: until then every connection is refused instead of going out without any policy."""

    def server_connect(self, data) -> None:
        data.server.error = "egress policy: gateway failed to start (fail closed)"

    def request(self, flow) -> None:
        flow.kill()

    def dns_request(self, flow) -> None:
        flow.kill()


try:
    from egressgw.core import Gateway

    addons = [Gateway()]
except Exception:  # never run the proxy without the policy
    logging.getLogger("egressgw").exception("egress-gw failed to start - refusing all connections")
    addons = [RefuseAll()]
