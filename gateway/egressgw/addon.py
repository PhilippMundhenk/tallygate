"""mitmproxy script entry point (thin loader; logic lives in egressgw.core)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from egressgw.core import Gateway

addons = [Gateway()]
