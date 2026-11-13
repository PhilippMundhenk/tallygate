"""Shared by the unit and e2e tests.

ADR-0014 shadow check: every gateway started by the tests (in this process or as mitmdump) evaluates the
model in `egressgw/model.py` next to the code that decides, on every TLS handshake and every request. A
difference is written to one file, and the test during which it appeared fails.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

SHADOW_LOG = Path(tempfile.gettempdir()) / f"tallygate-shadow-{os.getpid()}.log"
os.environ["GW_TEST_SHADOW"] = "1"  # read when egressgw.core is imported, and inherited by the e2e gateways
os.environ["GW_TEST_SHADOW_LOG"] = str(SHADOW_LOG)
SHADOW_LOG.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def model_agrees_with_the_current_code():
    yield
    if SHADOW_LOG.exists():
        found = SHADOW_LOG.read_text().strip()
        SHADOW_LOG.unlink()
        if found:
            pytest.fail(f"ADR-0014: the model disagrees with the current code:\n{found}", pytrace=False)
