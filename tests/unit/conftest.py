"""Unit tests build gateways outside the compose stack: there are no networks of a stack to lock."""

import pytest


@pytest.fixture(autouse=True)
def _no_stack_networks(monkeypatch):
    """An empty GW_INTERNAL_NETS stops the gateway (#232) unless this test-only switch is set. Tests of the
    locked ranges set GW_INTERNAL_NETS themselves; tests of the refusal remove the switch."""
    monkeypatch.setenv("GW_TEST_NO_INTERNAL_NETS", "1")
