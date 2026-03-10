from unittest.mock import MagicMock

import pytest

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient


@pytest.fixture
def cache() -> IPCache:
    return IPCache()


def make_context(client: IPinfoClient, cache: IPCache | None = None) -> MagicMock:
    """Helper to create a mock Context with a real client and cache."""
    ctx = MagicMock()
    ctx.lifespan_context = {
        "client": client,
        "cache": cache or IPCache(),
    }
    return ctx
