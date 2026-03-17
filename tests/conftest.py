import os
from unittest.mock import MagicMock

import pytest

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient

_UNSET = object()

@pytest.fixture
def cache() -> IPCache:
    return IPCache()


def make_context(client: IPinfoClient, cache: IPCache | None = None, *, api_token: object = _UNSET) -> MagicMock:
    """Helper to create a mock Context with a real client and cache."""
    token = os.environ.get("IPINFO_TOKEN", "test_token") if api_token is _UNSET else api_token
    ctx = MagicMock()
    ctx.lifespan_context = {
        "client": client,
        "cache": cache or IPCache(),
        "api_token": token,
    }
    return ctx
