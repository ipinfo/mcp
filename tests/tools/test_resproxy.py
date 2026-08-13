"""Tests for the ipinfo_check_residential_proxy tool."""

import pytest
from pytest_httpx import HTTPXMock

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.tools.resproxy import ipinfo_check_residential_proxy
from ipinfo_mcp.types import ResproxyResponse
from tests.conftest import make_context

BASE_URL = "https://api.ipinfo.io"
LEGACY_BASE_URL = "https://ipinfo.io"

RESPROXY_HIT: ResproxyResponse = {
    "ip": "1.2.3.4",
    "service": "NordVPN",
    "last_seen": "2025-01-15",
    "percent_days_seen": 85,
}


@pytest.fixture
async def client(httpx_mock: HTTPXMock) -> IPinfoClient:
    async with IPinfoClient(base_url=BASE_URL, legacy_base_url=LEGACY_BASE_URL) as c:
        yield c


class TestResproxyBasic:
    async def test_residential_proxy_detected(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"resproxy/1.2.3.4": RESPROXY_HIT},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_residential_proxy(
            ips=["1.2.3.4"], page=1, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["total_results"] == 1
        assert "1.2.3.4" in result["results"]
        info = result["results"]["1.2.3.4"]
        assert info["is_residential_proxy"] is True
        assert info["service"] == "NordVPN"
        assert info["last_seen"] == "2025-01-15"
        assert info["percent_days_seen"] == 85

    async def test_not_residential_proxy(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        """Empty dict from API means the IP is not a residential proxy."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"resproxy/8.8.8.8": {}},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_residential_proxy(
            ips=["8.8.8.8"], page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        info = result["results"]["8.8.8.8"]
        assert info["is_residential_proxy"] is False


class TestResproxyCaching:
    async def test_uses_resproxy_cache(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        cache.put("fake_token", "resproxy", "1.2.3.4", RESPROXY_HIT)

        ctx = make_context(client, cache, api_token="fake_token")
        result = await ipinfo_check_residential_proxy(
            ips=["1.2.3.4"], page=1, page_size=5, ctx=ctx
        )

        assert result["_meta"]["api_calls_made"] == 0
        assert result["_meta"]["from_cache"] == 1
        assert "1.2.3.4" in result["results"]


class TestResproxyErrors:
    async def test_403_returns_access_denied(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=403,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_residential_proxy(
            ips=["1.2.3.4"], page=1, page_size=5, ctx=ctx
        )

        assert result["error"] is True
        assert result["code"] == "ACCESS_DENIED"

    async def test_no_token_returns_error(
        self, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        async with IPinfoClient(base_url=BASE_URL, legacy_base_url=LEGACY_BASE_URL) as no_token_client:
            ctx = make_context(no_token_client, cache, api_token=None)
            result = await ipinfo_check_residential_proxy(
                ips=["1.2.3.4"], page=1, page_size=5, ctx=ctx
            )

            assert result["error"] is True
            assert result["code"] == "NO_TOKEN"


class TestResproxyValidation:
    async def test_invalid_ips_reported(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"resproxy/1.2.3.4": RESPROXY_HIT},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_residential_proxy(
            ips=["1.2.3.4", "not-valid"], page=1, page_size=5, ctx=ctx
        )

        assert "1.2.3.4" in result["results"]
        assert "validation_errors" in result
        assert "not-valid" in result["validation_errors"]
