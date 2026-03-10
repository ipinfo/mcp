"""Tests for the ipinfo_check_privacy tool."""

import pytest
from pytest_httpx import HTTPXMock

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.tools.privacy import ipinfo_check_privacy
from ipinfo_mcp.types import LookupResponse
from tests.conftest import make_context

BASE_URL = "https://api.ipinfo.io"

LOOKUP_8888: LookupResponse = {
    "ip": "8.8.8.8",
    "geo": {
        "city": "Mountain View",
        "region": "California",
        "region_code": "CA",
        "country": "United States",
        "country_code": "US",
        "continent": "North America",
        "continent_code": "NA",
        "latitude": 37.4056,
        "longitude": -122.0775,
        "timezone": "America/Los_Angeles",
        "postal_code": "94043",
    },
    "as": {
        "asn": "AS15169",
        "name": "Google LLC",
        "domain": "google.com",
        "type": "hosting",
    },
    "anonymous": {
        "is_proxy": False,
        "is_relay": False,
        "is_tor": False,
        "is_vpn": False,
    },
    "is_anonymous": False,
    "is_anycast": True,
    "is_hosting": True,
    "is_mobile": False,
    "is_satellite": False,
}

LOOKUP_VPN: LookupResponse = {
    "ip": "1.2.3.4",
    "geo": {
        "city": "Amsterdam",
        "region": "North Holland",
        "region_code": "NH",
        "country": "Netherlands",
        "country_code": "NL",
        "continent": "Europe",
        "continent_code": "EU",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "timezone": "Europe/Amsterdam",
        "postal_code": "1012",
    },
    "as": {
        "asn": "AS9009",
        "name": "M247 Europe SRL",
        "domain": "m247.com",
        "type": "hosting",
    },
    "anonymous": {
        "is_proxy": False,
        "is_relay": False,
        "is_tor": False,
        "is_vpn": True,
        "name": "NordVPN",
    },
    "is_anonymous": True,
    "is_anycast": False,
    "is_hosting": True,
    "is_mobile": False,
    "is_satellite": False,
}


@pytest.fixture
async def client(httpx_mock: HTTPXMock) -> IPinfoClient:
    async with IPinfoClient(base_url=BASE_URL, token="test_token") as c:
        yield c


class TestPrivacyBasic:
    async def test_non_anonymous_ip(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lookup/8.8.8.8": LOOKUP_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_privacy(
            ips=["8.8.8.8"], page=1, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["total_results"] == 1
        assert "8.8.8.8" in result["results"]
        privacy = result["results"]["8.8.8.8"]
        assert privacy["is_anonymous"] is False
        assert privacy["anonymous"]["is_vpn"] is False
        assert privacy["anonymous"]["is_tor"] is False

    async def test_vpn_detected(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lookup/1.2.3.4": LOOKUP_VPN},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_privacy(
            ips=["1.2.3.4"], page=1, page_size=5, ctx=ctx
        )

        assert "1.2.3.4" in result["results"]
        privacy = result["results"]["1.2.3.4"]
        assert privacy["is_anonymous"] is True
        assert privacy["anonymous"]["is_vpn"] is True
        assert privacy["anonymous"]["name"] == "NordVPN"


class TestPrivacyCaching:
    async def test_uses_lookup_cache(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        """Privacy should reuse data already cached by a lookup call."""
        cache.put("lookup", "8.8.8.8", LOOKUP_8888)

        ctx = make_context(client, cache)
        result = await ipinfo_check_privacy(
            ips=["8.8.8.8"], page=1, page_size=5, ctx=ctx
        )

        assert result["_meta"]["api_calls_made"] == 0
        assert result["_meta"]["from_cache"] == 1
        assert "8.8.8.8" in result["results"]


class TestPrivacyErrors:
    async def test_403_returns_access_denied(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=403,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_privacy(
            ips=["8.8.8.8"], page=1, page_size=5, ctx=ctx
        )

        assert result["error"] is True
        assert result["code"] == "ACCESS_DENIED"

    async def test_no_token_returns_error(
        self, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        async with IPinfoClient(base_url=BASE_URL, token=None) as no_token_client:
            ctx = make_context(no_token_client, cache)
            result = await ipinfo_check_privacy(
                ips=["8.8.8.8"], page=1, page_size=5, ctx=ctx
            )

            assert result["error"] is True
            assert result["code"] == "NO_TOKEN"


class TestPrivacyValidation:
    async def test_invalid_ips_reported(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lookup/8.8.8.8": LOOKUP_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_check_privacy(
            ips=["8.8.8.8", "not-valid"], page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        assert "validation_errors" in result
        assert "not-valid" in result["validation_errors"]
