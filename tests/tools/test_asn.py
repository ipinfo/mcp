import pytest
from pytest_httpx import HTTPXMock

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.tools.asn import ipinfo_asn
from ipinfo_mcp.types import LiteResponse, LookupResponse
from tests.conftest import make_context

BASE_URL = "https://api.ipinfo.io"
LEGACY_BASE_URL = "https://ipinfo.io"

LITE_8888: LiteResponse = {
    "ip": "8.8.8.8",
    "asn": "AS15169",
    "as_name": "Google LLC",
    "as_domain": "google.com",
    "country_code": "US",
    "country": "United States",
    "continent_code": "NA",
    "continent": "North America",
}

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
        "last_changed": "2024-06-01",
    },
    "is_anonymous": False,
    "is_anycast": True,
    "is_hosting": True,
    "is_mobile": False,
    "is_satellite": False,
}


@pytest.fixture
async def client(httpx_mock: HTTPXMock) -> IPinfoClient:
    async with IPinfoClient(base_url=BASE_URL, legacy_base_url=LEGACY_BASE_URL) as c:
        yield c


class TestAsnLite:
    async def test_lite_returns_asn_info(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": LITE_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_asn(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["total_results"] == 1
        assert "8.8.8.8" in result["results"]
        asn = result["results"]["8.8.8.8"]
        assert asn["asn"] == "AS15169"
        assert asn["name"] == "Google LLC"
        assert asn["domain"] == "google.com"


class TestAsnDetailed:
    async def test_detailed_includes_type(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lookup/8.8.8.8": LOOKUP_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_asn(
            ips=["8.8.8.8"], detailed=True, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        asn = result["results"]["8.8.8.8"]
        assert asn["asn"] == "AS15169"
        assert asn["name"] == "Google LLC"
        assert asn["domain"] == "google.com"
        assert asn["type"] == "hosting"
        assert asn["last_changed"] == "2024-06-01"


class TestAsnCaching:
    async def test_uses_cache(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        cache.put("fake_token", "lite", "8.8.8.8", LITE_8888)

        ctx = make_context(client, cache, api_token="fake_token")
        result = await ipinfo_asn(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_meta"]["api_calls_made"] == 0
        assert result["_meta"]["from_cache"] == 1
        assert "8.8.8.8" in result["results"]


class TestAsnErrors:
    async def test_403_returns_access_denied(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=403,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_asn(
            ips=["8.8.8.8"], detailed=True, page=1, page_size=5, ctx=ctx
        )

        assert result["error"] is True
        assert result["code"] == "ACCESS_DENIED"

    async def test_no_token_returns_error(
        self, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        async with IPinfoClient(base_url=BASE_URL, legacy_base_url=LEGACY_BASE_URL) as no_token_client:
            ctx = make_context(no_token_client, cache, api_token=None)
            result = await ipinfo_asn(
                ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
            )

            assert result["error"] is True
            assert result["code"] == "NO_TOKEN"


class TestAsnValidation:
    async def test_invalid_ips_reported(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": LITE_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_asn(
            ips=["8.8.8.8", "not-valid"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        assert "validation_errors" in result
        assert "not-valid" in result["validation_errors"]
