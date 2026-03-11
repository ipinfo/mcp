import pytest
from ipinfo_mcp.tools.geolocate import ipinfo_geolocate
from pytest_httpx import HTTPXMock

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.types import LiteResponse, LookupResponse
from tests.conftest import make_context

BASE_URL = "https://api.ipinfo.io"

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
    },
    "is_anonymous": False,
    "is_anycast": True,
    "is_hosting": True,
    "is_mobile": False,
    "is_satellite": False,
}


@pytest.fixture
async def client(httpx_mock: HTTPXMock) -> IPinfoClient:
    async with IPinfoClient(base_url=BASE_URL, token="test_token") as c:
        yield c


class TestGeolocateLite:
    async def test_lite_returns_country_and_continent(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": LITE_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_geolocate(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["total_results"] == 1
        assert "8.8.8.8" in result["results"]
        geo = result["results"]["8.8.8.8"]
        assert geo["country"] == "United States"
        assert geo["country_code"] == "US"
        assert geo["continent"] == "North America"
        assert geo["continent_code"] == "NA"


class TestGeolocateDetailed:
    async def test_detailed_returns_full_geo(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lookup/8.8.8.8": LOOKUP_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_geolocate(
            ips=["8.8.8.8"], detailed=True, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        geo = result["results"]["8.8.8.8"]
        assert geo["city"] == "Mountain View"
        assert geo["region"] == "California"
        assert geo["latitude"] == 37.4056
        assert geo["longitude"] == -122.0775
        assert geo["timezone"] == "America/Los_Angeles"


class TestGeolocateCaching:
    async def test_uses_cache(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        cache.put("lite", "8.8.8.8", LITE_8888)

        ctx = make_context(client, cache)
        result = await ipinfo_geolocate(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_meta"]["api_calls_made"] == 0
        assert result["_meta"]["from_cache"] == 1
        assert "8.8.8.8" in result["results"]


class TestGeolocateErrors:
    async def test_403_returns_access_denied(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=403,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_geolocate(
            ips=["8.8.8.8"], detailed=True, page=1, page_size=5, ctx=ctx
        )

        assert result["error"] is True
        assert result["code"] == "ACCESS_DENIED"

    async def test_no_token_returns_error(
        self, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        async with IPinfoClient(base_url=BASE_URL, token=None) as no_token_client:
            ctx = make_context(no_token_client, cache)
            result = await ipinfo_geolocate(
                ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
            )

            assert result["error"] is True
            assert result["code"] == "NO_TOKEN"


class TestGeolocateValidation:
    async def test_invalid_ips_reported(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": LITE_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_geolocate(
            ips=["8.8.8.8", "not-valid"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        assert "validation_errors" in result
        assert "not-valid" in result["validation_errors"]
