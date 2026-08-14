import pytest
from pytest_httpx import HTTPXMock

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.tools.lookup import ipinfo_lookup
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

LITE_1111: LiteResponse = {
    "ip": "1.1.1.1",
    "asn": "AS13335",
    "as_name": "Cloudflare Inc.",
    "as_domain": "cloudflare.com",
    "country_code": "AU",
    "country": "Australia",
    "continent_code": "OC",
    "continent": "Oceania",
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
    async with IPinfoClient(base_url=BASE_URL, legacy_base_url=LEGACY_BASE_URL) as c:
        yield c


class TestLookupLite:
    async def test_basic_lite_lookup(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": LITE_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["total_results"] == 1
        assert "8.8.8.8" in result["results"]
        assert result["results"]["8.8.8.8"]["ip"] == "8.8.8.8"

    async def test_multiple_ips_lite(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={
                "lite/8.8.8.8": LITE_8888,
                "lite/1.1.1.1": LITE_1111,
            },
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8", "1.1.1.1"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["total_results"] == 2
        assert "8.8.8.8" in result["results"]
        assert "1.1.1.1" in result["results"]


class TestLookupDetailed:
    async def test_detailed_lookup(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lookup/8.8.8.8": LOOKUP_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=True, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        assert result["results"]["8.8.8.8"]["geo"]["city"] == "Mountain View"


class TestLookupPagination:
    async def test_pagination_page_2(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        ips = [f"1.0.0.{i}" for i in range(1, 8)]
        batch_response = {f"lite/{ip}": {"ip": ip, **_lite_stub(ip)} for ip in ips}
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json=batch_response,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=ips, detailed=False, page=2, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["page"] == 2
        assert result["_pagination"]["total_pages"] == 2
        assert result["_pagination"]["has_previous"] is True
        assert result["_pagination"]["has_next"] is False
        assert len(result["results"]) == 2


class TestLookupCaching:
    async def test_second_call_uses_cache(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": LITE_8888},
        )
        ctx = make_context(client, cache)

        # First call — hits API
        result1 = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )
        assert result1["_meta"]["api_calls_made"] == 1
        assert result1["_meta"]["from_cache"] == 0

        # Second call — should use cache, no additional API call
        result2 = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )
        assert result2["_meta"]["api_calls_made"] == 0
        assert result2["_meta"]["from_cache"] == 1

    async def test_partial_cache_hit(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        # Pre-populate cache with one IP
        cache.put("fake_token", "lite", "8.8.8.8", LITE_8888)

        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/1.1.1.1": LITE_1111},
        )
        ctx = make_context(client, cache, api_token="fake_token")
        result = await ipinfo_lookup(
            ips=["8.8.8.8", "1.1.1.1"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_meta"]["api_calls_made"] == 1
        assert result["_meta"]["from_cache"] == 1
        assert "8.8.8.8" in result["results"]
        assert "1.1.1.1" in result["results"]


class TestLookupValidation:
    async def test_mixed_valid_and_invalid_ips(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": LITE_8888},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8", "not-valid"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" in result["results"]
        assert "validation_errors" in result
        assert "not-valid" in result["validation_errors"]

    async def test_all_invalid_ips(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["bad-ip"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["_pagination"]["total_results"] == 0
        assert result["results"] == {}
        assert "validation_errors" in result


class TestLookupErrors:
    async def test_per_key_error_is_surfaced(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        """A per-key error body arrives inside a 200 batch response."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={
                "lite/8.8.8.8": {
                    "error": "Token does not have access to this API",
                    "token": "some_token",
                }
            },
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" not in result["results"]
        assert result["errors"]["8.8.8.8"] == {
            "code": "ACCESS_DENIED",
            "message": "Token does not have access to this API",
            "suggestion": "Tell the user they can get access by upgrading at https://ipinfo.io/pricing",
        }

    async def test_per_key_error_is_not_cached(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        """An errored IP must not be cached, or the error outlives the request."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": {"error": "Token does not have access to this API"}},
        )
        ctx = make_context(client, cache, api_token="fake_token")
        _ = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert cache.get("fake_token", "lite", "8.8.8.8") is None

    async def test_bare_message_error_is_surfaced(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        """The generic error handler replies with a message and no error key."""
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={"lite/8.8.8.8": {"message": "The server exploded"}},
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert "8.8.8.8" not in result["results"]
        assert result["errors"]["8.8.8.8"] == {
            "code": "UNKNOWN",
            "message": "The server exploded",
            "suggestion": "An unforseen error happened, tell the user to report it to https://ipinfo.io/",
        }

    async def test_partial_error_still_returns_good_ips(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={
                "lite/8.8.8.8": LITE_8888,
                "lite/1.1.1.1": {"error": "You've reached your limit on this API"},
            },
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8", "1.1.1.1"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["results"]["8.8.8.8"]["ip"] == "8.8.8.8"
        assert "1.1.1.1" not in result["results"]
        assert result["errors"]["1.1.1.1"] == {
            "code": "RATE_LIMITED",
            "message": "You've reached your limit on this API",
            "suggestion": "Tell the user they can upgrade their tier at https://ipinfo.io/pricing",
        }

    async def test_403_returns_access_denied(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=403,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=True, page=1, page_size=5, ctx=ctx
        )

        assert result["code"] == "ACCESS_DENIED"
        assert result["message"] == "You don't have access to lookup."
        assert result["suggestion"] == "Tell the user they can get access by upgrading at https://ipinfo.io/pricing"

    async def test_429_returns_rate_limited(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=429,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_lookup(
            ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
        )

        assert result["code"] == "RATE_LIMITED"
        assert result["message"] == "Rate limit exceeded."
        assert result["suggestion"] == "Tell the user they can upgrade their tier at https://ipinfo.io/pricing"

    async def test_no_token_returns_error(
        self, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        async with IPinfoClient(base_url=BASE_URL, legacy_base_url=LEGACY_BASE_URL) as no_token_client:
            ctx = make_context(no_token_client, cache, api_token=None)
            result = await ipinfo_lookup(
                ips=["8.8.8.8"], detailed=False, page=1, page_size=5, ctx=ctx
            )

            assert result["code"] == "NO_TOKEN"
            assert result["message"] == "No API token configured."
            assert result["suggestion"] == "The user didn't set IPINFO_TOKEN. They can get a free token at https://ipinfo.io/signup"


def _lite_stub(ip: str) -> LiteResponse:
    """Create a minimal LiteResponse stub for testing."""
    return {
        "ip": ip,
        "asn": "AS0",
        "as_name": "Test",
        "as_domain": "test.com",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America",
    }
