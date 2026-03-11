import pytest
from ipinfo_mcp.tools.quota import ipinfo_quota
from pytest_httpx import HTTPXMock

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.types import MeResponse
from tests.conftest import make_context

ME_URL = "https://ipinfo.io/me"
BASE_URL = "https://api.ipinfo.io"

ME_RESPONSE: MeResponse = {
    "token": "abc123",
    "requests": {
        "day": 150,
        "month": 3200,
        "limit": 50000,
        "remaining": 46800,
    },
    "features": {
        "privacy": {"daily": 50000, "monthly": 50000, "vpn_provider": True},
        "hostio": {"daily": 50000, "monthly": 50000, "result_limit": 5},
        "company": {
            "daily": 50000,
            "monthly": 50000,
            "firmographics": True,
            "org_additional": True,
        },
    },
}


@pytest.fixture
async def client(httpx_mock: HTTPXMock) -> IPinfoClient:
    async with IPinfoClient(base_url=BASE_URL, token="test_token") as c:
        yield c


class TestQuotaBasic:
    async def test_returns_quota_info(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=ME_URL,
            method="GET",
            json=ME_RESPONSE,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_quota(ctx=ctx)

        assert result["requests"]["day"] == 150
        assert result["requests"]["month"] == 3200
        assert result["requests"]["limit"] == 50000
        assert result["requests"]["remaining"] == 46800

        features = result["features"]
        assert features["privacy"]["daily"] == 50000
        assert features["privacy"]["vpn_provider"] is True
        assert features["hostio"]["result_limit"] == 5
        assert features["company"]["firmographics"] is True
        assert features["company"]["org_additional"] is True


class TestQuotaErrors:
    async def test_403_returns_access_denied(
        self, client: IPinfoClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=ME_URL,
            method="GET",
            status_code=403,
        )
        ctx = make_context(client, cache)
        result = await ipinfo_quota(ctx=ctx)

        assert result["error"] is True
        assert result["code"] == "ACCESS_DENIED"

    async def test_no_token_returns_error(
        self, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        async with IPinfoClient(base_url=BASE_URL, token=None) as no_token_client:
            ctx = make_context(no_token_client, cache)
            result = await ipinfo_quota(ctx=ctx)

            assert result["error"] is True
            assert result["code"] == "NO_TOKEN"
