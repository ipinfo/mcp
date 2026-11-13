from collections.abc import AsyncIterator
from unittest.mock import MagicMock

import httpx
import pytest
from pytest_httpx import HTTPXMock

from ipinfo_mcp.aauth.lite import LiteClient, ipinfo_lite_lookup
from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import USER_AGENT
from ipinfo_mcp.types import LiteResponse
from tests.aauth_helpers import make_agent_provider

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


@pytest.fixture
async def client(httpx_mock: HTTPXMock) -> AsyncIterator[LiteClient]:
    async with LiteClient(BASE_URL, make_agent_provider()) as c:
        yield c


def make_context(client: LiteClient, cache: IPCache) -> MagicMock:
    ctx = MagicMock()
    ctx.lifespan_context = {"client": client, "cache": cache}
    return ctx


class TestLiteClient:
    async def test_looks_up_each_ip_signed_as_our_agent(self, client: LiteClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", json=LITE_8888)
        httpx_mock.add_response(
            url=f"{BASE_URL}/lite/2001:4860:4860::8888", method="GET", json={"ip": "2001:4860:4860::8888"}
        )

        result = await client.lookup(["8.8.8.8", "2001:4860:4860::8888"])

        assert result == {"8.8.8.8": LITE_8888, "2001:4860:4860::8888": {"ip": "2001:4860:4860::8888"}}
        for request in httpx_mock.get_requests():
            assert request.headers["Signature-Key"].startswith('sig=jwt;jwt="')
            assert request.headers["Signature-Input"].startswith('sig=("@method" "@authority" "@path" "signature-key")')
            assert request.headers["Signature"].startswith("sig=:")
            assert "Authorization" not in request.headers
            assert request.headers["User-Agent"] == USER_AGENT

    async def test_relays_the_person_it_looks_up_for(self, client: LiteClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", json=LITE_8888)

        await client.lookup(["8.8.8.8"], person_token="caller.person.token")

        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["IPinfo-Person-Token"] == "caller.person.token"
        assert '"ipinfo-person-token"' in request.headers["Signature-Input"]

    async def test_relays_nothing_without_a_person(self, client: LiteClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", json=LITE_8888)

        await client.lookup(["8.8.8.8"])

        request = httpx_mock.get_request()
        assert request is not None
        assert "IPinfo-Person-Token" not in request.headers
        assert "ipinfo-person-token" not in request.headers["Signature-Input"]

    @pytest.mark.parametrize("status_code", [401, 403, 429])
    async def test_propagates_errors(self, client: LiteClient, httpx_mock: HTTPXMock, status_code: int) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", status_code=status_code)

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.lookup(["8.8.8.8"])

        assert exc_info.value.response.status_code == status_code


class TestLiteLookup:
    async def test_returns_lite_data(self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", json=LITE_8888)
        httpx_mock.add_response(url=f"{BASE_URL}/lite/1.1.1.1", method="GET", json=LITE_1111)

        result = await ipinfo_lite_lookup(ips=["8.8.8.8", "1.1.1.1"], ctx=make_context(client, cache))

        assert result["results"] == {"8.8.8.8": LITE_8888, "1.1.1.1": LITE_1111}
        assert result["_meta"] == {"api_calls_made": 2, "from_cache": 0}
        assert result["_pagination"]["total_results"] == 2
        assert result["errors"] == {}

    async def test_second_call_uses_cache(self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", json=LITE_8888)
        ctx = make_context(client, cache)
        await ipinfo_lite_lookup(ips=["8.8.8.8"], ctx=ctx)

        result = await ipinfo_lite_lookup(ips=["8.8.8.8"], ctx=ctx)

        assert result["results"] == {"8.8.8.8": LITE_8888}
        assert result["_meta"] == {"api_calls_made": 0, "from_cache": 1}

    async def test_only_the_requested_page_is_fetched(
        self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/1.1.1.1", method="GET", json=LITE_1111)

        result = await ipinfo_lite_lookup(
            ips=["8.8.8.8", "1.1.1.1"], page=2, page_size=1, ctx=make_context(client, cache)
        )

        assert result["results"] == {"1.1.1.1": LITE_1111}
        assert result["_pagination"]["page"] == 2
        assert result["_pagination"]["has_previous"]

    async def test_invalid_ips_are_reported_without_lookups(self, client: LiteClient, cache: IPCache) -> None:
        result = await ipinfo_lite_lookup(ips=["10.0.0.1", "not-an-ip"], ctx=make_context(client, cache))

        assert result["results"] == {}
        assert set(result["validation_errors"]) == {"10.0.0.1", "not-an-ip"}

    async def test_429_sends_the_user_to_sign_up(
        self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", status_code=429)

        result = await ipinfo_lite_lookup(ips=["8.8.8.8"], ctx=make_context(client, cache))

        assert result == {
            "code": "RATE_LIMITED",
            "message": "Rate limit exceeded.",
            "suggestion": (
                "The user has reached their daily limit of lookups without an IPinfo account, try again tomorrow. "
                "The user can get a free token at https://ipinfo.io/signup"
            ),
        }

    async def test_refused_signature_is_named(
        self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/lite/8.8.8.8",
            method="GET",
            status_code=401,
            headers={"Signature-Error": "error=unknown_key"},
            json={"error": "unknown_key"},
        )

        result = await ipinfo_lite_lookup(ips=["8.8.8.8"], ctx=make_context(client, cache))

        assert result == {
            "code": "API_ERROR",
            "message": "The IPinfo API refused this server's AAuth signature (error=unknown_key).",
            "suggestion": "Tell the user to contact IPinfo support at support@ipinfo.io",
        }

    async def test_refused_person_token_is_named(
        self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/lite/8.8.8.8",
            method="GET",
            status_code=401,
            headers={"Signature-Error": "error=expired_jwt, relayed"},
            json={"error": "expired_jwt", "relayed": True},
        )

        result = await ipinfo_lite_lookup(ips=["8.8.8.8"], ctx=make_context(client, cache))

        assert result == {
            "code": "API_ERROR",
            "message": "The IPinfo API refused the user's person token (error=expired_jwt, relayed).",
            "suggestion": (
                "Try the request again. If it keeps failing, tell the user to contact IPinfo support at "
                "support@ipinfo.io"
            ),
        }

    async def test_api_not_accepting_agents_is_named(
        self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", status_code=403)

        result = await ipinfo_lite_lookup(ips=["8.8.8.8"], ctx=make_context(client, cache))

        assert result["code"] == "API_ERROR"
        assert result["message"] == "The IPinfo API isn't accepting lookups without an account."

    async def test_5xx_returns_api_error_with_retry_suggestion(
        self, client: LiteClient, cache: IPCache, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", status_code=503)

        result = await ipinfo_lite_lookup(ips=["8.8.8.8"], ctx=make_context(client, cache))

        assert result == {
            "code": "API_ERROR",
            "message": "IPinfo API returned status 503.",
            "suggestion": "The IPinfo API is having a temporary problem, try the request again in a moment",
        }
