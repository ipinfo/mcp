import httpx
import pytest
from pytest_httpx import HTTPXMock

from ipinfo_mcp.client import IPinfoClient

BASE_URL = "https://api.ipinfo.io"


@pytest.fixture
async def client() -> IPinfoClient:
    async with IPinfoClient(base_url=BASE_URL, token="test_token") as c:
        yield c


class TestBatch:
    async def test_batch_with_lite_prefix(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={
                "lite/8.8.8.8": {"ip": "8.8.8.8", "country": "US"},
            },
        )
        result = await client.batch(["lite/8.8.8.8"])
        assert "lite/8.8.8.8" in result
        assert result["lite/8.8.8.8"]["ip"] == "8.8.8.8"

    async def test_batch_with_lookup_prefix(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={
                "lookup/8.8.8.8": {"ip": "8.8.8.8", "city": "Mountain View"},
            },
        )
        result = await client.batch(["lookup/8.8.8.8"])
        assert "lookup/8.8.8.8" in result

    async def test_batch_with_resproxy_prefix(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={
                "resproxy/8.8.8.8": {},
            },
        )
        result = await client.batch(["resproxy/8.8.8.8"])
        assert result["resproxy/8.8.8.8"] == {}

    async def test_batch_mixed_prefixes(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={
                "lite/8.8.8.8": {"ip": "8.8.8.8"},
                "lookup/1.1.1.1": {"ip": "1.1.1.1"},
                "resproxy/2.2.2.2": {"service": "test"},
            },
        )
        result = await client.batch(
            ["lite/8.8.8.8", "lookup/1.1.1.1", "resproxy/2.2.2.2"]
        )
        assert len(result) == 3

    async def test_batch_sends_json_body(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={},
        )
        await client.batch(["lite/8.8.8.8", "lookup/1.1.1.1"])

        request = httpx_mock.get_request()
        assert request is not None
        assert request.content == b'["lite/8.8.8.8","lookup/1.1.1.1"]'

    async def test_batch_includes_auth_header(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            json={},
        )
        await client.batch(["lite/8.8.8.8"])

        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["Authorization"] == "Bearer test_token"

    async def test_batch_propagates_403(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=403,
        )
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.batch(["lookup/8.8.8.8"])
        assert exc_info.value.response.status_code == 403

    async def test_batch_propagates_429(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/batch",
            method="POST",
            status_code=429,
        )
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.batch(["lite/8.8.8.8"])
        assert exc_info.value.response.status_code == 429


ME_URL = "https://ipinfo.io"


class TestMe:
    async def test_me_returns_account_info(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{ME_URL}/me",
            method="GET",
            json={
                "token": "test_token",
                "requests": {"month": 100, "limit": 50000},
            },
        )
        result = await client.me()
        assert "token" in result
        assert "requests" in result

    async def test_me_includes_auth_header(
        self, client: IPinfoClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{ME_URL}/me",
            method="GET",
            json={},
        )
        await client.me()

        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["Authorization"] == "Bearer test_token"


class TestNoToken:
    async def test_no_auth_header_without_token(self, httpx_mock: HTTPXMock) -> None:
        async with IPinfoClient(base_url=BASE_URL, token=None) as client:
            httpx_mock.add_response(
                url=f"{BASE_URL}/batch",
                method="POST",
                json={},
            )
            await client.batch(["lite/8.8.8.8"])

            request = httpx_mock.get_request()
            assert request is not None
            assert "Authorization" not in request.headers
