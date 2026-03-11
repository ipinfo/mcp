import os

import pytest

from ipinfo_mcp.client import IPinfoClient

BASE_URL = "https://api.ipinfo.io"

pytestmark = pytest.mark.integration


@pytest.fixture
def token() -> str:
    tok = os.environ.get("IPINFO_TOKEN")
    if not tok:
        pytest.skip("IPINFO_TOKEN not set")
    return tok


@pytest.fixture
async def client(token: str) -> IPinfoClient:
    async with IPinfoClient(base_url=BASE_URL, token=token) as c:
        yield c


class TestBatchLite:
    async def test_lite_response_structure(self, client: IPinfoClient) -> None:
        result = await client.batch(["lite/8.8.8.8"])

        assert "lite/8.8.8.8" in result
        data = result["lite/8.8.8.8"]
        assert isinstance(data, dict)
        assert "ip" in data

        # Lite returns flat fields, not nested objects
        assert "country" in data
        assert "country_code" in data
        assert "continent" in data
        assert "continent_code" in data
        assert "asn" in data
        assert "as_name" in data
        assert "as_domain" in data

    async def test_lite_multiple_ips(self, client: IPinfoClient) -> None:
        result = await client.batch(["lite/8.8.8.8", "lite/1.1.1.1"])

        assert "lite/8.8.8.8" in result
        assert "lite/1.1.1.1" in result
        for key in result:
            assert isinstance(result[key], dict)
            assert "ip" in result[key]


class TestBatchLookup:
    async def test_lookup_response_structure(self, client: IPinfoClient) -> None:
        result = await client.batch(["lookup/8.8.8.8"])

        assert "lookup/8.8.8.8" in result
        data = result["lookup/8.8.8.8"]
        assert isinstance(data, dict)
        assert "ip" in data

        # Geo fields (should have city-level with paid token)
        assert "geo" in data
        geo = data["geo"]
        assert isinstance(geo, dict)
        assert "city" in geo
        assert "region" in geo
        assert "country" in geo
        assert "latitude" in geo
        assert "longitude" in geo
        assert "timezone" in geo

        # AS fields (should have type with paid token)
        assert "as" in data
        as_data = data["as"]
        assert "asn" in as_data
        assert "name" in as_data
        assert "type" in as_data
        assert "last_changed" in as_data


class TestBatchResproxy:
    async def test_resproxy_known_non_proxy(self, client: IPinfoClient) -> None:
        """8.8.8.8 is Google DNS, not a residential proxy — expect empty response."""
        result = await client.batch(["resproxy/8.8.8.8"])

        assert "resproxy/8.8.8.8" in result
        data = result["resproxy/8.8.8.8"]
        # Empty dict for non-proxy IPs
        assert isinstance(data, dict)

    async def test_resproxy_response_fields_when_proxy(
        self, client: IPinfoClient
    ) -> None:
        """If the IP is a known proxy, verify field structure.

        We use a known residential proxy IP. If it's no longer a proxy,
        we just verify we get a dict back.
        """
        result = await client.batch(["resproxy/175.107.211.204"])

        assert "resproxy/175.107.211.204" in result
        data = result["resproxy/175.107.211.204"]
        assert isinstance(data, dict)

        # If it has data, check structure
        if data:
            assert "ip" in data
            assert "service" in data
            assert "last_seen" in data
            assert "percent_days_seen" in data


class TestBatchMixed:
    async def test_mixed_prefixes_in_single_call(self, client: IPinfoClient) -> None:
        result = await client.batch(
            ["lite/8.8.8.8", "lookup/1.1.1.1", "resproxy/8.8.8.8"]
        )

        assert "lite/8.8.8.8" in result
        assert "lookup/1.1.1.1" in result
        assert "resproxy/8.8.8.8" in result


class TestMe:
    async def test_me_response_structure(self, client: IPinfoClient) -> None:
        result = await client.me()

        assert isinstance(result, dict)
        assert "token" in result
        assert "requests" in result
        assert isinstance(result["requests"], dict)
