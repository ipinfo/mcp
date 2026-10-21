import json
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from fastmcp import Context, FastMCP
from fastmcp.server.auth import MultiAuth
from joserfc import jwt
from joserfc.jwk import ECKey

from ipinfo_mcp import server
from ipinfo_mcp.auth import create_auth, get_cache_owner, get_request_token, is_jwt

ISSUER = "https://ipinfo.io"
RESOURCE = "https://mcp.ipinfo.io/"
API_AUDIENCE = "https://api.ipinfo.io"
METADATA_URL = "https://mcp.ipinfo.io/.well-known/oauth-protected-resource"

KEY = ECKey.generate_key("P-256", parameters={"kid": "signing-key"})
OTHER_KEY = ECKey.generate_key("P-256", parameters={"kid": "signing-key"})

API_TOKENS = ["a1b2c3d4e5f6a7", "MY-ad_hoc.token+with/chars"]


def make_token(key: ECKey = KEY, **overrides: object) -> str:
    """Create an access token shaped like the ones apps/api issues."""
    now = time.time()
    claims = {
        "iss": ISSUER,
        "aud": [RESOURCE, API_AUDIENCE],
        "sub": "42",
        "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
        "scope": "ipinfo:read",
        "jti": str(uuid.uuid4()),
        # apps/api issues fractional timestamps, in milliseconds
        "iat": round(now, 3),
        "exp": round(now + 3600, 3),
        **overrides,
    }
    return jwt.encode({"alg": "ES256", "kid": key.kid}, claims, key)


def make_auth(monkeypatch: pytest.MonkeyPatch, resource_url: str = RESOURCE) -> MultiAuth:
    auth = create_auth(issuer=ISSUER, resource_url=resource_url)

    async def fetch_jwks() -> dict[str, object]:
        return {"keys": [KEY.as_dict(private=False)]}

    monkeypatch.setattr(auth.server.token_verifier, "_fetch_jwks", fetch_jwks)
    return auth


@asynccontextmanager
async def serve(auth: MultiAuth) -> AsyncIterator[httpx.AsyncClient]:
    mcp = FastMCP("test", auth=auth)

    @mcp.tool
    def whoami(ctx: Context) -> dict[str, str | None]:
        token = get_request_token(ctx)
        return {"token": token, "cache_owner": get_cache_owner(token) if token else None}

    app = mcp.http_app(path="/", stateless_http=True)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield client


async def call_whoami(monkeypatch: pytest.MonkeyPatch, token: str | None) -> httpx.Response:
    headers = {"accept": "application/json, text/event-stream"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    async with serve(make_auth(monkeypatch)) as http:
        return await http.post(
            "/",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}},
            headers=headers,
        )


def tool_result(response: httpx.Response) -> dict[str, str | None]:
    for line in response.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line.removeprefix("data:"))["result"]["structuredContent"]
    return response.json()["result"]["structuredContent"]


class TestDiscovery:
    @pytest.mark.parametrize("resource_url", ["https://mcp.ipinfo.io", "https://mcp.ipinfo.io/"])
    async def test_metadata_advertises_the_audience_tokens_must_carry(
        self, monkeypatch: pytest.MonkeyPatch, resource_url: str
    ) -> None:
        auth = make_auth(monkeypatch, resource_url)
        async with serve(auth) as http:
            response = await http.get("/.well-known/oauth-protected-resource")

            assert response.status_code == 200
            metadata = response.json()
            assert metadata["resource"] == RESOURCE
            assert metadata["resource"] == auth.server.token_verifier.audience
            assert metadata["authorization_servers"] == [ISSUER]
            assert metadata["scopes_supported"] == ["ipinfo:read"]

    async def test_request_without_token_is_challenged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = await call_whoami(monkeypatch, None)

        assert response.status_code == 401
        assert f'resource_metadata="{METADATA_URL}"' in response.headers["www-authenticate"]


class TestOAuthAccessTokens:
    async def test_valid_token_is_forwarded_as_is(self, monkeypatch: pytest.MonkeyPatch) -> None:
        token = make_token()

        response = await call_whoami(monkeypatch, token)

        assert response.status_code == 200
        assert tool_result(response)["token"] == token

    async def test_cache_is_owned_by_the_account_not_the_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        first = tool_result(await call_whoami(monkeypatch, make_token()))
        refreshed = tool_result(await call_whoami(monkeypatch, make_token()))

        assert first["token"] != refreshed["token"]
        assert first["cache_owner"] == refreshed["cache_owner"] == "oauth:42"

    @pytest.mark.parametrize(
        "token",
        [
            pytest.param(make_token(exp=time.time() - 1), id="expired"),
            pytest.param(make_token(aud=[API_AUDIENCE]), id="other audience"),
            pytest.param(make_token(aud="https://mcp.ipinfo.io"), id="audience without trailing slash"),
            pytest.param(make_token(iss="https://example.com"), id="other issuer"),
            pytest.param(make_token(OTHER_KEY), id="other signing key"),
        ],
    )
    async def test_rejected_token_is_challenged(self, monkeypatch: pytest.MonkeyPatch, token: str) -> None:
        response = await call_whoami(monkeypatch, token)

        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]


class TestApiTokens:
    @pytest.mark.parametrize("token", API_TOKENS)
    async def test_api_token_is_forwarded_as_is(self, monkeypatch: pytest.MonkeyPatch, token: str) -> None:
        response = await call_whoami(monkeypatch, token)

        assert response.status_code == 200
        assert tool_result(response) == {"token": token, "cache_owner": token}


class TestIsJwt:
    def test_jwt(self) -> None:
        assert is_jwt(make_token())

    @pytest.mark.parametrize("token", [*API_TOKENS, "a.b.c", ""])
    def test_not_jwt(self, token: str) -> None:
        assert not is_jwt(token)


class TestServerAuth:
    def test_disabled_without_issuer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IPINFO_OAUTH_ISSUER", raising=False)

        assert server._auth() is None

    def test_issuer_requires_resource_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IPINFO_OAUTH_ISSUER", ISSUER)
        monkeypatch.delenv("IPINFO_MCP_RESOURCE_URL", raising=False)

        with pytest.raises(RuntimeError, match="IPINFO_MCP_RESOURCE_URL"):
            server._auth()

    def test_jwks_uri_defaults_to_the_issuer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IPINFO_OAUTH_ISSUER", ISSUER)
        monkeypatch.setenv("IPINFO_MCP_RESOURCE_URL", RESOURCE)
        monkeypatch.delenv("IPINFO_OAUTH_JWKS_URI", raising=False)

        auth = server._auth()

        assert auth is not None
        assert auth.server.token_verifier.jwks_uri == "https://ipinfo.io/.well-known/jwks.json"
