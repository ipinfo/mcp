import base64
import json
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
import pytest
from fastmcp import Context, FastMCP
from fastmcp.server.auth import AuthProvider
from fastmcp.server.dependencies import get_http_request
from joserfc.jwk import OKPKey
from pytest_httpx import HTTPXMock
from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send

from ipinfo_mcp import server
from ipinfo_mcp.aauth import resource
from ipinfo_mcp.aauth.app import AAuthMiddleware, agent_from_env, with_aauth
from ipinfo_mcp.aauth.protocol import REQUIRED_COMPONENTS
from ipinfo_mcp.aauth.resource import AgentVerifier, scope_agent
from ipinfo_mcp.auth import create_auth, get_request_token
from tests.aauth_helpers import (
    AGENT,
    MCP_AUTHORITY,
    FakeFetch,
    agent_token,
    make_agent_provider,
    provider_documents,
    run_lifespan,
    sign_request,
)
from tests.test_aauth_lite import BASE_URL, LITE_8888
from tests.test_aauth_resource import with_digest
from tests.test_auth import tool_result


@pytest.fixture
def documents(monkeypatch: pytest.MonkeyPatch) -> FakeFetch:
    fetch = FakeFetch(provider_documents())
    monkeypatch.setattr(resource, "ssrf_safe_fetch", fetch)
    return fetch


def provider_key_pem() -> str:
    return OKPKey.generate_key("Ed25519").as_pem(private=True).decode()


def whoami_server(name: str, auth: AuthProvider | None = None) -> FastMCP:
    mcp = FastMCP(name, auth=auth)

    @mcp.tool
    def whoami(ctx: Context) -> dict[str, str | None]:
        agent = scope_agent(get_http_request().scope)
        return {"server": name, "token": get_request_token(ctx), "agent": agent.identifier if agent else None}

    return mcp


@asynccontextmanager
async def serve(auth: AuthProvider | None) -> AsyncIterator[httpx.AsyncClient]:
    app = AAuthMiddleware(
        whoami_server("main", auth).http_app(path="/", stateless_http=True),
        agent=make_agent_provider(),
        agent_app=whoami_server("agents").http_app(path="/", stateless_http=True),
        verifier=AgentVerifier(authority=MCP_AUTHORITY),
        origin="https://mcp.ipinfo.io",
    )
    async with run_lifespan(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.ipinfo.io") as client:
            yield client


def oauth() -> AuthProvider:
    return create_auth(issuer="https://ipinfo.io", resource_url="https://mcp.ipinfo.io/")


def signed_now(**overrides: object) -> Callable[[httpx.Request], httpx.Request]:
    """httpx auth signing a request as an agent, at the current time."""

    def auth(request: httpx.Request) -> httpx.Request:
        now = int(time.time())
        claims = {"iat": now, "exp": now + 3600}
        return sign_request(request, jwt=agent_token(claims=claims, **overrides), created=now)

    return auth


async def call_whoami(
    http: httpx.AsyncClient,
    auth: Callable[[httpx.Request], httpx.Request] | None = None,
    token: str | None = None,
    path: str = "/",
) -> httpx.Response:
    headers = {"accept": "application/json, text/event-stream"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    return await http.post(
        path,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}},
        headers=headers,
        auth=auth,
    )


class TestMainEndpoint:
    """/ is untouched by AAuth: it signs people in with OAuth or takes their token, as before."""

    async def test_unsigned_request_is_offered_sign_in_only(self, documents: FakeFetch) -> None:
        async with serve(oauth()) as http:
            response = await call_whoami(http)

        assert response.status_code == 401
        assert 'resource_metadata="https://mcp.ipinfo.io/.well-known/oauth-protected-resource"' in (
            response.headers["www-authenticate"]
        )
        assert "aauth-requirement" not in response.headers

    async def test_signature_is_ignored(self, documents: FakeFetch) -> None:
        async with serve(oauth()) as http:
            response = await call_whoami(http, auth=signed_now())

        assert response.status_code == 401
        assert "www-authenticate" in response.headers
        assert documents.fetched == []

    async def test_token_is_used(self, documents: FakeFetch) -> None:
        async with serve(oauth()) as http:
            response = await call_whoami(http, auth=signed_now(), token="a1b2c3d4e5f6a7")

        assert response.status_code == 200
        assert tool_result(response) == {"server": "main", "token": "a1b2c3d4e5f6a7", "agent": None}
        assert documents.fetched == []


def jsonrpc(method: str, params: dict[str, object] | None = None) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}


async def post_unsigned(http: httpx.AsyncClient, path: str, body: object) -> httpx.Response:
    return await http.post(path, json=body, headers={"accept": "application/json, text/event-stream"})


class TestAgentEndpoint:
    async def test_unsigned_discovery_reaches_agents_even_with_oauth(self, documents: FakeFetch) -> None:
        initialize = jsonrpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})

        async with serve(oauth()) as http:
            initialized = await post_unsigned(http, "/aauth", initialize)
            listed = await post_unsigned(http, "/aauth", jsonrpc("tools/list"))

        assert initialized.status_code == 200
        assert '"name":"agents"' in initialized.text
        assert listed.status_code == 200
        assert '"whoami"' in listed.text
        assert documents.fetched == []

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(jsonrpc("tools/call", {"name": "whoami", "arguments": {}}), id="tool call"),
            pytest.param([jsonrpc("tools/list"), jsonrpc("tools/call", {"name": "whoami"})], id="batch with a call"),
            pytest.param("not json-rpc", id="not json-rpc"),
        ],
    )
    async def test_anything_else_unsigned_must_be_signed(self, documents: FakeFetch, body: object) -> None:
        async with serve(oauth()) as http:
            response = await post_unsigned(http, "/aauth", body)

        assert response.status_code == 401
        assert response.headers["aauth-requirement"] == "requirement=agent-token"
        assert "www-authenticate" not in response.headers

    async def test_signed_call_reaches_agents(self, documents: FakeFetch) -> None:
        async with serve(oauth()) as http:
            response = await call_whoami(http, auth=signed_now(), path="/aauth")

        assert response.status_code == 200
        assert tool_result(response) == {"server": "agents", "token": None, "agent": AGENT}

    async def test_signed_call_reaches_agents_without_oauth(self, documents: FakeFetch) -> None:
        async with serve(None) as http:
            response = await call_whoami(http, auth=signed_now(), path="/aauth")

        assert response.status_code == 200
        assert tool_result(response) == {"server": "agents", "token": None, "agent": AGENT}

    async def test_body_reaches_agents_after_its_digest_is_checked(self, documents: FakeFetch) -> None:
        def auth(request: httpx.Request) -> httpx.Request:
            now = int(time.time())
            return sign_request(
                with_digest(request),
                jwt=agent_token(claims={"iat": now, "exp": now + 3600}),
                created=now,
                components=(*REQUIRED_COMPONENTS, "content-digest"),
            )

        async with serve(oauth()) as http:
            response = await call_whoami(http, auth=auth, path="/aauth")

        assert response.status_code == 200
        assert tool_result(response)["agent"] == AGENT

    async def test_refused_signature_names_why(self, documents: FakeFetch) -> None:
        async with serve(oauth()) as http:
            response = await call_whoami(http, auth=signed_now(header={"alg": "EdDSA"}), path="/aauth")

        assert response.status_code == 401
        assert response.json() == {"error": "unsupported_algorithm"}
        assert response.headers["signature-error"] == "error=unsupported_algorithm"
        assert response.headers["accept-signature-alg"] == "Ed25519, ES256"
        assert "www-authenticate" not in response.headers

    async def test_missing_components_are_named(self, documents: FakeFetch) -> None:
        def auth(request: httpx.Request) -> httpx.Request:
            return sign_request(request, components=("@method", "@authority", "signature-key"))

        async with serve(oauth()) as http:
            response = await call_whoami(http, auth=auth, path="/aauth")

        assert response.status_code == 401
        assert response.headers["signature-error"] == (
            'error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key")'
        )

    async def test_connector_lists_unsigned_then_calls_signed(
        self, monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", json=LITE_8888)

        async with serve_app(monkeypatch) as http:
            listed = await rpc(http, "tools/list", {}, signed=False, path="/aauth")
            called = await rpc(
                http, "tools/call", {"name": "ipinfo_lite_lookup", "arguments": {"ips": ["8.8.8.8"]}}, signed=True, path="/aauth"
            )

        assert [tool["name"] for tool in listed["result"]["tools"]] == ["ipinfo_lite_lookup"]
        assert called["result"]["structuredContent"]["result"]["results"] == {"8.8.8.8": LITE_8888}
        # The API is told which agent the lookup is for
        lookup = httpx_mock.get_request()
        assert lookup is not None
        relayed = lookup.headers["IPinfo-Agent-Token"]
        claims = json.loads(base64.urlsafe_b64decode(relayed.split(".")[1] + "=="))
        assert claims["sub"] == AGENT


class TestConfiguration:
    def test_disabled_without_provider_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IPINFO_AAUTH_PROVIDER_KEY", raising=False)

        assert agent_from_env() is None

    def test_provider_key_requires_issuer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IPINFO_AAUTH_PROVIDER_KEY", provider_key_pem())
        monkeypatch.delenv("IPINFO_AAUTH_ISSUER", raising=False)

        with pytest.raises(RuntimeError, match="IPINFO_AAUTH_ISSUER"):
            agent_from_env()

    def test_agent_is_named_after_the_issuer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IPINFO_AAUTH_PROVIDER_KEY", provider_key_pem())
        monkeypatch.setenv("IPINFO_AAUTH_ISSUER", "https://mcp.ipinfo.io")

        provider = agent_from_env()

        assert provider is not None
        assert provider.agent == "aauth:ipinfo-mcp@mcp.ipinfo.io"

    def test_app_is_left_as_is_without_aauth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IPINFO_AAUTH_PROVIDER_KEY", raising=False)

        assert with_aauth(mcp_app, api_base_url=BASE_URL, cache_ttl=60) is mcp_app


class TestProviderDocuments:
    @pytest.mark.parametrize(
        ("path", "document"),
        [
            ("/.well-known/aauth-agent.json", "metadata"),
            ("/.well-known/aauth-jwks.json", "jwks"),
        ],
    )
    async def test_are_served(self, path: str, document: str) -> None:
        provider = make_agent_provider()
        app = AAuthMiddleware(
            mcp_app,
            agent=provider,
            agent_app=whoami_server("agents").http_app(path="/"),
            verifier=AgentVerifier(),
            origin="https://mcp.ipinfo.io",
        )

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.ipinfo.io") as http:
            response = await http.get(path)

        assert response.status_code == 200
        assert response.json() == getattr(provider, document)()

    async def test_resource_metadata_sends_agents_to_their_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async with serve_app(monkeypatch) as http:
            response = await http.get("/.well-known/aauth-resource.json")

        assert response.status_code == 200
        assert response.json() == {
            "issuer": "https://mcp.ipinfo.io",
            "name": "IPinfo",
            "description": (
                "IP address geolocation and network (ASN) data from IPinfo Lite, without an IPinfo account"
            ),
            "access_mode": "agent-token",
            "r3_vocabularies": {"urn:aauth:vocabulary:mcp": "https://mcp.ipinfo.io/aauth"},
        }

    async def test_resource_metadata_names_the_public_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IPINFO_MCP_RESOURCE_URL", "http://LocalHost:8000/")

        async with serve_app(monkeypatch) as http:
            response = await http.get("/.well-known/aauth-resource.json")

        metadata = response.json()
        assert metadata["issuer"] == "http://localhost:8000"
        assert metadata["r3_vocabularies"] == {"urn:aauth:vocabulary:mcp": "http://localhost:8000/aauth"}

    async def test_are_served_with_the_whole_app(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async with serve_app(monkeypatch) as http:
            response = await http.get("/.well-known/aauth-agent.json")

        assert response.status_code == 200
        assert response.json()["issuer"] == "https://mcp.ipinfo.io"


async def mcp_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Stands in for the MCP app everyone else uses."""
    await PlainTextResponse("from the MCP app", status_code=404)(scope, receive, send)


MAIN_TOOLS = [
    "ipinfo_lookup",
    "ipinfo_check_privacy",
    "ipinfo_check_residential_proxy",
    "ipinfo_geolocate",
    "ipinfo_asn",
    "ipinfo_quota",
]


@asynccontextmanager
async def serve_app(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    """The whole HTTP app, with AAuth configured, as the server runs it."""
    monkeypatch.setenv("IPINFO_AAUTH_PROVIDER_KEY", provider_key_pem())
    monkeypatch.setenv("IPINFO_AAUTH_ISSUER", "https://mcp.ipinfo.io")
    monkeypatch.setattr(resource, "ssrf_safe_fetch", FakeFetch(provider_documents()))
    app = server.create_app()
    async with run_lifespan(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.ipinfo.io") as http:
            yield http


async def rpc(
    http: httpx.AsyncClient, method: str, params: dict[str, object], *, signed: bool, path: str = "/"
) -> dict[str, object]:
    response = await http.post(
        path,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers={"accept": "application/json, text/event-stream"},
        auth=signed_now() if signed else None,
    )
    assert response.status_code == 200, response.text
    for line in response.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line.removeprefix("data:"))
    return response.json()


class TestServers:
    async def test_agents_see_only_the_lite_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async with serve_app(monkeypatch) as http:
            listed = await rpc(http, "tools/list", {}, signed=True, path="/aauth")

        assert [tool["name"] for tool in listed["result"]["tools"]] == ["ipinfo_lite_lookup"]

    async def test_everyone_else_sees_the_usual_tools(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async with serve_app(monkeypatch) as http:
            listed = await rpc(http, "tools/list", {}, signed=False)

        assert [tool["name"] for tool in listed["result"]["tools"]] == MAIN_TOOLS

    async def test_agents_get_lite_data(self, monkeypatch: pytest.MonkeyPatch, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/lite/8.8.8.8", method="GET", json=LITE_8888)

        async with serve_app(monkeypatch) as http:
            called = await rpc(
                http,
                "tools/call",
                {"name": "ipinfo_lite_lookup", "arguments": {"ips": ["8.8.8.8"]}},
                signed=True,
                path="/aauth",
            )

        assert called["result"]["structuredContent"]["result"]["results"] == {"8.8.8.8": LITE_8888}
        request = httpx_mock.get_request()
        assert request is not None
        assert "Signature" in request.headers

    async def test_agents_cant_call_the_usual_tools(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async with serve_app(monkeypatch) as http:
            called = await rpc(
                http, "tools/call", {"name": "ipinfo_lookup", "arguments": {"ips": ["8.8.8.8"]}}, signed=True, path="/aauth"
            )

        assert called["result"]["isError"] is True
        assert "ipinfo_lookup" in called["result"]["content"][0]["text"]
