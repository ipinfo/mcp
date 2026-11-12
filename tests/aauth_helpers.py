import asyncio
import base64
import json
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

import httpx
from fastmcp.server.auth.ssrf import SSRFFetchError
from http_sf import Token, ser
from http_sf.innerlist import ser_innerlist
from joserfc.jwk import ECKey, OKPKey
from starlette.types import ASGIApp, Message, Scope

from ipinfo_mcp.aauth.agent import AgentProvider
from ipinfo_mcp.aauth.protocol import REQUIRED_COMPONENTS, sign
from ipinfo_mcp.aauth.resource import PersonVerifier

NOW = 1800000000

# The agent provider of the agents that call this server in tests, and one of its agents
AGENT_ISSUER = "https://agents.example"
AGENT = "aauth:assistant@agents.example"
PROVIDER_KID = "ap-key-1"
PROVIDER_KEY = OKPKey.generate_key("Ed25519")
AGENT_KEY = OKPKey.generate_key("Ed25519")
OTHER_AGENT_KEY = OKPKey.generate_key("Ed25519")
P256_AGENT_KEY = ECKey.generate_key("P-256")

# The person server of the people agents call this server for, and one of them
PERSON_SERVER = "https://person.example"
PERSON = "person-7f3c"
PERSON_SERVER_KID = "ps-key-1"
PERSON_SERVER_KEY = OKPKey.generate_key("Ed25519")
OTHER_PERSON_SERVER_KEY = OKPKey.generate_key("Ed25519")

# This server, as agents reach it
MCP_URL = "https://mcp.ipinfo.io/"
MCP_ORIGIN = "https://mcp.ipinfo.io"
MCP_AUTHORITY = "mcp.ipinfo.io"


def make_agent_provider(issuer: str = "https://mcp.ipinfo.io") -> AgentProvider:
    return AgentProvider(issuer=issuer, provider_key=OKPKey.generate_key("Ed25519").as_pem(private=True).decode())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt(header: dict[str, object], claims: dict[str, object], key: OKPKey) -> str:
    """
    Build a JWT signed with key. A claim set to None is left out.
    """
    claims = {name: value for name, value in claims.items() if value is not None}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
    return f"{signing_input}.{_b64url(sign(signing_input.encode(), key, 'Ed25519'))}"


def agent_token(
    *,
    header: dict[str, object] | None = None,
    claims: dict[str, object] | None = None,
    agent_key: OKPKey | ECKey = AGENT_KEY,
) -> str:
    """
    Build an agent token the way an agent provider issues one. A claim set to None is left out.
    """
    return _jwt(
        {"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": PROVIDER_KID, **(header or {})},
        {
            "iss": AGENT_ISSUER,
            "dwk": "aauth-agent.json",
            "sub": AGENT,
            "jti": "token-1",
            "iat": NOW,
            "exp": NOW + 3600,
            "ps": PERSON_SERVER,
            "cnf": {"jwk": {**agent_key.as_dict(private=False), "alg": "Ed25519"}},
            **(claims or {}),
        },
        PROVIDER_KEY,
    )


def person_token(
    *,
    header: dict[str, object] | None = None,
    claims: dict[str, object] | None = None,
    server_key: OKPKey = PERSON_SERVER_KEY,
    agent_key: OKPKey | ECKey = AGENT_KEY,
    agent_alg: str = "Ed25519",
) -> str:
    """
    Build a person token the way a person server issues one for an agent. A claim set to None is left out.
    """
    return _jwt(
        {"alg": "Ed25519", "typ": "aa-person+jwt", "kid": PERSON_SERVER_KID, **(header or {})},
        {
            "iss": PERSON_SERVER,
            "dwk": "aauth-person.json",
            "sub": PERSON,
            "aud": MCP_ORIGIN,
            "jti": "person-token-1",
            "iat": NOW,
            "exp": NOW + 3600,
            "cnf": {"jwk": {**agent_key.as_dict(private=False), "alg": agent_alg}},
            **(claims or {}),
        },
        server_key,
    )


def _component(request: httpx.Request, name: str) -> str:
    match name:
        case "@method":
            return request.method
        case "@authority":
            return request.headers["host"]
        case "@path":
            return request.url.path
        case "@query":
            return f"?{request.url.query.decode()}"
        case "@target-uri":
            return str(request.url)
        case _:
            return request.headers[name]


def sign_request(
    request: httpx.Request,
    *,
    jwt: str | None = None,
    key: OKPKey | ECKey = AGENT_KEY,
    alg: str = "Ed25519",
    components: Sequence[str] = REQUIRED_COMPONENTS,
    created: int = NOW,
    label: str = "sig",
    scheme: str = "jwt",
) -> httpx.Request:
    """
    Sign request the way an AAuth agent does, presenting jwt, a person token unless given, and covering components.
    """
    jwt = person_token() if jwt is None else jwt
    request.headers["Signature-Key"] = ser({label: (Token(scheme), {"jwt": jwt})})
    params = ser_innerlist(([(name, {}) for name in components], {"created": created}))
    lines = [f'"{name}": {_component(request, name)}' for name in components]
    lines.append(f'"@signature-params": {params}')
    request.headers["Signature-Input"] = f"{label}={params}"
    request.headers["Signature"] = ser({label: (sign("\n".join(lines).encode(), key, alg), {})})
    return request


def mcp_request(body: bytes = b'{"jsonrpc": "2.0"}', url: str = MCP_URL) -> httpx.Request:
    return httpx.Request("POST", url, content=body, headers={"content-type": "application/json"})


def asgi_scope(request: httpx.Request) -> Scope:
    raw_path, _, query = request.url.raw_path.partition(b"?")
    return {
        "type": "http",
        "method": request.method,
        "path": request.url.path,
        "raw_path": raw_path,
        "query_string": query,
        "headers": [(name.lower(), value) for name, value in request.headers.raw],
    }


def person_server_documents(metadata: dict[str, object] | None = None) -> dict[str, object]:
    """
    The documents the person server publishes, by URL. metadata overrides members of its metadata document.
    """
    return {
        f"{PERSON_SERVER}/.well-known/aauth-person.json": {
            "issuer": PERSON_SERVER,
            "jwks_uri": f"{PERSON_SERVER}/jwks.json",
            **(metadata or {}),
        },
        f"{PERSON_SERVER}/jwks.json": {
            "keys": [
                {**PERSON_SERVER_KEY.as_dict(private=False), "kid": PERSON_SERVER_KID, "alg": "Ed25519", "use": "sig"}
            ]
        },
    }


def make_person_verifier(authority: str | None = MCP_AUTHORITY) -> PersonVerifier:
    """
    The verifier of this server, which takes person tokens from the person server, issued for it.
    """
    return PersonVerifier(audience=MCP_ORIGIN, person_servers=[PERSON_SERVER], authority=authority)


class FakeFetch:
    """
    Stands in for ssrf_safe_fetch, serving documents by URL and recording what was fetched.
    """

    def __init__(self, documents: dict[str, object]) -> None:
        self.documents = documents
        self.fetched: list[str] = []

    async def __call__(self, url: str, **_: object) -> bytes:
        self.fetched.append(url)
        if url not in self.documents:
            raise SSRFFetchError(f"{url} unreachable")
        return json.dumps(self.documents[url]).encode()


@asynccontextmanager
async def run_lifespan(app: ASGIApp) -> AsyncIterator[None]:
    """
    Start and stop app through the ASGI lifespan protocol, as uvicorn does.
    """
    messages: asyncio.Queue[Message] = asyncio.Queue()
    started = asyncio.Event()
    sent: list[str] = []

    async def send(message: Message) -> None:
        sent.append(message["type"])
        if message["type"] == "lifespan.startup.complete":
            started.set()

    await messages.put({"type": "lifespan.startup"})
    task = asyncio.create_task(app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, messages.get, send))
    await started.wait()
    try:
        yield
    finally:
        await messages.put({"type": "lifespan.shutdown"})
        await task
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
