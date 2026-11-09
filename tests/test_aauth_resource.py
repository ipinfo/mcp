import hashlib
from collections.abc import Callable

import httpx
import pytest
from http_sf import ser

from ipinfo_mcp.aauth import resource
from ipinfo_mcp.aauth.protocol import REQUIRED_COMPONENTS
from ipinfo_mcp.aauth.resource import Agent, AgentVerifier, SignatureError
from tests.aauth_helpers import (
    AGENT,
    AGENT_ISSUER,
    MCP_AUTHORITY,
    NOW,
    OTHER_AGENT_KEY,
    OTHER_PROVIDER_KEY,
    P256_AGENT_KEY,
    FakeFetch,
    agent_token,
    asgi_scope,
    make_agent_provider,
    mcp_request,
    provider_documents,
    sign_request,
)


@pytest.fixture
def documents(monkeypatch: pytest.MonkeyPatch) -> FakeFetch:
    fetch = FakeFetch(provider_documents())
    monkeypatch.setattr(resource, "ssrf_safe_fetch", fetch)
    return fetch


class FakeTime:
    """Stands in for the time module in ipinfo_mcp.aauth.resource, so cache ages can be moved."""

    def __init__(self) -> None:
        self.elapsed = 0.0

    def time(self) -> float:
        return NOW + self.elapsed

    def monotonic(self) -> float:
        return 1000 + self.elapsed


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeTime:
    fake = FakeTime()
    monkeypatch.setattr(resource, "time", fake)
    return fake


async def verify_request(
    request: httpx.Request, *, verifier: AgentVerifier | None = None, now: int | None = NOW
) -> Agent:
    verifier = verifier or AgentVerifier(authority=MCP_AUTHORITY)
    return await verifier.verify(asgi_scope(request), request.content, now=now)


def with_digest(request: httpx.Request, body: bytes | None = None, algorithm: str = "sha-256") -> httpx.Request:
    digest = hashlib.sha256(request.content if body is None else body).digest()
    request.headers["Content-Digest"] = ser({algorithm: (digest, {})})
    return request


def moved(request: httpx.Request, url: str) -> httpx.Request:
    """The signed request, sent to url instead."""
    return httpx.Request(request.method, url, headers=request.headers, content=request.content)


def relabeled(request: httpx.Request) -> httpx.Request:
    """The signed request, with its Signature under a label the other headers don't use."""
    request.headers["Signature"] = request.headers["Signature"].replace("sig=", "other=", 1)
    return request


def unsigned_key(request: httpx.Request) -> httpx.Request:
    del request.headers["Signature-Key"]
    return request


class TestVerify:
    async def test_accepts_signed_request(self, documents: FakeFetch) -> None:
        jwt = agent_token()

        agent = await verify_request(sign_request(mcp_request(), jwt=jwt))

        assert agent == Agent(identifier=AGENT, issuer=AGENT_ISSUER, token=jwt)

    async def test_accepts_p256_agent_key(self, documents: FakeFetch) -> None:
        jwt = agent_token(agent_key=P256_AGENT_KEY, agent_alg="ES256")

        agent = await verify_request(sign_request(mcp_request(), jwt=jwt, key=P256_AGENT_KEY, alg="ES256"))

        assert agent.identifier == AGENT

    async def test_accepts_request_our_own_agent_signed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = make_agent_provider("https://agents.example")
        monkeypatch.setattr(
            resource,
            "ssrf_safe_fetch",
            FakeFetch(
                {
                    "https://agents.example/.well-known/aauth-agent.json": provider.metadata(),
                    "https://agents.example/.well-known/aauth-jwks.json": provider.jwks(),
                }
            ),
        )

        agent = await verify_request(provider.sign(mcp_request()), now=None)

        assert agent.identifier == "aauth:ipinfo-mcp@agents.example"

    async def test_accepts_covered_query(self, documents: FakeFetch) -> None:
        request = mcp_request(url="https://mcp.ipinfo.io/?debug=1")

        agent = await verify_request(sign_request(request, components=(*REQUIRED_COMPONENTS, "@query")))

        assert agent.identifier == AGENT

    async def test_accepts_body_matching_covered_digest(self, documents: FakeFetch) -> None:
        request = with_digest(mcp_request())

        agent = await verify_request(
            sign_request(request, components=(*REQUIRED_COMPONENTS, "content-type", "content-digest"))
        )

        assert agent.identifier == AGENT

    @pytest.mark.parametrize(
        "request_factory",
        [
            pytest.param(lambda: with_digest(mcp_request(), body=b"{}"), id="digest of another body"),
            pytest.param(lambda: with_digest(mcp_request(), algorithm="md5"), id="digest algorithm we don't know"),
        ],
    )
    async def test_refuses_body_not_matching_covered_digest(
        self, documents: FakeFetch, request_factory: Callable[[], httpx.Request]
    ) -> None:
        request = sign_request(request_factory(), components=(*REQUIRED_COMPONENTS, "content-digest"))

        with pytest.raises(SignatureError) as refused:
            await verify_request(request)

        assert refused.value.code == "invalid_signature"

    @pytest.mark.parametrize(
        ("request_factory", "code"),
        [
            pytest.param(mcp_request, "invalid_signature", id="unsigned"),
            pytest.param(lambda: unsigned_key(sign_request(mcp_request())), "invalid_signature", id="no Signature-Key"),
            pytest.param(lambda: relabeled(sign_request(mcp_request())), "invalid_signature", id="labels differ"),
            pytest.param(lambda: sign_request(mcp_request(), scheme="hwk"), "unsupported_scheme", id="hwk scheme"),
            pytest.param(
                lambda: sign_request(mcp_request(), components=("@method", "@authority", "signature-key")),
                "invalid_input",
                id="path not covered",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), components=(*REQUIRED_COMPONENTS, "@target-uri")),
                "invalid_input",
                id="derived component we can't check",
            ),
            pytest.param(lambda: sign_request(mcp_request(), created=NOW - 61), "invalid_signature", id="too old"),
            pytest.param(lambda: sign_request(mcp_request(), created=NOW + 61), "clock_skew", id="created ahead"),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(claims={"exp": NOW})),
                "expired_jwt",
                id="expired token",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(claims={"iat": NOW + 61})),
                "clock_skew",
                id="token issued ahead",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(header={"typ": "JWT"})),
                "invalid_jwt",
                id="not an agent token",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(header={"alg": "EdDSA"})),
                "unsupported_algorithm",
                id="EdDSA token",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(claims={"iss": None})),
                "issuer_missing",
                id="no issuer",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(claims={"iss": "https://agents.example/"})),
                "invalid_jwt",
                id="issuer with trailing slash",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(claims={"sub": "aauth:assistant@other.example"})),
                "invalid_jwt",
                id="agent of another provider",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(claims={"dwk": "aauth-person.json"})),
                "invalid_jwt",
                id="other metadata document",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(agent_alg="EdDSA")),
                "unsupported_algorithm",
                id="EdDSA agent key",
            ),
            pytest.param(
                lambda: sign_request(
                    mcp_request(),
                    jwt=agent_token(agent_key=P256_AGENT_KEY, agent_alg="Ed25519"),
                    key=P256_AGENT_KEY,
                    alg="ES256",
                ),
                "invalid_key",
                id="agent key type disagrees with its alg",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), key=OTHER_AGENT_KEY),
                "invalid_signature",
                id="signed with a key the token doesn't bind",
            ),
            pytest.param(
                lambda: moved(sign_request(mcp_request()), "https://mcp.ipinfo.io/other"),
                "invalid_signature",
                id="sent to another path",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(url="https://other.example/")),
                "invalid_signature",
                id="signed for another server",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(header={"kid": "unknown"})),
                "unknown_key",
                id="provider key not published",
            ),
            pytest.param(
                lambda: sign_request(mcp_request(), jwt=agent_token(provider_key=OTHER_PROVIDER_KEY)),
                "invalid_jwt",
                id="token not signed by its provider",
            ),
        ],
    )
    async def test_refuses(
        self, documents: FakeFetch, request_factory: Callable[[], httpx.Request], code: str
    ) -> None:
        with pytest.raises(SignatureError) as refused:
            await verify_request(request_factory())

        assert refused.value.code == code

    async def test_any_authority_is_accepted_when_none_is_configured(self, documents: FakeFetch) -> None:
        request = sign_request(mcp_request(url="http://localhost:8000/"))

        agent = await verify_request(request, verifier=AgentVerifier())

        assert agent.identifier == AGENT


class TestProviderKeys:
    async def test_refuses_unreachable_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(resource, "ssrf_safe_fetch", FakeFetch({}))

        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request()))

        assert refused.value.code == "unknown_key"

    @pytest.mark.parametrize(
        ("metadata", "code"),
        [
            pytest.param({"issuer": "https://other.example"}, "issuer_mismatch", id="other issuer"),
            pytest.param({"issuer": None}, "issuer_mismatch", id="null issuer"),
            pytest.param({"jwks_uri": "http://agents.example/jwks.json"}, "unknown_key", id="keys not over https"),
        ],
    )
    async def test_refuses_metadata(
        self, monkeypatch: pytest.MonkeyPatch, metadata: dict[str, object], code: str
    ) -> None:
        monkeypatch.setattr(resource, "ssrf_safe_fetch", FakeFetch(provider_documents(metadata=metadata)))

        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request()))

        assert refused.value.code == code

    async def test_refuses_metadata_without_issuer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        documents = provider_documents()
        del documents["https://agents.example/.well-known/aauth-agent.json"]["issuer"]
        monkeypatch.setattr(resource, "ssrf_safe_fetch", FakeFetch(documents))

        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request()))

        assert refused.value.code == "issuer_missing"

    async def test_are_fetched_once_for_many_requests(self, documents: FakeFetch, clock: FakeTime) -> None:
        verifier = AgentVerifier(authority=MCP_AUTHORITY)

        await verify_request(sign_request(mcp_request()), verifier=verifier)
        clock.elapsed = 599
        await verify_request(sign_request(mcp_request()), verifier=verifier)

        assert documents.fetched == ["https://agents.example/.well-known/aauth-agent.json", "https://agents.example/jwks.json"]

    async def test_are_fetched_again_after_ten_minutes(self, documents: FakeFetch, clock: FakeTime) -> None:
        verifier = AgentVerifier(authority=MCP_AUTHORITY)

        await verify_request(sign_request(mcp_request()), verifier=verifier)
        clock.elapsed = 600
        await verify_request(sign_request(mcp_request()), verifier=verifier)

        assert len(documents.fetched) == 4

    async def test_rotated_key_is_fetched_early_but_once_a_minute(self, documents: FakeFetch, clock: FakeTime) -> None:
        verifier = AgentVerifier(authority=MCP_AUTHORITY)
        await verify_request(sign_request(mcp_request()), verifier=verifier)
        # The provider starts signing with a key we haven't fetched yet
        jwks = documents.documents["https://agents.example/jwks.json"]
        jwks["keys"].append({**OTHER_PROVIDER_KEY.as_dict(private=False), "kid": "ap-key-2", "alg": "Ed25519"})
        rotated = agent_token(header={"kid": "ap-key-2"}, provider_key=OTHER_PROVIDER_KEY)

        clock.elapsed = 59
        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request(), jwt=rotated), verifier=verifier)
        assert refused.value.code == "unknown_key"
        assert len(documents.fetched) == 2

        clock.elapsed = 60
        agent = await verify_request(sign_request(mcp_request(), jwt=rotated), verifier=verifier)
        assert agent.identifier == AGENT
        assert len(documents.fetched) == 4

    async def test_failed_fetch_is_retried_after_a_minute(
        self, monkeypatch: pytest.MonkeyPatch, clock: FakeTime
    ) -> None:
        fetch = FakeFetch({})
        monkeypatch.setattr(resource, "ssrf_safe_fetch", fetch)
        verifier = AgentVerifier(authority=MCP_AUTHORITY)
        with pytest.raises(SignatureError):
            await verify_request(sign_request(mcp_request()), verifier=verifier)

        fetch.documents = provider_documents()
        clock.elapsed = 60
        agent = await verify_request(sign_request(mcp_request()), verifier=verifier)

        assert agent.identifier == AGENT
