import hashlib
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from http_sf import ser

from ipinfo_mcp.aauth import resource
from ipinfo_mcp.aauth.protocol import REQUIRED_COMPONENTS
from ipinfo_mcp.aauth.resource import Person, PersonTokenRequiredError, PersonVerifier, SignatureError
from tests.aauth_helpers import (
    NOW,
    OTHER_AGENT_KEY,
    OTHER_PERSON_SERVER_KEY,
    P256_AGENT_KEY,
    PERSON,
    PERSON_SERVER,
    FakeFetch,
    agent_token,
    asgi_scope,
    make_person_verifier,
    mcp_request,
    person_server_documents,
    person_token,
    sign_request,
)


@pytest.fixture
def documents(monkeypatch: pytest.MonkeyPatch) -> FakeFetch:
    fetch = FakeFetch(person_server_documents())
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
    request: httpx.Request, *, verifier: PersonVerifier | None = None, now: int | None = NOW
) -> Person:
    verifier = verifier or make_person_verifier()
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


def signed_with(**token: Any) -> Callable[[], httpx.Request]:
    """A request signed with a person token built from token."""
    return lambda: sign_request(mcp_request(), jwt=person_token(**token))


class TestVerify:
    async def test_accepts_signed_request(self, documents: FakeFetch) -> None:
        jwt = person_token()

        person = await verify_request(sign_request(mcp_request(), jwt=jwt))

        assert person == Person(identifier=PERSON, issuer=PERSON_SERVER, token=jwt)

    async def test_accepts_p256_agent_key(self, documents: FakeFetch) -> None:
        jwt = person_token(agent_key=P256_AGENT_KEY, agent_alg="ES256")

        person = await verify_request(sign_request(mcp_request(), jwt=jwt, key=P256_AGENT_KEY, alg="ES256"))

        assert person.identifier == PERSON

    async def test_accepts_covered_query(self, documents: FakeFetch) -> None:
        request = mcp_request(url="https://mcp.ipinfo.io/?debug=1")

        person = await verify_request(sign_request(request, components=(*REQUIRED_COMPONENTS, "@query")))

        assert person.identifier == PERSON

    async def test_accepts_body_matching_covered_digest(self, documents: FakeFetch) -> None:
        request = with_digest(mcp_request())

        person = await verify_request(
            sign_request(request, components=(*REQUIRED_COMPONENTS, "content-type", "content-digest"))
        )

        assert person.identifier == PERSON

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

    async def test_agent_token_is_asked_for_a_person_token(self, documents: FakeFetch) -> None:
        with pytest.raises(PersonTokenRequiredError):
            await verify_request(sign_request(mcp_request(), jwt=agent_token()))

        assert documents.fetched == []

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
            pytest.param(signed_with(claims={"exp": NOW}), "expired_jwt", id="expired token"),
            pytest.param(signed_with(claims={"iat": NOW + 61}), "clock_skew", id="token issued ahead"),
            pytest.param(signed_with(header={"typ": "JWT"}), "invalid_jwt", id="not a person token"),
            pytest.param(signed_with(header={"kid": None}), "invalid_jwt", id="no kid"),
            pytest.param(signed_with(header={"alg": "EdDSA"}), "unsupported_algorithm", id="EdDSA token"),
            pytest.param(signed_with(header={"alg": "RS256"}), "unsupported_algorithm", id="RS256 token"),
            pytest.param(signed_with(claims={"iss": None}), "issuer_missing", id="no issuer"),
            pytest.param(
                signed_with(claims={"iss": "https://person.example/"}), "invalid_jwt", id="issuer with trailing slash"
            ),
            pytest.param(
                signed_with(claims={"dwk": "aauth-agent.json"}), "invalid_jwt", id="other metadata document"
            ),
            pytest.param(signed_with(claims={"jti": None}), "invalid_jwt", id="no jti"),
            pytest.param(signed_with(claims={"sub": None}), "invalid_jwt", id="no person"),
            pytest.param(signed_with(claims={"sub": ""}), "invalid_jwt", id="empty person"),
            pytest.param(signed_with(claims={"aud": None}), "invalid_jwt", id="no audience"),
            pytest.param(signed_with(claims={"exp": NOW + 3601}), "invalid_jwt", id="lives longer than an hour"),
            pytest.param(signed_with(claims={"scope": "lite"}), "invalid_jwt", id="carries a scope"),
            pytest.param(signed_with(claims={"account": "acct-1"}), "invalid_jwt", id="carries an account"),
            pytest.param(signed_with(agent_alg="EdDSA"), "unsupported_algorithm", id="EdDSA agent key"),
            pytest.param(
                lambda: sign_request(
                    mcp_request(),
                    jwt=person_token(agent_key=P256_AGENT_KEY, agent_alg="Ed25519"),
                    key=P256_AGENT_KEY,
                    alg="ES256",
                ),
                "invalid_key",
                id="agent key type disagrees with its alg",
            ),
            pytest.param(
                signed_with(claims={"iss": "https://other.example"}), "invalid_jwt", id="person server not allowed"
            ),
            pytest.param(
                signed_with(claims={"aud": "https://other.example"}), "invalid_jwt", id="issued for another resource"
            ),
            pytest.param(
                signed_with(claims={"aud": "https://mcp.ipinfo.io/aauth"}),
                "invalid_jwt",
                id="issued for the endpoint instead of the resource",
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
            pytest.param(signed_with(header={"kid": "unknown"}), "unknown_key", id="person server key not published"),
            pytest.param(
                signed_with(server_key=OTHER_PERSON_SERVER_KEY), "invalid_jwt", id="not signed by its person server"
            ),
        ],
    )
    async def test_refuses(
        self, documents: FakeFetch, request_factory: Callable[[], httpx.Request], code: str
    ) -> None:
        with pytest.raises(SignatureError) as refused:
            await verify_request(request_factory())

        assert refused.value.code == code

    async def test_person_server_not_allowed_is_not_fetched(self, documents: FakeFetch) -> None:
        jwt = person_token(claims={"iss": "https://other.example"})

        with pytest.raises(SignatureError):
            await verify_request(sign_request(mcp_request(), jwt=jwt))

        assert documents.fetched == []

    async def test_any_authority_is_accepted_when_none_is_configured(self, documents: FakeFetch) -> None:
        request = sign_request(mcp_request(url="http://localhost:8000/"))

        person = await verify_request(request, verifier=make_person_verifier(authority=None))

        assert person.identifier == PERSON


class TestPersonServerKeys:
    async def test_refuses_unreachable_person_server(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(resource, "ssrf_safe_fetch", FakeFetch({}))

        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request()))

        assert refused.value.code == "unknown_key"

    @pytest.mark.parametrize(
        ("metadata", "code"),
        [
            pytest.param({"issuer": "https://other.example"}, "issuer_mismatch", id="other issuer"),
            pytest.param({"issuer": None}, "issuer_mismatch", id="null issuer"),
            pytest.param({"jwks_uri": "http://person.example/jwks.json"}, "unknown_key", id="keys not over https"),
        ],
    )
    async def test_refuses_metadata(
        self, monkeypatch: pytest.MonkeyPatch, metadata: dict[str, object], code: str
    ) -> None:
        monkeypatch.setattr(resource, "ssrf_safe_fetch", FakeFetch(person_server_documents(metadata=metadata)))

        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request()))

        assert refused.value.code == code

    async def test_refuses_metadata_without_issuer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        documents = person_server_documents()
        del documents["https://person.example/.well-known/aauth-person.json"]["issuer"]
        monkeypatch.setattr(resource, "ssrf_safe_fetch", FakeFetch(documents))

        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request()))

        assert refused.value.code == "issuer_missing"

    async def test_are_fetched_once_for_many_requests(self, documents: FakeFetch, clock: FakeTime) -> None:
        verifier = make_person_verifier()

        await verify_request(sign_request(mcp_request()), verifier=verifier)
        clock.elapsed = 599
        await verify_request(sign_request(mcp_request()), verifier=verifier)

        assert documents.fetched == [
            "https://person.example/.well-known/aauth-person.json",
            "https://person.example/jwks.json",
        ]

    async def test_are_fetched_again_after_ten_minutes(self, documents: FakeFetch, clock: FakeTime) -> None:
        verifier = make_person_verifier()

        await verify_request(sign_request(mcp_request()), verifier=verifier)
        clock.elapsed = 600
        await verify_request(sign_request(mcp_request()), verifier=verifier)

        assert len(documents.fetched) == 4

    async def test_rotated_key_is_fetched_early_but_once_a_minute(self, documents: FakeFetch, clock: FakeTime) -> None:
        verifier = make_person_verifier()
        await verify_request(sign_request(mcp_request()), verifier=verifier)
        # The person server starts signing with a key we haven't fetched yet
        jwks = documents.documents["https://person.example/jwks.json"]
        jwks["keys"].append({**OTHER_PERSON_SERVER_KEY.as_dict(private=False), "kid": "ps-key-2", "alg": "Ed25519"})
        rotated = person_token(header={"kid": "ps-key-2"}, server_key=OTHER_PERSON_SERVER_KEY)

        clock.elapsed = 59
        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request(), jwt=rotated), verifier=verifier)
        assert refused.value.code == "unknown_key"
        assert len(documents.fetched) == 2

        clock.elapsed = 60
        person = await verify_request(sign_request(mcp_request(), jwt=rotated), verifier=verifier)
        assert person.identifier == PERSON
        assert len(documents.fetched) == 4

    async def test_key_with_another_alg_is_not_used(self, documents: FakeFetch) -> None:
        jwks = documents.documents["https://person.example/jwks.json"]
        jwks["keys"][0]["alg"] = "ES256"

        with pytest.raises(SignatureError) as refused:
            await verify_request(sign_request(mcp_request()))

        assert refused.value.code == "unknown_key"

    async def test_failed_fetch_is_retried_after_a_minute(
        self, monkeypatch: pytest.MonkeyPatch, clock: FakeTime
    ) -> None:
        fetch = FakeFetch({})
        monkeypatch.setattr(resource, "ssrf_safe_fetch", fetch)
        verifier = make_person_verifier()
        with pytest.raises(SignatureError):
            await verify_request(sign_request(mcp_request()), verifier=verifier)

        fetch.documents = person_server_documents()
        clock.elapsed = 60
        person = await verify_request(sign_request(mcp_request()), verifier=verifier)

        assert person.identifier == PERSON
