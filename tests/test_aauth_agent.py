import base64
import json

import httpx
import pytest
from http_sf import parse
from joserfc import jws
from joserfc.jwk import ECKey, JWKRegistry, OKPKey

from ipinfo_mcp.aauth import agent as agent_module
from ipinfo_mcp.aauth.agent import AgentProvider
from ipinfo_mcp.aauth.protocol import verify
from tests.aauth_helpers import make_agent_provider

ISSUER = "https://mcp.ipinfo.io"


def decode_token(provider: AgentProvider, token: str) -> tuple[dict[str, object], dict[str, object]]:
    """Verify an agent token with the provider's published key, the way the API does, and decode it."""
    key = JWKRegistry.import_key(provider.jwks()["keys"][0])
    token_object = jws.deserialize_compact(token, key, algorithms=["Ed25519"])
    return token_object.headers(), json.loads(token_object.payload)


class TestProviderDocuments:
    def test_metadata_points_at_the_keys(self) -> None:
        provider = make_agent_provider(ISSUER)

        assert provider.metadata() == {
            "issuer": "https://mcp.ipinfo.io",
            "jwks_uri": "https://mcp.ipinfo.io/.well-known/aauth-jwks.json",
            "name": "IPinfo MCP Server",
            "documentation_uri": "https://github.com/ipinfo/mcp",
        }

    def test_jwks_publishes_the_public_provider_key(self) -> None:
        provider = make_agent_provider(ISSUER)

        [key] = provider.jwks()["keys"]

        assert key["kty"] == "OKP"
        assert key["crv"] == "Ed25519"
        assert key["alg"] == "Ed25519"
        assert key["use"] == "sig"
        assert "d" not in key
        assert key["kid"] == OKPKey.import_key(key).thumbprint()


class TestAgentToken:
    def test_names_this_server_as_its_own_agent(self) -> None:
        provider = make_agent_provider(ISSUER)

        header, claims = decode_token(provider, provider.agent_token())

        assert header == {"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": provider.jwks()["keys"][0]["kid"]}
        assert claims["iss"] == "https://mcp.ipinfo.io"
        assert claims["dwk"] == "aauth-agent.json"
        assert claims["sub"] == "aauth:ipinfo-mcp@mcp.ipinfo.io"
        assert claims["exp"] - claims["iat"] == 3600
        assert claims["cnf"]["jwk"]["alg"] == "Ed25519"
        assert claims["cnf"]["jwk"] != provider.jwks()["keys"][0]

    def test_is_reused_until_close_to_expiry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = make_agent_provider(ISSUER)
        monkeypatch.setattr(agent_module.time, "time", lambda: 1800000000)
        first = provider.agent_token()

        monkeypatch.setattr(agent_module.time, "time", lambda: 1800000000 + 3600 - 301)
        assert provider.agent_token() == first

        monkeypatch.setattr(agent_module.time, "time", lambda: 1800000000 + 3600 - 299)
        refreshed = provider.agent_token()
        assert refreshed != first
        assert decode_token(provider, refreshed)[1]["iat"] == 1800000000 + 3600 - 299

    @pytest.mark.parametrize(
        "issuer",
        ["https://mcp.ipinfo.io/", "http://mcp.ipinfo.io", "https://MCP.ipinfo.io", "https://localhost:8000", ""],
    )
    def test_issuer_must_be_a_server_identifier(self, issuer: str) -> None:
        with pytest.raises(ValueError, match="AAuth issuer"):
            make_agent_provider(issuer)

    @pytest.mark.parametrize(
        "key",
        [
            pytest.param(OKPKey.generate_key("Ed25519").as_pem(private=False), id="public key"),
            pytest.param(OKPKey.generate_key("Ed448").as_pem(private=True), id="Ed448"),
            pytest.param(ECKey.generate_key("P-256").as_pem(private=True), id="P-256"),
            pytest.param(b"not a key", id="not a key"),
        ],
    )
    def test_provider_key_must_be_an_ed25519_private_key(self, key: bytes) -> None:
        with pytest.raises(ValueError, match="Ed25519 private key"):
            AgentProvider(issuer=ISSUER, provider_key=key.decode())


class TestSign:
    @pytest.mark.parametrize(
        ("url", "path"),
        [
            ("https://api.ipinfo.io/lite/8.8.8.8", "/lite/8.8.8.8"),
            ("https://api.ipinfo.io/lite/2001:4860:4860::8888", "/lite/2001:4860:4860::8888"),
            ("https://api.ipinfo.io/lite/8.8.8.8?site=api.ipinfo.io", "/lite/8.8.8.8"),
        ],
    )
    def test_signature_covers_what_is_sent(self, url: str, path: str) -> None:
        provider = make_agent_provider(ISSUER)

        request = provider.sign(httpx.Request("GET", url))

        signature_key = request.headers["signature-key"]
        signature_input = request.headers["signature-input"]
        assert signature_key.startswith('sig=jwt;jwt="')
        assert signature_input.startswith('sig=("@method" "@authority" "@path" "signature-key");created=')
        # RFC 9421 signature base, rebuilt from the request as sent
        base = "\n".join(
            [
                '"@method": GET',
                '"@authority": api.ipinfo.io',
                f'"@path": {path}',
                f'"signature-key": {signature_key}',
                f'"@signature-params": {signature_input.removeprefix("sig=")}',
            ]
        )
        signature = parse(request.headers["signature"].encode(), tltype="dictionary")["sig"][0]
        agent_jwk = decode_token(provider, provider.agent_token())[1]["cnf"]["jwk"]
        assert verify(base.encode(), signature, agent_jwk)

    def test_signs_the_host_header_sent(self) -> None:
        provider = make_agent_provider(ISSUER)

        request = provider.sign(
            httpx.Request("GET", "http://localhost:3000/lite/8.8.8.8", headers={"Host": "api.ipinfo.io"})
        )

        signature_key = request.headers["signature-key"]
        params = request.headers["signature-input"].removeprefix("sig=")
        base = (
            f'"@method": GET\n"@authority": api.ipinfo.io\n"@path": /lite/8.8.8.8\n'
            f'"signature-key": {signature_key}\n"@signature-params": {params}'
        )
        signature = base64.b64decode(request.headers["signature"].removeprefix("sig=:").removesuffix(":"))
        agent_jwk = decode_token(provider, provider.agent_token())[1]["cnf"]["jwk"]
        assert verify(base.encode(), signature, agent_jwk)

    def test_signature_covers_the_relayed_agent(self) -> None:
        provider = make_agent_provider(ISSUER)

        request = provider.sign(
            httpx.Request(
                "GET", "https://api.ipinfo.io/lite/8.8.8.8", headers={"IPinfo-Agent-Token": "caller.agent.token"}
            )
        )

        signature_key = request.headers["signature-key"]
        params = request.headers["signature-input"].removeprefix("sig=")
        assert params.startswith('("@method" "@authority" "@path" "signature-key" "ipinfo-agent-token")')
        base = "\n".join(
            [
                '"@method": GET',
                '"@authority": api.ipinfo.io',
                '"@path": /lite/8.8.8.8',
                f'"signature-key": {signature_key}',
                '"ipinfo-agent-token": caller.agent.token',
                f'"@signature-params": {params}',
            ]
        )
        signature = parse(request.headers["signature"].encode(), tltype="dictionary")["sig"][0]
        agent_jwk = decode_token(provider, provider.agent_token())[1]["cnf"]["jwk"]
        assert verify(base.encode(), signature, agent_jwk)

    def test_sends_no_token(self) -> None:
        provider = make_agent_provider(ISSUER)

        request = provider.sign(httpx.Request("GET", "https://api.ipinfo.io/lite/8.8.8.8"))

        assert "authorization" not in request.headers
        assert "token" not in request.url.params
