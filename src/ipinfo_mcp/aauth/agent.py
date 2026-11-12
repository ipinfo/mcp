import time
import uuid

import httpx
from http_sf import Token, ser
from http_sf.innerlist import ser_innerlist
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

from ipinfo_mcp.aauth.protocol import (
    AGENT_METADATA_DOCUMENT,
    AGENT_TOKEN_TYPE,
    HTTPS_PREFIX,
    is_server_identifier,
    sign,
    signature_base,
)

AGENT_LOCAL_PART = "ipinfo-mcp"

METADATA_PATH = f"/.well-known/{AGENT_METADATA_DOCUMENT}"
JWKS_PATH = "/.well-known/aauth-jwks.json"

ALGORITHM = "Ed25519"

# Agent tokens last an hour, and a fresh one is issued when less than five minutes remain.
# AAuth caps them at 24 hours, a short lifetime limits what a leaked one can do.
TOKEN_LIFETIME = 3600
TOKEN_REFRESH_MARGIN = 300

SIGNATURE_LABEL = "sig"

# Where requests to the IPinfo API relay the person this server acts for: the person token
# their agent presented. AAuth doesn't define relaying a person's identity, so this is IPinfo's
# own convention.
PERSON_TOKEN_HEADER = "ipinfo-person-token"


class AgentProvider:
    """
    This server as an AAuth agent, and as the agent provider that vouches for it.

    The IPinfo API serves Lite without an API token to agents that sign their requests.
    AAuth requires a server that calls other services as an agent to be its own agent
    provider, so this server publishes its provider metadata and keys, and issues
    itself the agent token it presents.

    Two keys are held. The provider key is long-lived, shared by every replica and
    published, it signs agent tokens. The agent key is generated when the process
    starts and never leaves it, it signs requests and is bound into the agent token.
    """

    def __init__(self, *, issuer: str, provider_key: str) -> None:
        """
        Args:
            issuer: Public URL this server is reachable at, e.g. https://mcp.ipinfo.io.
                Agent tokens name it and the API fetches the provider documents from it.
            provider_key: The provider's Ed25519 private key, PEM encoded.
        """
        if not is_server_identifier(issuer):
            raise ValueError(
                f"AAuth issuer {issuer!r} must be https and a lowercase domain, with no port, path or trailing slash"
            )
        try:
            key = OKPKey.import_key(provider_key)
        except (JoseError, ValueError) as exc:
            raise ValueError("AAuth provider key must be an Ed25519 private key, PEM encoded") from exc
        if key.curve_name != ALGORITHM or not key.is_private:
            raise ValueError("AAuth provider key must be an Ed25519 private key, PEM encoded")

        self.issuer = issuer
        self.agent = f"aauth:{AGENT_LOCAL_PART}@{issuer.removeprefix(HTTPS_PREFIX)}"
        self._provider_key = key
        # The thumbprint changes with the key, so a rotated key gets a kid of its own
        self._kid = key.thumbprint()
        self._agent_key = OKPKey.generate_key(ALGORITHM)
        self._token = ""
        self._token_expires_at = 0

    def metadata(self) -> dict[str, str]:
        """
        The agent provider metadata document, served at METADATA_PATH.
        """
        return {
            "issuer": self.issuer,
            "jwks_uri": f"{self.issuer}{JWKS_PATH}",
            "name": "IPinfo MCP Server",
            "documentation_uri": "https://github.com/ipinfo/mcp",
        }

    def jwks(self) -> dict[str, object]:
        """
        The agent provider's public keys, served at JWKS_PATH.
        """
        public_key = self._provider_key.as_dict(private=False)
        return {"keys": [{**public_key, "kid": self._kid, "alg": ALGORITHM, "use": "sig"}]}

    def agent_token(self) -> str:
        """
        Get the agent token this server presents, issuing a fresh one when the current one is about to expire.
        """
        now = int(time.time())
        if now < self._token_expires_at - TOKEN_REFRESH_MARGIN:
            return self._token

        header = {"alg": ALGORITHM, "typ": AGENT_TOKEN_TYPE, "kid": self._kid}
        claims = {
            "iss": self.issuer,
            "dwk": AGENT_METADATA_DOCUMENT,
            "sub": self.agent,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + TOKEN_LIFETIME,
            "cnf": {"jwk": {**self._agent_key.as_dict(private=False), "alg": ALGORITHM}},
        }
        # joserfc refuses Ed25519 unless asked for it by name
        self._token = jwt.encode(header, claims, self._provider_key, algorithms=[ALGORITHM])
        self._token_expires_at = now + TOKEN_LIFETIME
        return self._token

    def sign(self, request: httpx.Request) -> httpx.Request:
        """
        Sign request as this server's agent, adding the Signature-Key, Signature-Input and Signature headers.

        Pass it as a request's httpx auth: httpx calls it once the request is built, so the
        authority and path signed are exactly the ones sent, IPv6 addresses included.

        When the request relays the person this server acts for, in PERSON_TOKEN_HEADER,
        the signature covers that header too, so it can't be swapped on the way.
        """
        signature_key = ser({SIGNATURE_LABEL: (Token("jwt"), {"jwt": self.agent_token()})})
        components = [
            ("@method", request.method),
            ("@authority", request.headers["host"].lower()),
            ("@path", request.url.raw_path.split(b"?", 1)[0].decode() or "/"),
            ("signature-key", signature_key),
        ]
        if PERSON_TOKEN_HEADER in request.headers:
            components.append((PERSON_TOKEN_HEADER, request.headers[PERSON_TOKEN_HEADER].strip()))
        signature_params = ser_innerlist(([(name, {}) for name, _ in components], {"created": int(time.time())}))
        base = signature_base(components, signature_params)
        signature = sign(base.encode(), self._agent_key, ALGORITHM)

        request.headers["Signature-Key"] = signature_key
        request.headers["Signature-Input"] = f"{SIGNATURE_LABEL}={signature_params}"
        request.headers["Signature"] = ser({SIGNATURE_LABEL: (signature, {})})
        return request
