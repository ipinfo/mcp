import base64
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

from fastmcp.server.auth.ssrf import SSRFError, SSRFFetchError, ssrf_safe_fetch
from http_sf import Token, parse, ser
from http_sf.innerlist import ser_innerlist
from http_sf.types import DictionaryType, InnerListType
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import Scope

from ipinfo_mcp.aauth.protocol import (
    AGENT_TOKEN_TYPE,
    PERSON_METADATA_DOCUMENT,
    PERSON_TOKEN_TYPE,
    REQUIRED_COMPONENTS,
    SIGNATURE_ALGORITHMS,
    algorithm_of,
    is_server_identifier,
    signature_base,
    verify,
)

logger = logging.getLogger(__name__)

# How far a signature's created time, or a token's iat, may lie from now, in seconds
SIGNATURE_WINDOW = 60

# AAuth caps person tokens at an hour
PERSON_TOKEN_MAX_LIFETIME = 3600

# Person server keys are kept for 10 minutes. A token naming a key they lack makes
# them refetched early, but AAuth forbids fetching them more than once a minute.
KEYS_MAX_AGE = 600
KEYS_REFRESH_AGE = 60

# Person server documents are small, and fetching one holds up the request that needs it
FETCH_TIMEOUT = 3.0
MAX_DOCUMENT_SIZE = 64 * 1024

SIGNATURE_HEADERS = ("signature", "signature-input", "signature-key")

# Derived components a signature may cover, anything else starting with @ can't be checked
DERIVED_COMPONENTS = ("@method", "@authority", "@path", "@query")

# Content-Digest algorithms a request body is checked with (RFC 9530), by their hashlib names
DIGEST_ALGORITHMS = {"sha-256": "sha256", "sha-512": "sha512"}

PERSON_SCOPE_KEY = "ipinfo_mcp.aauth_person"

RESOURCE_METADATA_PATH = "/.well-known/aauth-resource.json"

# The R3 vocabulary through which agents call an MCP server's tools
MCP_VOCABULARY = "urn:aauth:vocabulary:mcp"

# The AAuth-Requirement value asking for a request signed with a person token
PERSON_TOKEN_REQUIREMENT = "requirement=person-token"

# Structured field values as http_sf parses them: a bare value with its parameters
_Member = tuple[object, dict[str, object]]


class SignatureError(Exception):
    """
    A refused AAuth request. code is the Signature-Error code it is answered with.
    """

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PersonTokenRequiredError(Exception):
    """
    An AAuth request signed with an agent token, where a person token is needed.
    """


@dataclass(frozen=True)
class Person:
    """
    A person an AAuth agent's signed request verified as made for.
    """

    # Their identifier at the person server, which names them to this server only
    identifier: str
    # The person server that vouches for them
    issuer: str
    # The person token the agent presented
    token: str


@dataclass(frozen=True)
class SignedRequest:
    components: list[str]
    created: int
    expires: int | None
    signature_params: str
    signature: bytes
    jwt: str


@dataclass(frozen=True)
class PersonToken:
    person: str
    issuer: str
    audience: str
    kid: str
    alg: str
    jwk: dict[str, object]
    signing_input: bytes
    signature: bytes


def _parse_dictionary(value: str | None) -> dict[str, _Member] | None:
    if value is None:
        return None
    try:
        return cast(dict[str, _Member], parse(value.encode("latin-1"), tltype="dictionary"))
    except ValueError:
        return None


def _is_computable(item: _Member) -> bool:
    name, params = item
    return (
        isinstance(name, str)
        and name == name.lower()
        and not params
        and (name in DERIVED_COMPONENTS or not name.startswith("@"))
    )


def parse_signed_request(headers: Headers) -> SignedRequest:
    """
    Read the signature and the token presented with it from an AAuth request's headers, and check
    the signature covers the required components.

    Raises SignatureError when the signature is refused.
    """
    inputs = _parse_dictionary(headers.get("signature-input"))
    signatures = _parse_dictionary(headers.get("signature"))
    keys = _parse_dictionary(headers.get("signature-key"))
    if inputs is None or signatures is None or keys is None:
        raise SignatureError("invalid_signature")
    # The signature to check is the first one all three headers carry
    label = next((key for key in keys if key in inputs and key in signatures), None)
    if label is None:
        raise SignatureError("invalid_signature")

    scheme, key_params = keys[label]
    if isinstance(scheme, Token) and str(scheme) != "jwt":
        raise SignatureError("unsupported_scheme")

    items, params = inputs[label]
    signature, _ = signatures[label]
    jwt = key_params.get("jwt")
    created = params.get("created")
    expires = params.get("expires")
    if (
        not isinstance(scheme, Token)
        or not isinstance(jwt, str)
        or not isinstance(items, list)
        or not isinstance(signature, bytes)
        # bool is an int too, a structured field boolean isn't a time
        or type(created) is not int
        or (expires is not None and type(expires) is not int)
    ):
        raise SignatureError("invalid_signature")

    members = cast(list[_Member], items)
    components = [cast(str, name) for name, _ in members]
    if not all(_is_computable(item) for item in members) or not all(name in components for name in REQUIRED_COMPONENTS):
        raise SignatureError("invalid_input")

    return SignedRequest(
        components=components,
        created=created,
        expires=cast(int | None, expires),
        signature_params=ser_innerlist(cast(InnerListType, (items, params))),
        signature=signature,
        jwt=jwt,
    )


def check_signature_timing(signed: SignedRequest, now: int) -> None:
    """
    Check a signature was created recently and has not expired. Raises SignatureError when it falls outside the window.
    """
    if signed.created > now + SIGNATURE_WINDOW:
        raise SignatureError("clock_skew")
    if signed.created < now - SIGNATURE_WINDOW or (signed.expires is not None and signed.expires < now):
        raise SignatureError("invalid_signature")


def _decode_part(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _decode_json_part(part: str) -> dict[str, object] | None:
    try:
        value = json.loads(_decode_part(part))
    except ValueError:
        return None
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_agent_token(jwt: str) -> bool:
    """
    Whether jwt says it is an agent token. Nothing about it is verified.
    """
    header = _decode_json_part(jwt.split(".", 1)[0])
    return header is not None and header.get("typ") == AGENT_TOKEN_TYPE


def _has_person_claims(claims: dict[str, object]) -> bool:
    cnf = claims.get("cnf")
    jwk = cast(dict[str, object], cnf).get("jwk") if isinstance(cnf, dict) else None
    subject = claims.get("sub")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    return (
        is_server_identifier(claims.get("iss"))
        and claims.get("dwk") == PERSON_METADATA_DOCUMENT
        and isinstance(claims.get("jti"), str)
        and _is_number(issued_at)
        and _is_number(expires_at)
        and isinstance(jwk, dict)
        and isinstance(cast(dict[str, object], jwk).get("alg"), str)
        and isinstance(subject, str)
        and subject != ""
        and isinstance(claims.get("aud"), str)
        and cast(float, expires_at) - cast(float, issued_at) <= PERSON_TOKEN_MAX_LIFETIME
        # A person token carries identity only, never authorization
        and "scope" not in claims
        and "account" not in claims
    )


def parse_person_token(jwt: str, now: int) -> PersonToken:
    """
    Decode a person token and check its header and claims, but not the person server's signature.

    Returns the person with what is needed to verify that signature. Raises SignatureError
    when the token is refused.
    """
    parts = jwt.split(".")
    header = _decode_json_part(parts[0]) if len(parts) == 3 else None
    claims = _decode_json_part(parts[1]) if header is not None else None
    if (
        header is None
        or claims is None
        or header.get("typ") != PERSON_TOKEN_TYPE
        or not isinstance(header.get("kid"), str)
    ):
        raise SignatureError("invalid_jwt")

    if header.get("alg") not in SIGNATURE_ALGORITHMS:
        raise SignatureError("unsupported_algorithm")

    if "iss" not in claims:
        raise SignatureError("issuer_missing")

    if not _has_person_claims(claims):
        raise SignatureError("invalid_jwt")

    if cast(float, claims["exp"]) <= now:
        raise SignatureError("expired_jwt")

    if cast(float, claims["iat"]) > now + SIGNATURE_WINDOW:
        raise SignatureError("clock_skew")

    jwk = cast(dict[str, object], cast(dict[str, object], claims["cnf"])["jwk"])
    if jwk["alg"] not in SIGNATURE_ALGORITHMS:
        raise SignatureError("unsupported_algorithm")

    if algorithm_of(jwk) is None:
        raise SignatureError("invalid_key")

    try:
        signature = _decode_part(parts[2])
    except ValueError as exc:
        raise SignatureError("invalid_jwt") from exc

    return PersonToken(
        person=cast(str, claims["sub"]),
        issuer=cast(str, claims["iss"]),
        audience=cast(str, claims["aud"]),
        kid=cast(str, header["kid"]),
        alg=cast(str, header["alg"]),
        jwk=jwk,
        signing_input=f"{parts[0]}.{parts[1]}".encode(),
        signature=signature,
    )


def component_value(scope: Scope, headers: Headers, name: str) -> str | None:
    """
    Get the value a covered component has in the request as received, None when the request lacks it.
    """
    match name:
        case "@method":
            return cast(str, scope["method"])
        case "@authority":
            host = headers.get("host")
            return host.lower() if host else None
        case "@path":
            raw_path = cast(bytes | None, scope.get("raw_path")) or cast(str, scope["path"]).encode()
            return raw_path.split(b"?", 1)[0].decode("latin-1") or "/"
        case "@query":
            return "?" + cast(bytes, scope.get("query_string", b"")).decode("latin-1")
        case _:
            values = headers.getlist(name)
            return ", ".join(value.strip() for value in values) if values else None


def check_content_digest(headers: Headers, body: bytes) -> None:
    """
    Check the Content-Digest header matches body. Raises SignatureError when it doesn't, or has no digest we know.
    """
    digests = _parse_dictionary(headers.get("content-digest")) or {}
    checked = False
    for algorithm, (digest, _) in digests.items():
        hash_name = DIGEST_ALGORITHMS.get(algorithm)
        if hash_name is None:
            continue
        if not isinstance(digest, bytes) or not hmac.compare_digest(digest, hashlib.new(hash_name, body).digest()):
            raise SignatureError("invalid_signature")
        checked = True
    if not checked:
        raise SignatureError("invalid_signature")


async def _fetch_document(url: str) -> dict[str, object]:
    """
    Fetch a JSON object from a public https URL, refusing redirects and addresses outside the public internet.
    """
    document = json.loads(
        await ssrf_safe_fetch(url, max_size=MAX_DOCUMENT_SIZE, timeout=FETCH_TIMEOUT, overall_timeout=FETCH_TIMEOUT)
    )
    if not isinstance(document, dict):
        raise ValueError(f"{url} is not a JSON object")
    return cast(dict[str, object], document)


async def _fetch_person_server_keys(issuer: str) -> dict[str, object] | SignatureError:
    """
    Fetch a person server's keys, through its metadata document. Returns the error refusing them when they can't be.
    """
    try:
        metadata = await _fetch_document(f"{issuer}/.well-known/{PERSON_METADATA_DOCUMENT}")
        if "issuer" not in metadata:
            return SignatureError("issuer_missing")
        if metadata["issuer"] != issuer:
            return SignatureError("issuer_mismatch")
        jwks_uri = metadata.get("jwks_uri")
        if not isinstance(jwks_uri, str) or urlsplit(jwks_uri).scheme != "https":
            return SignatureError("unknown_key")
        return await _fetch_document(jwks_uri)
    except (SSRFError, SSRFFetchError, ValueError) as exc:
        logger.warning("aauth person server keys unreachable issuer=%s error=%s", issuer, exc)
        return SignatureError("unknown_key")


def _token_key_error(token: PersonToken, keys: dict[str, object] | SignatureError) -> str | None:
    """
    Check the person server signed token with one of keys. Returns the Signature-Error code refusing it, or None.
    """
    if isinstance(keys, SignatureError):
        return keys.code
    candidates = keys.get("keys")
    key = None
    if isinstance(candidates, list):
        key = next(
            (
                cast(dict[str, object], candidate)
                for candidate in cast(list[object], candidates)
                if isinstance(candidate, dict) and cast(dict[str, object], candidate).get("kid") == token.kid
            ),
            None,
        )
    if key is None or key.get("alg") != token.alg:
        return "unknown_key"
    return None if verify(token.signing_input, token.signature, key) else "invalid_jwt"


class PersonVerifier:
    """
    Verify requests AAuth agents sign with a person token: the request signature, the
    person token, that it binds the key the request was signed with, and the person
    server's signature on it.
    """

    def __init__(self, *, audience: str, person_servers: Sequence[str], authority: str | None = None) -> None:
        """
        Args:
            audience: This server's resource identifier, which person tokens must be issued for.
            person_servers: Person servers whose person tokens are accepted.
            authority: Host, and port if any, this server is reached at. When set, a request
                that names any other is refused, so a signature made for another service
                can't be replayed here.
        """
        self._audience = audience
        self._person_servers = frozenset(person_servers)
        self._authority = authority.lower() if authority else None
        # Each person server's keys, or the error fetching them ended in, with when they were
        # fetched. Only allowed person servers are fetched, so this stays small.
        self._person_server_keys: dict[str, tuple[float, dict[str, object] | SignatureError]] = {}

    async def verify(self, scope: Scope, body: bytes, now: int | None = None) -> Person:
        """
        Verify an AAuth request. Returns the person it is made for.

        Raises PersonTokenRequiredError when it is signed with an agent token, and SignatureError when it is refused.

        Args:
            scope: The request's ASGI scope.
            body: The request's body, checked against Content-Digest when the signature covers it.
            now: Current Unix time in seconds.
        """
        now = int(time.time()) if now is None else now
        headers = Headers(scope=scope)

        signed = parse_signed_request(headers)
        if _is_agent_token(signed.jwt):
            raise PersonTokenRequiredError()
        check_signature_timing(signed, now)
        token = parse_person_token(signed.jwt, now)

        if token.issuer not in self._person_servers or token.audience != self._audience:
            raise SignatureError("invalid_jwt")

        if self._authority is not None and component_value(scope, headers, "@authority") != self._authority:
            raise SignatureError("invalid_signature")

        components: list[tuple[str, str]] = []
        for name in signed.components:
            value = component_value(scope, headers, name)
            if value is None:
                raise SignatureError("invalid_signature")
            components.append((name, value))
        base = signature_base(components, signed.signature_params)
        # Verifying with the key the token binds is what ties the token to the agent presenting it
        if not verify(base.encode(), signed.signature, token.jwk):
            raise SignatureError("invalid_signature")

        if "content-digest" in signed.components:
            check_content_digest(headers, body)

        await self._verify_token_signature(token)
        return Person(identifier=token.person, issuer=token.issuer, token=signed.jwt)

    async def _keys(self, issuer: str, *, refresh: bool = False) -> dict[str, object] | SignatureError:
        max_age = KEYS_REFRESH_AGE if refresh else KEYS_MAX_AGE
        cached = self._person_server_keys.get(issuer)
        if cached is not None and time.monotonic() - cached[0] < max_age:
            return cached[1]

        keys = await _fetch_person_server_keys(issuer)
        self._person_server_keys[issuer] = (time.monotonic(), keys)
        return keys

    async def _verify_token_signature(self, token: PersonToken) -> None:
        error = _token_key_error(token, await self._keys(token.issuer))
        if error is not None:
            # The person server may have rotated its key since we fetched its keys
            error = _token_key_error(token, await self._keys(token.issuer, refresh=True))
        if error is not None:
            raise SignatureError(error)


def scope_person(scope: Scope) -> Person | None:
    """
    Get the person AAuthMiddleware verified the request in scope as made for, or None.
    """
    person = scope.get(PERSON_SCOPE_KEY)
    return person if isinstance(person, Person) else None


def resource_metadata(issuer: str, mcp_endpoint: str) -> dict[str, object]:
    """
    This server's AAuth resource metadata, served at RESOURCE_METADATA_PATH.

    Agents that read it, such as the AAuth Connector, find the MCP server at mcp_endpoint.
    They call its tools with a person token issued for issuer, which they get from their
    person server.
    """
    return {
        "issuer": issuer,
        "name": "IPinfo",
        "description": "IP address geolocation and network (ASN) data from IPinfo Lite, without an IPinfo account",
        "access_mode": "person-token",
        "r3_vocabularies": {MCP_VOCABULARY: mcp_endpoint},
    }


def person_token_required_response() -> JSONResponse:
    """
    Answer a request that needs a person token and carries none: a 401 whose AAuth-Requirement asks for one.
    """
    return JSONResponse(
        {"error": "This request must be signed by an AAuth agent presenting a person token"},
        status_code=401,
        headers={"AAuth-Requirement": PERSON_TOKEN_REQUIREMENT},
    )


def signature_error_response(code: str) -> JSONResponse:
    """
    Answer a refused AAuth request: a 401 whose Signature-Error header names why.
    """
    error: DictionaryType = {"error": (Token(code), {})}
    if code == "invalid_input":
        error["required_input"] = ([(name, {}) for name in REQUIRED_COMPONENTS], {})
    headers = {"Signature-Error": ser(error)}
    if code == "unsupported_scheme":
        headers["Accept-Signature-Scheme"] = "jwt"
    if code == "unsupported_algorithm":
        headers["Accept-Signature-Alg"] = ser([(Token(alg), {}) for alg in SIGNATURE_ALGORITHMS])
    return JSONResponse({"error": code}, status_code=401, headers=headers)
