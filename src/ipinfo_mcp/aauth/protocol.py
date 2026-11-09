import re
from collections.abc import Mapping, Sequence
from typing import Any, cast

from joserfc.errors import JoseError
from joserfc.jwk import ECKey, JWKRegistry, OKPKey
from joserfc.jws import JWSRegistry

# Algorithms AAuth keys may sign with, by the key type and curve each one uses.
# The polymorphic EdDSA is not one of them, AAuth only takes the fully specified Ed25519.
KEY_ALGORITHMS: dict[tuple[str, str], str] = {("OKP", "Ed25519"): "Ed25519", ("EC", "P-256"): "ES256"}

SIGNATURE_ALGORITHMS = tuple(KEY_ALGORITHMS.values())

# Components every AAuth request signature must cover
REQUIRED_COMPONENTS = ("@method", "@authority", "@path", "signature-key")

AGENT_TOKEN_TYPE = "aa-agent+jwt"

AGENT_METADATA_DOCUMENT = "aauth-agent.json"

HTTPS_PREFIX = "https://"

# Top-level domains are alphabetic (RFC 1123), which keeps IPv4 addresses out
_DOMAIN = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")

_AGENT_IDENTIFIER = re.compile(r"^aauth:[A-Za-z0-9._+-]{1,255}@([^@]+)$")


def is_server_identifier(value: object) -> bool:
    """
    Whether value is an AAuth server identifier: https and a lowercase domain, with no port, path or trailing slash.

    Identifiers are compared byte for byte, so any other spelling of the same URL is refused.
    """
    return (
        isinstance(value, str)
        and value.startswith(HTTPS_PREFIX)
        and _DOMAIN.match(value.removeprefix(HTTPS_PREFIX)) is not None
    )


def agent_domain(value: object) -> str | None:
    """
    Get the domain of an AAuth agent identifier, aauth:local@domain, or None if value is not one.
    """
    match = _AGENT_IDENTIFIER.match(value) if isinstance(value, str) else None
    if match is None or _DOMAIN.match(match[1]) is None:
        return None
    return match[1]


def algorithm_of(jwk: Mapping[str, object]) -> str | None:
    """
    Get the algorithm a public JWK signs with.

    Returns None for keys other than Ed25519 and P-256 ones, and for keys whose alg disagrees with their type.
    """
    algorithm = KEY_ALGORITHMS.get((str(jwk.get("kty")), str(jwk.get("crv"))))
    if algorithm is None or jwk.get("alg", algorithm) != algorithm:
        return None
    return algorithm


def signature_base(components: Sequence[tuple[str, str]], signature_params: str) -> str:
    """
    Build the RFC 9421 signature base, the text a request signature covers.

    components pairs each covered component with its value, in the order the signature lists them.
    signature_params is the serialized inner list of those components with the signature's parameters.
    """
    lines = [f'"{name}": {value}' for name, value in components]
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines)


def sign(message: bytes, key: OKPKey | ECKey, algorithm: str) -> bytes:
    """
    Sign message with a private key. ES256 signatures are the raw r and s values, as JWS and RFC 9421 expect.
    """
    return JWSRegistry.algorithms[algorithm].sign(message, key)


def verify(message: bytes, signature: bytes, jwk: Mapping[str, object]) -> bool:
    """
    Check that signature over message verifies with the public key jwk.

    Only Ed25519 and P-256 keys are accepted, see algorithm_of.
    """
    algorithm = algorithm_of(jwk)
    if algorithm is None:
        return False
    try:
        key = JWKRegistry.import_key(cast(dict[str, Any], dict(jwk)))
        return JWSRegistry.algorithms[algorithm].verify(message, signature, key)
    except (JoseError, ValueError, TypeError):
        return False
