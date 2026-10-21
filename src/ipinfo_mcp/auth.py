import contextlib
from typing import cast, override

from fastmcp import Context
from fastmcp.server.auth import AccessToken, JWTVerifier, MultiAuth, RemoteAuthProvider, TokenVerifier
from fastmcp.server.dependencies import get_http_request
from joserfc import jws
from joserfc.errors import JoseError
from pydantic import AnyHttpUrl

OAUTH_SCOPE = "ipinfo:read"


def get_request_token(ctx: Context) -> str | None:
    """
    Get the API token for the current request.

    In HTTP mode: reads Bearer token from the Authorization request header.
    In stdio mode: falls back to the IPINFO_TOKEN env var stored in lifespan context.

    OAuth access tokens are returned as is too, the IPinfo API accepts them in
    place of the account's API token.
    """
    with contextlib.suppress(RuntimeError):
        request = get_http_request()
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip() or None
        return None
    return ctx.lifespan_context.get("api_token")


def is_jwt(token: str) -> bool:
    """
    Whether token is structurally a JWT. Neither signature nor claims are checked.
    """
    try:
        _ = jws.extract_compact(token.encode())
    except JoseError:
        return False
    return True


class ApiTokenVerifier(TokenVerifier):
    """
    Accept IPinfo API tokens alongside OAuth access tokens.

    API tokens are not validated here, the IPinfo API stays the authority on them.
    JWTs are always declined, so one that failed OAuth verification ends in a 401
    and the client refreshes it, instead of reaching the tools as an API token.
    """

    @override
    async def verify_token(self, token: str) -> AccessToken | None:
        if is_jwt(token):
            return None
        return AccessToken(token=token, client_id="ipinfo_api_token", scopes=[])


def create_auth(*, issuer: str, resource_url: str, jwks_uri: str | None = None) -> MultiAuth:
    """
    Create the auth provider for the HTTP transport.

    Access tokens issued by issuer are verified offline against its JWKS.
    IPinfo API tokens keep working as before.
    """
    # FastMCP advertises the resource of an app mounted at "/" with a trailing slash,
    # and the audience is compared byte for byte, so expect the same form here.
    resource = resource_url.rstrip("/") + "/"
    return MultiAuth(
        server=RemoteAuthProvider(
            token_verifier=JWTVerifier(
                jwks_uri=jwks_uri or f"{issuer.rstrip('/')}/.well-known/jwks.json",
                issuer=issuer,
                audience=resource,
                algorithm="ES256",
            ),
            # Clients compare this with the issuer in the authorization server metadata, byte for
            # byte. Building an AnyHttpUrl here would add a trailing slash, a str is kept as is.
            authorization_servers=cast(list[AnyHttpUrl], [issuer]),
            base_url=resource,
            scopes_supported=[OAUTH_SCOPE],
            resource_name="IPinfo MCP",
        ),
        verifiers=[ApiTokenVerifier()],
    )
