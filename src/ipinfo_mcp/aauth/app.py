import json
import logging
import os
from typing import cast
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ipinfo_mcp.aauth.agent import JWKS_PATH, METADATA_PATH, AgentProvider
from ipinfo_mcp.aauth.lite import create_lite_server
from ipinfo_mcp.aauth.resource import (
    AGENT_SCOPE_KEY,
    RESOURCE_METADATA_PATH,
    SIGNATURE_HEADERS,
    AgentVerifier,
    SignatureError,
    agent_token_required_response,
    resource_metadata,
    signature_error_response,
)

logger = logging.getLogger(__name__)

# Where this server's resource metadata sends AAuth agents to call the Lite lookup
AGENT_ENDPOINT_PATH = "/aauth"

# JSON-RPC methods answered on AGENT_ENDPOINT_PATH without a signature: enough to list the tools
DISCOVERY_METHODS = ("initialize", "notifications/initialized", "tools/list", "ping")


async def _buffer_body(receive: Receive) -> tuple[bytes, Receive]:
    """
    Read a request's whole body. Returns it with a receive that hands it to the app again.
    """
    chunks: list[bytes] = []
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(cast(bytes, message.get("body", b"")))
        more_body = cast(bool, message.get("more_body", False))
    body = b"".join(chunks)

    replayed = False

    async def replay() -> Message:
        nonlocal replayed
        if replayed:
            return await receive()
        replayed = True
        return {"type": "http.request", "body": body, "more_body": False}

    return body, replay


def _is_discovery(body: bytes) -> bool:
    """
    Whether a JSON-RPC request body only sets up a session or lists the tools.
    """
    try:
        message = json.loads(body)
    except ValueError:
        return False
    messages = message if isinstance(message, list) else [message]
    return bool(messages) and all(
        isinstance(item, dict) and cast(dict[str, object], item).get("method") in DISCOVERY_METHODS
        for item in cast(list[object], messages)
    )


class AAuthMiddleware:
    """
    Let AAuth agents use the server without an IPinfo account, through the endpoint this
    server's resource metadata points them at.

    Requests to AGENT_ENDPOINT_PATH go to agent_app, the MCP server agents get, which has
    only the Lite lookup and demands no bearer token. Agents such as the AAuth Connector
    list an MCP server's tools before signing anything, so a request there may set up a
    session or list the tools unsigned. Anything else needs a signature: a refused one is
    answered with a 401 naming why, a verified one reaches agent_app with its agent in
    the ASGI scope. Every other request reaches app untouched.

    Also serves this server's agent provider documents, which the IPinfo API fetches
    to verify the requests this server signs as agent, and its resource metadata.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        agent: AgentProvider,
        agent_app: Starlette,
        verifier: AgentVerifier,
        origin: str,
    ) -> None:
        """
        Args:
            origin: Scheme and host, and port if any, agents reach this server at. Its
                resource metadata names it as issuer, as agents require.
        """
        self.app = app
        self.agent_app = agent_app
        self.verifier = verifier
        self.documents = {
            METADATA_PATH: agent.metadata(),
            JWKS_PATH: agent.jwks(),
            RESOURCE_METADATA_PATH: resource_metadata(origin, f"{origin}{AGENT_ENDPOINT_PATH}"),
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            # agent_app starts and stops along with app
            async with self.agent_app.router.lifespan_context(self.agent_app):
                await self.app(scope, receive, send)
            return

        if scope["type"] == "http" and scope["method"] == "GET" and scope["path"] in self.documents:
            await JSONResponse(self.documents[scope["path"]])(scope, receive, send)
            return

        if scope["type"] != "http" or scope["path"] != AGENT_ENDPOINT_PATH:
            await self.app(scope, receive, send)
            return

        body, receive = await _buffer_body(receive)
        # agent_app serves its MCP endpoint at /
        agent_scope = {**scope, "path": "/", "raw_path": b"/"}
        if any(name in Headers(scope=scope) for name in SIGNATURE_HEADERS):
            try:
                # Verified against the path the agent signed
                agent = await self.verifier.verify(scope, body)
            except SignatureError as exc:
                logger.info("aauth request refused error=%s", exc.code)
                await signature_error_response(exc.code)(scope, receive, send)
                return
            await self.agent_app({**agent_scope, AGENT_SCOPE_KEY: agent}, receive, send)
        elif _is_discovery(body):
            await self.agent_app(agent_scope, receive, send)
        else:
            await agent_token_required_response()(scope, receive, send)


def agent_from_env() -> AgentProvider | None:
    """
    Create this server's AAuth agent from the environment, or None when AAuth is not configured.

    IPINFO_AAUTH_PROVIDER_KEY is the Ed25519 private key, PEM encoded, this server signs its
    agent tokens with. IPINFO_AAUTH_ISSUER is the public URL it publishes its provider
    documents at, required with the key.
    """
    provider_key = os.environ.get("IPINFO_AAUTH_PROVIDER_KEY")
    if not provider_key:
        return None
    issuer = os.environ.get("IPINFO_AAUTH_ISSUER")
    if not issuer:
        raise RuntimeError("IPINFO_AAUTH_ISSUER must be set when IPINFO_AAUTH_PROVIDER_KEY is")
    return AgentProvider(issuer=issuer, provider_key=provider_key)


def with_aauth(app: ASGIApp, *, api_base_url: str, cache_ttl: float) -> ASGIApp:
    """
    Let AAuth agents use IPinfo Lite without an account, when AAuth is configured. Returns app as is otherwise.

    Agents that sign their requests get a server of their own with only the Lite lookup,
    every other request reaches app as before. See agent_from_env for the configuration.
    When IPINFO_MCP_RESOURCE_URL names this server's public URL, only signatures made for
    it are accepted, and the resource metadata names it, otherwise the agent's issuer.

    Args:
        app: The MCP app everyone else uses.
        api_base_url: Base URL of the api.ipinfo.io endpoints, which Lite lookups go to.
        cache_ttl: How long Lite results stay cached, in seconds.
    """
    agent = agent_from_env()
    if agent is None:
        return app

    lite_server = create_lite_server(agent=agent, api_base_url=api_base_url, cache_ttl=cache_ttl)
    resource_url = os.environ.get("IPINFO_MCP_RESOURCE_URL")
    public_url = urlsplit(resource_url) if resource_url else None
    authority = public_url.netloc.lower() if public_url else None
    return AAuthMiddleware(
        app,
        agent=agent,
        agent_app=lite_server.http_app(path="/", stateless_http=True),
        verifier=AgentVerifier(authority=authority),
        origin=f"{public_url.scheme}://{authority}" if public_url else agent.issuer,
    )
