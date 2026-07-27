import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TypedDict, cast

import uvicorn
from fastmcp import FastMCP
from starlette.responses import HTMLResponse, JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.logging import setup_logging
from ipinfo_mcp.tools.asn import register_asn
from ipinfo_mcp.tools.geolocate import register_geolocate
from ipinfo_mcp.tools.lookup import register_lookup
from ipinfo_mcp.tools.privacy import register_privacy
from ipinfo_mcp.tools.quota import register_quota
from ipinfo_mcp.tools.resproxy import register_resproxy

logger = logging.getLogger(__name__)


class Settings(TypedDict):
    api_token: str | None
    api_base_url: str
    legacy_base_url: str


def _settings() -> Settings:
    return {
        "api_token": os.environ.get("IPINFO_TOKEN"),
        "api_base_url": os.environ.get("IPINFO_API_BASE_URL", "https://api.ipinfo.io"),
        "legacy_base_url": os.environ.get("IPINFO_LEGACY_BASE_URL", "https://ipinfo.io"),
    }


class ContextData(TypedDict):
    client: IPinfoClient
    cache: IPCache
    api_token: str | None


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[ContextData]:
    """Initialize and clean up the IPinfo API client and cache."""
    settings = _settings()
    async with IPinfoClient(
        base_url=settings["api_base_url"],
        legacy_base_url=settings["legacy_base_url"],
    ) as client:
        cache = IPCache()
        logger.info(
            "IPinfo MCP server started (token=%s)",
            "configured" if settings["api_token"] else "anonymous",
        )
        yield {"client": client, "cache": cache, "api_token": settings["api_token"]}
    logger.info("IPinfo MCP server stopped")


mcp = FastMCP(
    name="ipinfo",
    instructions=(
        "This server provides IP address intelligence tools powered by IPinfo. "
        "Use ipinfo_lookup to get geolocation and network details for IP addresses. "
        "Use ipinfo_check_privacy to check if IPs use VPNs, proxies, or Tor. "
        "Use ipinfo_check_residential_proxy to detect residential proxy usage. "
        "Use ipinfo_geolocate to get geographic location data. "
        "Use ipinfo_asn to get network ownership information. "
        "Use ipinfo_quota to check your API usage and remaining quota. "
        "This server maintains an in-memory cache of IP lookup results for the "
        "lifetime of the session, so you do not need to keep your own cache or "
        "deduplicate IPs before calling tools: repeat lookups of the same IP are "
        "served from cache and do not consume API quota. The _meta field on each "
        "response reports how many results came from cache vs. the API."
    ),
    lifespan=lifespan,
)

register_lookup(mcp)
register_privacy(mcp)
register_resproxy(mcp)
register_geolocate(mcp)
register_asn(mcp)
register_quota(mcp)

_LANDING_HTML = (Path(__file__).parent / "landing.html").read_text()


class LandingPageMiddleware:
    """Intercept browser GET / requests and serve the landing page.

    MCP clients use POST or GET with Accept: text/event-stream,
    so a plain GET with Accept: text/html is always a browser.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] == "GET":
            path = cast(str, scope["path"])
            if path in ("/.healthz/is-ready", "/.healthz/is-alive"):
                response = JSONResponse({"status": "ok"})
                await response(scope, receive, send)
                return
            if path == "/":
                headers = dict(cast(list[tuple[bytes, bytes]], scope.get("headers", [])))
                accept = headers.get(b"accept", b"").decode()
                if "text/html" in accept or "text/event-stream" not in accept:
                    response = HTMLResponse(_LANDING_HTML)
                    await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)


def create_app() -> ASGIApp:
    """Create the ASGI app: landing page on GET /, MCP on POST /."""
    mcp_app = mcp.http_app(
        path="/",
        stateless_http=True,
    )
    return LandingPageMiddleware(mcp_app)


app = create_app()


def main() -> None:
    transport = os.environ.get("IPINFO_TRANSPORT", "stdio")
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))

    # We don't want to log to stdout when running in stdio mode as that
    # would pollute the MCP output and cause communication issues with the LLM
    stream = sys.stdout if transport == "http" else sys.stderr
    setup_logging(stream=stream)

    if transport == "http":
        uvicorn.run(app, host=host, port=int(port), log_config=None)
    else:
        mcp.run()
