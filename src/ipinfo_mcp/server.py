import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

import uvicorn
from fastmcp import FastMCP
from starlette.responses import HTMLResponse, JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.tools.asn import register_asn
from ipinfo_mcp.tools.geolocate import register_geolocate
from ipinfo_mcp.tools.lookup import register_lookup
from ipinfo_mcp.tools.privacy import register_privacy
from ipinfo_mcp.tools.quota import register_quota
from ipinfo_mcp.tools.resproxy import register_resproxy

logger = logging.getLogger(__name__)


def _settings() -> dict[str, str | None]:
    return {
        "api_token": os.environ.get("IPINFO_TOKEN"),
        "api_base_url": os.environ.get("IPINFO_API_BASE_URL", "https://api.ipinfo.io"),
    }


@asynccontextmanager
async def lifespan(_: FastMCP) -> AsyncIterator[dict[str, IPinfoClient | IPCache]]:
    """Initialize and clean up the IPinfo API client and cache."""
    settings = _settings()
    async with IPinfoClient(
        base_url=settings["api_base_url"] or "https://api.ipinfo.io",
        token=settings["api_token"],
    ) as client:
        cache = IPCache()
        logger.info(
            "IPinfo MCP server started (token=%s)",
            "configured" if settings["api_token"] else "anonymous",
        )
        yield {"client": client, "cache": cache}
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
        "Use ipinfo_quota to check your API usage and remaining quota."
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
                headers = cast(dict[bytes, bytes], scope.get("headers", {}))
                accept = headers.get(b"accept", b"").decode()
                if "text/html" in accept or "text/event-stream" not in accept:
                    response = HTMLResponse(_LANDING_HTML)
                    await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)


def create_app() -> ASGIApp:
    """Create the ASGI app: landing page on GET /, MCP on POST /."""
    mcp_app = mcp.http_app(path="/")
    return LandingPageMiddleware(mcp_app)


app = create_app()


def main() -> None:
    transport = os.environ.get("IPINFO_TRANSPORT", "stdio")
    host = os.environ.get("IPINFO_HOST", "0.0.0.0")
    port = int(os.environ.get("IPINFO_PORT", "8000"))

    if transport == "http":
        uvicorn.run(app, host=host, port=int(port))
    else:
        mcp.run()
