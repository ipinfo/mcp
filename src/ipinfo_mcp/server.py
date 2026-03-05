import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastmcp import FastMCP

from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.tools import register_tools

logger = logging.getLogger(__name__)


def _settings() -> dict:
    return {
        "api_token": os.environ.get("IPINFO_TOKEN"),
        "api_base_url": os.environ.get("IPINFO_API_BASE_URL", "https://api.ipinfo.io"),
    }


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Initialize and clean up the IPinfo API client."""
    settings = _settings()
    async with IPinfoClient(
        base_url=settings["api_base_url"],
        token=settings["api_token"],
    ) as client:
        logger.info(
            "IPinfo MCP server started (token=%s)",
            "configured" if settings["api_token"] else "anonymous",
        )
        yield {"client": client}
    logger.info("IPinfo MCP server stopped")


mcp = FastMCP(
    name="ipinfo",
    instructions=(
        "This server provides IP address intelligence tools powered by IPinfo. "
        "Use ipinfo_lookup to get geolocation and network details for IP addresses. "
        "Use ipinfo_summarize to analyze the geographic and network distribution of "
        "a set of IPs. Use ipinfo_map to generate a visual map of IP locations."
    ),
    lifespan=lifespan,
)

register_tools(mcp)


def main():
    transport = os.environ.get("IPINFO_TRANSPORT", "stdio")
    host = os.environ.get("IPINFO_HOST", "0.0.0.0")
    port = int(os.environ.get("IPINFO_PORT", "8000"))

    if transport == "http":
        mcp.run(transport="http", host=host, port=port)
    else:
        mcp.run()
