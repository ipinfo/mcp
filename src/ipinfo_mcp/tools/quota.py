import logging

import httpx
from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from ipinfo_mcp.auth import get_request_token
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.errors import ErrorResponse, handle_api_error, no_token_error
from ipinfo_mcp.types import MeResponse

logger = logging.getLogger(__name__)


async def ipinfo_quota(
    ctx: Context | None = None,
) -> MeResponse | ErrorResponse:
    """
    Check your IPinfo API usage and remaining quota.

    Returns daily and monthly request counts, the plan limit,
    and how many requests remain.
    """
    assert ctx is not None
    client: IPinfoClient = ctx.lifespan_context["client"]
    token = get_request_token(ctx)

    logger.info("ipinfo_quota has_token=%s", token is not None)

    if not token:
        return no_token_error()

    try:
        return await client.me(token=token)
    except httpx.HTTPStatusError as exc:
        logger.warning("ipinfo_quota api_error status=%d", exc.response.status_code)
        return handle_api_error(exc, feature_name="quota")


def register_quota(mcp: FastMCP) -> None:
    """Register the ipinfo_quota tool with the MCP server."""
    _ = mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )(ipinfo_quota)
