from typing import NotRequired, TypedDict

import httpx
from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from ipinfo_mcp.cache import CachedResponse, IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.errors import ErrorResponse, handle_api_error, no_token_error
from ipinfo_mcp.pagination import PaginationMeta, paginate_ips
from ipinfo_mcp.validation import validate_ips


class LookupMeta(TypedDict):
    api_calls_made: int
    from_cache: int


class LookupResult(TypedDict):
    _pagination: PaginationMeta
    _meta: LookupMeta
    results: dict[str, CachedResponse]
    validation_errors: NotRequired[dict[str, str]]


async def ipinfo_lookup(
    ips: list[str],
    detailed: bool = False,
    page: int = 1,
    page_size: int = 25,
    ctx: Context | None = None,
) -> LookupResult | ErrorResponse:
    """
    Look up IP address information.

    Args:
        ips: List of IP addresses to look up.
        detailed: If True, use the lookup API (paid); otherwise use lite.
        page: Page number (minimum 1).
        page_size: Results per page (1–1000).
        ctx: FastMCP context with client and cache.
    """
    assert ctx is not None
    client: IPinfoClient = ctx.lifespan_context["client"]
    cache: IPCache = ctx.lifespan_context["cache"]

    if not client.has_token:
        return no_token_error()

    namespace = "lookup" if detailed else "lite"

    valid_ips, validation_errors = validate_ips(ips)

    page_ips, pagination = paginate_ips(valid_ips, page, page_size)

    # Check cache for this page's IPs only
    cached, misses = cache.get_many(namespace, page_ips)

    api_calls = 0
    if misses:
        keys = [f"{namespace}/{ip}" for ip in misses]
        try:
            fetched = await client.batch(keys)
            api_calls = 1
            for key, data in fetched.items():
                ip = key.split("/", 1)[1]
                cache.put(namespace, ip, data)
                cached[ip] = data
        except httpx.HTTPStatusError as exc:
            return handle_api_error(exc, feature_name=namespace)

    from_cache = len(page_ips) - len(misses)

    # Build results dict keyed by IP
    page_results: dict[str, CachedResponse] = {
        ip: cached[ip] for ip in page_ips if ip in cached
    }

    output: LookupResult = {
        "_pagination": pagination,
        "_meta": {
            "api_calls_made": api_calls,
            "from_cache": from_cache,
        },
        "results": page_results,
    }

    if validation_errors:
        output["validation_errors"] = validation_errors

    return output


def register_lookup(mcp: FastMCP) -> None:
    """Register the ipinfo_lookup tool with the MCP server."""
    _ = mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )(ipinfo_lookup)
