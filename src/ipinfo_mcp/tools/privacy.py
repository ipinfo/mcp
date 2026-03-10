from typing import NotRequired, TypedDict, cast

import httpx
from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.errors import ErrorResponse, handle_api_error, no_token_error
from ipinfo_mcp.pagination import PaginationMeta, paginate_ips
from ipinfo_mcp.types import AnonymousObject
from ipinfo_mcp.validation import validate_ips


class PrivacyInfo(TypedDict):
    ip: str
    is_anonymous: bool
    anonymous: AnonymousObject
    is_anycast: bool
    is_hosting: bool
    is_mobile: bool
    is_satellite: bool


class PrivacyMeta(TypedDict):
    api_calls_made: int
    from_cache: int


class PrivacyResult(TypedDict):
    _pagination: PaginationMeta
    _meta: PrivacyMeta
    results: dict[str, PrivacyInfo]
    validation_errors: NotRequired[dict[str, str]]


async def ipinfo_check_privacy(
    ips: list[str],
    page: int = 1,
    page_size: int = 25,
    ctx: Context | None = None,
) -> PrivacyResult | ErrorResponse:
    """
    Check privacy/anonymity status of IP addresses.

    Args:
        ips: List of IP addresses to check.
        page: Page number (minimum 1).
        page_size: Results per page (1–1000).
        ctx: FastMCP context with client and cache.
    """
    assert ctx is not None
    client: IPinfoClient = ctx.lifespan_context["client"]
    cache: IPCache = ctx.lifespan_context["cache"]

    if not client.has_token:
        return no_token_error()

    namespace = "lookup"

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
            return handle_api_error(exc, feature_name="privacy detection")

    from_cache = len(page_ips) - len(misses)

    # Extract privacy fields from lookup data
    results: dict[str, PrivacyInfo] = {}
    for ip in page_ips:
        if ip not in cached:
            continue
        data = cached[ip]
        results[ip] = PrivacyInfo(
            ip=ip,
            is_anonymous=bool(data.get("is_anonymous", False)),
            anonymous=cast(
                AnonymousObject,
                data.get(
                    "anonymous",
                    AnonymousObject(
                        is_proxy=False,
                        is_relay=False,
                        is_tor=False,
                        is_vpn=False,
                    ),
                ),
            ),
            is_anycast=bool(data.get("is_anycast", False)),
            is_hosting=bool(data.get("is_hosting", False)),
            is_mobile=bool(data.get("is_mobile", False)),
            is_satellite=bool(data.get("is_satellite", False)),
        )

    output: PrivacyResult = {
        "_pagination": pagination,
        "_meta": {
            "api_calls_made": api_calls,
            "from_cache": from_cache,
        },
        "results": results,
    }

    if validation_errors:
        output["validation_errors"] = validation_errors

    return output


def register_privacy(mcp: FastMCP) -> None:
    """Register the ipinfo_check_privacy tool with the MCP server."""
    _ = mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )(ipinfo_check_privacy)
