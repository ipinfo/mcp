import logging
from typing import NotRequired, TypedDict, cast

import httpx
from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from ipinfo_mcp.auth import get_request_token
from ipinfo_mcp.cache import IPCache
from ipinfo_mcp.client import IPinfoClient
from ipinfo_mcp.errors import ErrorResponse, handle_api_error, no_token_error
from ipinfo_mcp.pagination import PaginationMeta, paginate_ips
from ipinfo_mcp.validation import validate_ips

logger = logging.getLogger(__name__)


class ResproxyInfo(TypedDict):
    ip: str
    is_residential_proxy: bool
    service: NotRequired[str]
    last_seen: NotRequired[str]
    percent_days_seen: NotRequired[int]


class ResproxyMeta(TypedDict):
    api_calls_made: int
    from_cache: int


class ResproxyResult(TypedDict):
    _pagination: PaginationMeta
    _meta: ResproxyMeta
    results: dict[str, ResproxyInfo]
    validation_errors: NotRequired[dict[str, str]]


async def ipinfo_check_residential_proxy(
    ips: list[str],
    page: int = 1,
    page_size: int = 25,
    ctx: Context | None = None,
) -> ResproxyResult | ErrorResponse:
    """
    Check whether IP addresses are known residential proxies.

    Returns whether each IP is a residential proxy and, if so, the proxy service name,
    the date it was last seen, and the percentage of days the IP was observed as a proxy.

    Requires a paid API token with residential proxy access. Results are paginated.

    Results are cached in memory for the session, so repeat checks of the same IP
    are served from cache without consuming API quota. You do not need to maintain
    your own cache or deduplicate IPs before calling this tool. The _meta field
    reports api_calls_made and from_cache counts.
    """
    assert ctx is not None
    client: IPinfoClient = ctx.lifespan_context["client"]
    cache: IPCache = ctx.lifespan_context["cache"]
    token = get_request_token(ctx)

    logger.info("ipinfo_check_residential_proxy ips=%d has_token=%s", len(ips), token is not None)

    if not token:
        return no_token_error()

    namespace = "resproxy"

    valid_ips, validation_errors = validate_ips(ips)

    page_ips, pagination = paginate_ips(valid_ips, page, page_size)

    cached, misses = cache.get_many(namespace, page_ips)

    api_calls = 0
    if misses:
        keys = [f"{namespace}/{ip}" for ip in misses]
        try:
            fetched = await client.batch(keys, token=token)
            api_calls = 1
            for key, data in fetched.items():
                ip = key.split("/", 1)[1]
                cache.put(namespace, ip, data)
                cached[ip] = data
        except httpx.HTTPStatusError as exc:
            logger.warning("ipinfo_check_residential_proxy api_error status=%d", exc.response.status_code)
            return handle_api_error(exc, feature_name="residential proxy detection")

    from_cache = len(page_ips) - len(misses)

    results: dict[str, ResproxyInfo] = {}
    for ip in page_ips:
        if ip not in cached:
            continue
        data = cached[ip]
        if data:
            results[ip] = ResproxyInfo(
                ip=ip,
                is_residential_proxy=True,
                service=str(data.get("service", "")),
                last_seen=str(data.get("last_seen", "")),
                percent_days_seen=cast(int, data.get("percent_days_seen", 0)),
            )
        else:
            results[ip] = ResproxyInfo(ip=ip, is_residential_proxy=False)

    output: ResproxyResult = {
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


def register_resproxy(mcp: FastMCP) -> None:
    """Register the ipinfo_check_residential_proxy tool with the MCP server."""
    _ = mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )(ipinfo_check_residential_proxy)
