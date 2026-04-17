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
from ipinfo_mcp.types import ASObject
from ipinfo_mcp.validation import validate_ips

logger = logging.getLogger(__name__)


class AsnInfo(TypedDict):
    ip: str
    asn: str
    name: str
    domain: str
    type: NotRequired[str]
    last_changed: NotRequired[str]


class AsnMeta(TypedDict):
    api_calls_made: int
    from_cache: int


class AsnResult(TypedDict):
    _pagination: PaginationMeta
    _meta: AsnMeta
    results: dict[str, AsnInfo]
    validation_errors: NotRequired[dict[str, str]]


async def ipinfo_asn(
    ips: list[str],
    detailed: bool = False,
    page: int = 1,
    page_size: int = 25,
    ctx: Context | None = None,
) -> AsnResult | ErrorResponse:
    """
    Get autonomous system (network ownership) information for IP addresses.

    By default uses the free lite API which returns ASN, name, and domain.
    Set detailed=True to use the paid lookup API which also includes the network type
    (e.g. isp, hosting, business, education).

    Results are paginated.

    Results are cached in memory for the session, so repeat lookups of the same IP
    are served from cache without consuming API quota. You do not need to maintain
    your own cache or deduplicate IPs before calling this tool. The _meta field
    reports api_calls_made and from_cache counts.
    """
    assert ctx is not None
    client: IPinfoClient = ctx.lifespan_context["client"]
    cache: IPCache = ctx.lifespan_context["cache"]
    token = get_request_token(ctx)

    logger.info("ipinfo_asn ips=%d detailed=%s has_token=%s", len(ips), detailed, token is not None)

    if not token:
        return no_token_error()

    namespace = "lookup" if detailed else "lite"

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
            logger.warning("ipinfo_asn api_error status=%d", exc.response.status_code)
            return handle_api_error(exc, feature_name="ASN lookup")

    from_cache = len(page_ips) - len(misses)

    results: dict[str, AsnInfo] = {}
    for ip in page_ips:
        if ip not in cached:
            continue
        data = cached[ip]
        if detailed:
            as_obj = cast(ASObject, data.get("as", {}))
            results[ip] = AsnInfo(
                ip=ip,
                asn=as_obj.get("asn", ""),
                name=as_obj.get("name", ""),
                domain=as_obj.get("domain", ""),
                type=as_obj.get("type", ""),
                last_changed=as_obj.get("last_changed", ""),
            )
        else:
            results[ip] = AsnInfo(
                ip=ip,
                asn=str(data.get("asn", "")),
                name=str(data.get("as_name", "")),
                domain=str(data.get("as_domain", "")),
            )

    output: AsnResult = {
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


def register_asn(mcp: FastMCP) -> None:
    """Register the ipinfo_asn tool with the MCP server."""
    _ = mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )(ipinfo_asn)
