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
from ipinfo_mcp.types import GeoObject
from ipinfo_mcp.validation import validate_ips

logger = logging.getLogger(__name__)


class GeoInfo(TypedDict):
    ip: str
    country: str
    country_code: str
    continent: str
    continent_code: str
    city: NotRequired[str]
    region: NotRequired[str]
    region_code: NotRequired[str]
    latitude: NotRequired[float]
    longitude: NotRequired[float]
    timezone: NotRequired[str]
    postal_code: NotRequired[str]


class GeoMeta(TypedDict):
    api_calls_made: int
    from_cache: int


class GeoResult(TypedDict):
    _pagination: PaginationMeta
    _meta: GeoMeta
    results: dict[str, GeoInfo]
    validation_errors: NotRequired[dict[str, str]]


async def ipinfo_geolocate(
    ips: list[str],
    detailed: bool = False,
    page: int = 1,
    page_size: int = 25,
    ctx: Context | None = None,
) -> GeoResult | ErrorResponse:
    """
    Get geographic location data for one or more IP addresses.

    By default uses the free lite API which returns country and continent.
    Set detailed=True to use the paid lookup API which adds city, region,
    coordinates, timezone, and postal code.

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

    logger.info("ipinfo_geolocate ips=%d detailed=%s has_token=%s", len(ips), detailed, token is not None)

    if not token:
        return no_token_error()

    namespace = "lookup" if detailed else "lite"

    valid_ips, validation_errors = validate_ips(ips)

    page_ips, pagination = paginate_ips(valid_ips, page, page_size)

    cached, misses = cache.get_many(token, namespace, page_ips)

    api_calls = 0
    if misses:
        keys = [f"{namespace}/{ip}" for ip in misses]
        try:
            fetched = await client.batch(keys, token=token)
            api_calls = 1
            for key, data in fetched.items():
                ip = key.split("/", 1)[1]
                cache.put(token, namespace, ip, data)
                cached[ip] = data
        except httpx.HTTPStatusError as exc:
            logger.warning("ipinfo_geolocate api_error status=%d", exc.response.status_code)
            return handle_api_error(exc, feature_name="geolocation")

    from_cache = len(page_ips) - len(misses)

    results: dict[str, GeoInfo] = {}
    for ip in page_ips:
        if ip not in cached:
            continue
        data = cached[ip]
        if detailed:
            geo = cast(GeoObject, data.get("geo", {}))
            results[ip] = GeoInfo(
                ip=ip,
                country=geo.get("country", ""),
                country_code=geo.get("country_code", ""),
                continent=geo.get("continent", ""),
                continent_code=geo.get("continent_code", ""),
                city=geo.get("city", ""),
                region=geo.get("region", ""),
                region_code=geo.get("region_code", ""),
                latitude=geo.get("latitude", 0.0),
                longitude=geo.get("longitude", 0.0),
                timezone=geo.get("timezone", ""),
                postal_code=geo.get("postal_code", ""),
            )
        else:
            results[ip] = GeoInfo(
                ip=ip,
                country=str(data.get("country", "")),
                country_code=str(data.get("country_code", "")),
                continent=str(data.get("continent", "")),
                continent_code=str(data.get("continent_code", "")),
            )

    output: GeoResult = {
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


def register_geolocate(mcp: FastMCP) -> None:
    """Register the ipinfo_geolocate tool with the MCP server."""
    _ = mcp.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )(ipinfo_geolocate)
