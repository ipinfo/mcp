import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import NotRequired, TypedDict, cast

import httpx
from fastmcp import Context, FastMCP
from fastmcp.server.dependencies import get_http_request
from http_sf import parse
from mcp.types import ToolAnnotations

from ipinfo_mcp.aauth.agent import PERSON_TOKEN_HEADER, AgentProvider
from ipinfo_mcp.aauth.resource import Person, scope_person
from ipinfo_mcp.cache import CachedResponse, IPCache
from ipinfo_mcp.client import USER_AGENT
from ipinfo_mcp.errors import ErrorResponse, extract_error, handle_api_error
from ipinfo_mcp.pagination import PaginationMeta, paginate_ips
from ipinfo_mcp.params import IPsParam, PageParam, PageSizeParam
from ipinfo_mcp.types import LiteResponse
from ipinfo_mcp.validation import validate_ips

logger = logging.getLogger(__name__)

# How many Lite requests run at once per tool call
MAX_CONCURRENT_REQUESTS = 10

# Lite data is the same whoever asks for it, so everyone shares the cached results
CACHE_OWNER = "aauth"


class LiteClient:
    """
    Async HTTP client for the IPinfo Lite endpoint, signing every request as this server's AAuth agent.

    The API serves Lite without a token to agents that sign their requests, on /lite only:
    /batch still needs a token, so each IP is a request of its own.
    """

    def __init__(self, base_url: str, agent: AgentProvider) -> None:
        """
        Args:
            base_url: Base URL of the api.ipinfo.io endpoints.
            agent: This server's AAuth agent, which requests are signed as.
        """
        self._base_url = base_url.rstrip("/")
        self._agent = agent
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "LiteClient":
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            auth=self._agent.sign,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._http:
            await self._http.aclose()

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        return self._http

    async def lookup(self, ips: list[str], *, person_token: str | None = None) -> dict[str, LiteResponse]:
        """
        Look up IPs on the Lite endpoint. Returns each IP's response, keyed by the IP.

        person_token is the person token of the person the lookups are for, relayed in PERSON_TOKEN_HEADER.

        HTTP errors (401, 429, etc.) are propagated as httpx.HTTPStatusError, the first one that happens.
        """
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        headers = {PERSON_TOKEN_HEADER: person_token} if person_token else None

        async def fetch(ip: str) -> LiteResponse:
            async with semaphore:
                response = await self.http.get(f"/lite/{ip}", headers=headers)
            if response.status_code == 401:
                # The API names what it refused, in our signature or in the person token we relayed
                logger.warning("GET /lite refused signature_error=%s", response.headers.get("signature-error"))
            _ = response.raise_for_status()
            return cast(LiteResponse, response.json())

        logger.info("GET /lite ips=%d", len(ips))
        try:
            async with asyncio.TaskGroup() as group:
                tasks = {ip: group.create_task(fetch(ip)) for ip in ips}
        except ExceptionGroup as exc:
            # The first failure cancels the other requests, report it on its own
            raise exc.exceptions[0] from None
        return {ip: task.result() for ip, task in tasks.items()}


def get_request_person() -> Person | None:
    """
    Get the person the current request was made for, or None outside of an HTTP request.
    """
    with contextlib.suppress(RuntimeError):
        return scope_person(get_http_request().scope)
    return None


def _refuses_person_token(response: httpx.Response) -> bool:
    """
    Whether a 401 from the API refuses the person token we relayed, rather than our own signature.
    """
    try:
        error = parse(response.headers.get("signature-error", "").encode("latin-1"), tltype="dictionary")
    except ValueError:
        return False
    return "relayed" in cast(dict[str, object], error)


def handle_lite_error(exc: httpx.HTTPStatusError) -> ErrorResponse:
    """
    Convert an HTTP error the Lite endpoint answered with into a user-friendly error response dict.
    """
    status = exc.response.status_code

    if status == 429:
        return ErrorResponse(
            code="RATE_LIMITED",
            message="Rate limit exceeded.",
            suggestion=(
                "The user has reached their daily limit of lookups without an IPinfo account, try again tomorrow. "
                "The user can get a free token at https://ipinfo.io/signup"
            ),
        )

    if status == 401 and _refuses_person_token(exc.response):
        return ErrorResponse(
            code="API_ERROR",
            message=f"The IPinfo API refused the user's person token ({exc.response.headers['signature-error']}).",
            suggestion=(
                "Try the request again. If it keeps failing, tell the user to contact IPinfo support at "
                "support@ipinfo.io"
            ),
        )

    # Any other refusal is of this server, which the user can't fix
    if status == 401:
        return ErrorResponse(
            code="API_ERROR",
            message=(
                "The IPinfo API refused this server's AAuth signature "
                f"({exc.response.headers.get('signature-error', 'no reason given')})."
            ),
            suggestion="Tell the user to contact IPinfo support at support@ipinfo.io",
        )
    if status == 403:
        return ErrorResponse(
            code="API_ERROR",
            message="The IPinfo API isn't accepting lookups without an account.",
            suggestion="Tell the user to contact IPinfo support at support@ipinfo.io",
        )

    return handle_api_error(exc, feature_name="Lite lookup")


class LiteLookupMeta(TypedDict):
    api_calls_made: int
    from_cache: int


class LiteLookupResult(TypedDict):
    _pagination: PaginationMeta
    _meta: LiteLookupMeta
    results: dict[str, CachedResponse]
    validation_errors: NotRequired[dict[str, str]]
    errors: NotRequired[dict[str, ErrorResponse]]


async def ipinfo_lite_lookup(
    ips: IPsParam,
    page: PageParam = 1,
    page_size: PageSizeParam = 25,
    ctx: Context | None = None,
) -> LiteLookupResult | ErrorResponse:
    """
    Look up the country, continent, and network (ASN) of one or more IP addresses, with IPinfo Lite.

    Works without an IPinfo account, for a person signed in with their AAuth person server.
    Lookups count against a daily limit for each person.

    Results are paginated. Use page and page_size to control which slice is returned.

    If the API reports an error for specific IPs, those IPs are listed in errors
    with the reason and left out of results.

    Results are cached in memory, so repeat lookups of the same IP are served from
    cache without counting against the limit. You do not need to maintain your own
    cache or deduplicate IPs before calling this tool. The _meta field reports
    api_calls_made and from_cache counts.
    """
    assert ctx is not None
    client: LiteClient = ctx.lifespan_context["client"]
    cache: IPCache = ctx.lifespan_context["cache"]
    person = get_request_person()

    logger.info("ipinfo_lite_lookup ips=%d person=%s", len(ips), person.identifier if person else None)

    valid_ips, validation_errors = validate_ips(ips)

    page_ips, pagination = paginate_ips(valid_ips, page, page_size)

    cached, misses = cache.get_many(CACHE_OWNER, "lite", page_ips)

    errors: dict[str, ErrorResponse] = {}
    if misses:
        try:
            fetched = await client.lookup(misses, person_token=person.token if person else None)
        except httpx.HTTPStatusError as exc:
            logger.warning("ipinfo_lite_lookup api_error status=%d", exc.response.status_code)
            return handle_lite_error(exc)
        for ip, data in fetched.items():
            if error := extract_error(data):
                errors[ip] = error
                # Errors are never cached, the next call may succeed
                continue
            cache.put(CACHE_OWNER, "lite", ip, data)
            cached[ip] = data

    output: LiteLookupResult = {
        "_pagination": pagination,
        "_meta": {
            "api_calls_made": len(misses),
            "from_cache": len(page_ips) - len(misses),
        },
        "results": {ip: cached[ip] for ip in page_ips if ip in cached},
        "errors": errors,
    }

    if validation_errors:
        output["validation_errors"] = validation_errors

    return output


class LiteContextData(TypedDict):
    client: LiteClient
    cache: IPCache


def create_lite_server(
    *,
    agent: AgentProvider,
    api_base_url: str,
    cache_ttl: float,
) -> FastMCP:
    """
    Create the MCP server AAuth agents use, in place of the main one.

    Agents have no IPinfo account, and the API serves them Lite only, so this server
    has a single tool for it. AAuthMiddleware sends it the requests agents signed with
    a person token.
    """

    @asynccontextmanager
    async def lifespan(_: FastMCP) -> AsyncIterator[LiteContextData]:
        async with LiteClient(api_base_url, agent) as client:
            logger.info("IPinfo Lite server for AAuth agents started (agent=%s)", agent.agent)
            yield {"client": client, "cache": IPCache(ttl=cache_ttl)}
        logger.info("IPinfo Lite server for AAuth agents stopped")

    server = FastMCP(
        name="ipinfo",
        instructions=(
            "This server provides IP address intelligence powered by IPinfo Lite, to people "
            "without an IPinfo account. Use ipinfo_lite_lookup to get the country, continent, "
            "and network (ASN) of IP addresses. This server maintains an in-memory cache of "
            "lookup results, so you do not need to keep your own cache or deduplicate IPs "
            "before calling it: repeat lookups of the same IP are served from cache and do "
            "not count against the daily limit. The _meta field on each response reports how "
            "many results came from cache vs. the API."
        ),
        lifespan=lifespan,
    )
    _ = server.tool(
        annotations=ToolAnnotations(
            title="IP Lite Lookup",
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        )
    )(ipinfo_lite_lookup)
    return server
