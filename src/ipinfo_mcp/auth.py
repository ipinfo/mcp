import contextlib

from fastmcp import Context
from fastmcp.server.dependencies import get_http_request


def get_request_token(ctx: Context) -> str | None:
    """
    Get the API token for the current request.

    In HTTP mode: reads Bearer token from the Authorization request header.
    In stdio mode: falls back to the IPINFO_TOKEN env var stored in lifespan context.
    """
    with contextlib.suppress(RuntimeError):
        request = get_http_request()
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip() or None
        return None
    return ctx.lifespan_context.get("api_token")
