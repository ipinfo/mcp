from typing import Literal, TypedDict, cast

import httpx

from ipinfo_mcp.cache import CachedResponse

ErrorCode = Literal[
    "ACCESS_DENIED",
    "RATE_LIMITED",
    "INVALID_TOKEN",
    "NO_TOKEN",
    "API_ERROR",
    "UNKNOWN",
]


class ErrorResponse(TypedDict, total=False):
    code: ErrorCode
    message: str
    suggestion: str


# We use this mapping to try and infer an error code from the error message
# received by the REST API.
# Getting an error code makes it easier to give the model suggestions on how
# to communicate the error to the user.
_MESSAGE_ERROR_CODES_MAPPING: list[tuple[str, ErrorCode]] = [
    ("does not have access", "ACCESS_DENIED"),
    ("not allowed access from this source", "ACCESS_DENIED"),
    ("do not have permission", "ACCESS_DENIED"),
    ("reached your limit", "RATE_LIMITED"),
    ("too many requests", "RATE_LIMITED"),
    ("entered your token correctly", "INVALID_TOKEN"),
    ("unknown token", "INVALID_TOKEN"),
    ("invalid token", "INVALID_TOKEN"),
    ("token required", "NO_TOKEN"),
    ("authentication required", "NO_TOKEN"),
]

_SUGGESTIONS: dict[ErrorCode, str] = {
    "ACCESS_DENIED": (
        "The user's IPinfo plan doesn't include this data. "
        "The data each plan includes is listed at https://ipinfo.io/pricing"
    ),
    "RATE_LIMITED": (
        "The user's IPinfo plan has reached its request limit, try again later. "
        "The limits of each plan are listed at https://ipinfo.io/pricing"
    ),
    "INVALID_TOKEN": "Tell the user to check their token at https://ipinfo.io/account/token",
    "NO_TOKEN": "The user didn't set IPINFO_TOKEN. They can get a free token at https://ipinfo.io/signup",
    "UNKNOWN": "An unexpected error happened, tell the user to contact IPinfo support at support@ipinfo.io",
}


def _find_error_code(message: str) -> ErrorCode:
    for chunk, code in _MESSAGE_ERROR_CODES_MAPPING:
        if chunk in message:
            return code
    return "UNKNOWN"


def extract_error(entry: CachedResponse) -> ErrorResponse | None:
    """
    Pull the error message out of a single batch endpoint response.

    Return None if no error is found.

    The batch endpoint embeds each sub-request's response body verbatim. Nearly all
    of them carry a flat "error" string, but the generic error handler and the
    invalid-response guard reply with a bare "message" instead, so fall back to it.
    """
    payload = cast(dict[str, str], entry)
    message = payload.get("error") or payload.get("message")
    if not message:
        return None
    error_code = _find_error_code(message)
    return ErrorResponse(
        code=error_code,
        message=message,
        suggestion=_SUGGESTIONS[error_code],
    )


def handle_api_error(
    exc: httpx.HTTPStatusError,
    *,
    feature_name: str = "",
) -> ErrorResponse:
    """
    Convert an HTTP error into a user-friendly error response dict.

    Args:
        exc: The HTTP status error from httpx.
        feature_name: Human-readable name of the feature that failed.
    """
    status = exc.response.status_code

    # Only OAuth access tokens get a 401, e.g. when the user revoked access after the
    # token was issued. The API answers unknown API tokens with a 403.
    if status == 401:
        return ErrorResponse(
            code="INVALID_TOKEN",
            message="The IPinfo API rejected the access token.",
            suggestion="Tell the user to reconnect IPinfo in their MCP client to authorize access again",
        )

    if status == 403:
        message = (
            f"You don't have access to {feature_name}." if feature_name else "You don't have access to this feature."
        )
        return ErrorResponse(
            code="ACCESS_DENIED",
            message=message,
            suggestion=_SUGGESTIONS["ACCESS_DENIED"],
        )

    if status == 429:
        return ErrorResponse(
            code="RATE_LIMITED",
            message="Rate limit exceeded.",
            suggestion=_SUGGESTIONS["RATE_LIMITED"],
        )

    return ErrorResponse(
        code="API_ERROR",
        message=f"IPinfo API returned status {status}.",
        suggestion=(
            "The IPinfo API is having a temporary problem, try the request again in a moment"
            if status >= 500
            else _SUGGESTIONS["UNKNOWN"]
        ),
    )


def no_token_error() -> ErrorResponse:
    """Error response when no IPINFO_TOKEN is configured."""
    return ErrorResponse(
        code="NO_TOKEN",
        message="No API token configured.",
        suggestion="The user didn't set IPINFO_TOKEN. They can get a free token at https://ipinfo.io/signup",
    )
