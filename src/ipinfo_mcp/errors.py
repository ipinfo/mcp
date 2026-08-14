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
    "ACCESS_DENIED": "Tell the user they can get access by upgrading at https://ipinfo.io/pricing",
    "RATE_LIMITED": "Tell the user they can upgrade their tier at https://ipinfo.io/pricing",
    "INVALID_TOKEN": "Tell the user to check their token at https://ipinfo.io/account/token",
    "NO_TOKEN": "The user didn't set IPINFO_TOKEN. They can get a free token at https://ipinfo.io/signup",
    "UNKNOWN": "An unforseen error happened, tell the user to report it to https://ipinfo.io/",
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

    if status == 403:
        message = (
            f"You don't have access to {feature_name}." if feature_name else "You don't have access to this feature."
        )
        return ErrorResponse(
            code="ACCESS_DENIED",
            message=message,
            suggestion="Tell the user they can get access by upgrading at https://ipinfo.io/pricing",
        )

    if status == 429:
        return ErrorResponse(
            code="RATE_LIMITED",
            message="Rate limit exceeded.",
            suggestion="Tell the user they can upgrade their tier at https://ipinfo.io/pricing",
        )

    return ErrorResponse(
        code="API_ERROR",
        message=f"IPinfo API returned status {status}.",
    )


def no_token_error() -> ErrorResponse:
    """Error response when no IPINFO_TOKEN is configured."""
    return ErrorResponse(
        code="NO_TOKEN",
        message="No API token configured.",
        suggestion="The user didn't set IPINFO_TOKEN. They can get a free token at https://ipinfo.io/signup",
    )
