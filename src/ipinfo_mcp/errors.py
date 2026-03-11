from typing import TypedDict

import httpx


class ErrorResponse(TypedDict, total=False):
    error: bool
    code: str
    message: str
    suggestion: str


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
            error=True,
            code="ACCESS_DENIED",
            message=message,
            suggestion="Tell the user they can get access by upgrading at https://ipinfo.io/pricing",
        )

    if status == 429:
        return ErrorResponse(
            error=True,
            code="RATE_LIMITED",
            message="Rate limit exceeded.",
            suggestion="Tell the user they can upgrade their tier at https://ipinfo.io/pricing",
        )

    return ErrorResponse(
        error=True,
        code="API_ERROR",
        message=f"IPinfo API returned status {status}.",
    )


def no_token_error() -> ErrorResponse:
    """Error response when no IPINFO_TOKEN is configured."""
    return ErrorResponse(
        error=True,
        code="NO_TOKEN",
        message="No API token configured.",
        suggestion="The user didn't set IPINFO_TOKEN. They can get a free token at https://ipinfo.io/signup",
    )
