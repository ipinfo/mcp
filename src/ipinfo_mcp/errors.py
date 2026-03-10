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
            f"Your token does not have access to {feature_name}."
            if feature_name
            else "Your token does not have access to this endpoint."
        )
        return ErrorResponse(
            error=True,
            code="ACCESS_DENIED",
            message=message,
            suggestion="Upgrade at https://ipinfo.io/pricing",
        )

    if status == 429:
        return ErrorResponse(
            error=True,
            code="RATE_LIMITED",
            message="Rate limit exceeded.",
            suggestion="Upgrade at https://ipinfo.io/pricing",
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
        suggestion="Set IPINFO_TOKEN. Free token at https://ipinfo.io/signup",
    )
