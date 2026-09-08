from typing import Annotated

from pydantic import Field

from ipinfo_mcp.client import MAX_BATCH_SIZE

IPsParam = Annotated[
    list[str],
    Field(
        description=(
            "Public IP addresses to query, IPv4 or IPv6, e.g. "
            '["8.8.8.8", "2001:4860:4860::8888"]. Private, loopback, reserved, multicast, '
            "and bogon addresses are rejected: they are reported under validation_errors "
            "and left out of results."
        )
    ),
]

PageParam = Annotated[
    int,
    Field(
        description=(
            "Page of the result set to return, 1-based. Values below 1 are clamped to 1, "
            "and a page past the last one returns no results."
        )
    ),
]

PageSizeParam = Annotated[
    int,
    Field(
        description=(
            "How many IPs to resolve and return per page. Clamped to a maximum of "
            f"{MAX_BATCH_SIZE}, the API batch limit. Only the IPs on the requested page "
            "are fetched, so a smaller page size consumes less quota per call."
        )
    ),
]
