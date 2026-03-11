import math
from typing import TypedDict

from ipinfo_mcp.client import MAX_BATCH_SIZE


class PaginationMeta(TypedDict):
    total_results: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_previous: bool


def paginate_ips(ips: list[str], page: int, page_size: int) -> tuple[list[str], PaginationMeta]:
    """
    Slice a list of IPs for the requested page and build pagination metadata.

    Args:
        ips: Full list of validated IPs.
        page: Page number (clamped to minimum 1).
        page_size: Results per page (clamped to 1–MAX_BATCH_SIZE).

    Returns:
        Tuple of (page_ips, pagination_meta).
    """
    page = max(1, page)
    page_size = max(1, min(MAX_BATCH_SIZE, page_size))
    total_results = len(ips)
    total_pages = math.ceil(total_results / page_size) if total_results > 0 else 0

    start = (page - 1) * page_size
    end = start + page_size
    page_ips = ips[start:end]

    meta: PaginationMeta = {
        "total_results": total_results,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_previous": page > 1,
    }
    return page_ips, meta
