import math
from typing import TypedDict


class PaginationMeta(TypedDict):
    total_results: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_previous: bool


class PaginatedResult(TypedDict):
    _pagination: PaginationMeta
    results: list[dict[str, object]]


def paginate(
    results: list[dict[str, object]], page: int, page_size: int
) -> PaginatedResult:
    """
    Apply pagination to a list of results.

    Args:
        results: Full list of result dicts.
        page: Page number (clamped to minimum 1).
        page_size: Results per page (clamped to 1–25).

    Returns:
        Dict with "_pagination" metadata and "results" slice.
    """
    page = max(1, page)
    page_size = max(1, min(25, page_size))

    total_results = len(results)
    total_pages = math.ceil(total_results / page_size) if total_results > 0 else 0

    start = (page - 1) * page_size
    end = start + page_size
    page_results = results[start:end]

    return {
        "_pagination": {
            "total_results": total_results,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        },
        "results": page_results,
    }
