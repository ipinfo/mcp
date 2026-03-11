from ipinfo_mcp.types import LiteResponse, LookupResponse, ResproxyResponse

# Any single-IP response that can be cached
CachedResponse = LiteResponse | LookupResponse | ResproxyResponse | dict[str, object]


class IPCache:
    """
    In-memory cache with namespace support.

    Namespaces: "lite", "lookup", "resproxy".
    """

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], CachedResponse] = {}

    def get(self, namespace: str, ip: str) -> CachedResponse | None:
        """Get cached data for an IP in a namespace. Returns None on miss."""
        return self._store.get((namespace, ip))

    def put(self, namespace: str, ip: str, data: CachedResponse) -> None:
        """Store data for an IP in a namespace."""
        self._store[(namespace, ip)] = data

    def get_many(self, namespace: str, ips: list[str]) -> tuple[dict[str, CachedResponse], list[str]]:
        """Look up multiple IPs. Returns (cached_results, cache_misses)."""
        cached: dict[str, CachedResponse] = {}
        misses: list[str] = []
        for ip in ips:
            data = self._store.get((namespace, ip))
            if data is not None:
                cached[ip] = data
            else:
                misses.append(ip)
        return cached, misses

    def put_many(self, namespace: str, items: dict[str, CachedResponse]) -> None:
        """Store multiple IP results in a namespace."""
        for ip, data in items.items():
            self._store[(namespace, ip)] = data
