import hashlib
import time

from ipinfo_mcp.types import LiteResponse, LookupResponse, ResproxyResponse

# Any single-IP response that can be cached
CachedResponse = LiteResponse | LookupResponse | ResproxyResponse | dict[str, object]

# How long an entry stays fresh, in seconds.
DEFAULT_TTL = 3600.0


class IPCache:
    """
    In-memory cache of per-IP responses, scoped by token and namespace.

    Namespaces: "lite", "lookup", "resproxy".

    Entries are scoped also using the token that fetched them. The cache is process
    wide, so if we don't use the token as part of the key we would hand one token's
    results to another.

    Entries expire after ttl seconds. Expiry is checked on read, and an expired
    entry is dropped as we find it, so nothing sweeps the store in the background.
    """

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self._ttl = ttl
        # Each entry is (stored_at, data), stored_at coming from a monotonic clock
        # so that a system clock change can't make an entry look fresh forever.
        self._store: dict[tuple[str, str, str], tuple[float, CachedResponse]] = {}

    @staticmethod
    def _hash_token(token: str) -> str:
        """
        We don't want to store the token directly, though we still need
        to scope by token so we derive an hash from it and use it as part
        of the hash key.
        """
        return hashlib.sha256(token.encode()).hexdigest()[:32]

    def _get_fresh(self, key: tuple[str, str, str]) -> CachedResponse | None:
        """Read an entry by key, dropping and reporting it as a miss if it expired."""
        entry = self._store.get(key)
        if entry is None:
            return None

        stored_at, data = entry
        if time.monotonic() > stored_at + self._ttl:
            del self._store[key]
            return None

        return data

    def get(self, token: str, namespace: str, ip: str) -> CachedResponse | None:
        """Get this token's cached data for an IP in a namespace. Returns None on miss."""
        return self._get_fresh((self._hash_token(token), namespace, ip))

    def put(self, token: str, namespace: str, ip: str, data: CachedResponse) -> None:
        """Store data for an IP in a namespace, scoped to this token."""
        self._store[(self._hash_token(token), namespace, ip)] = (time.monotonic(), data)

    def get_many(self, token: str, namespace: str, ips: list[str]) -> tuple[dict[str, CachedResponse], list[str]]:
        """Look up multiple IPs for this token. Returns (cached_results, cache_misses)."""
        token_hash = self._hash_token(token)
        cached: dict[str, CachedResponse] = {}
        misses: list[str] = []
        for ip in ips:
            data = self._get_fresh((token_hash, namespace, ip))
            if data is not None:
                cached[ip] = data
            else:
                misses.append(ip)
        return cached, misses

    def put_many(self, token: str, namespace: str, items: dict[str, CachedResponse]) -> None:
        """Store multiple IP results in a namespace, scoped to this token."""
        token_hash = self._hash_token(token)
        stored_at = time.monotonic()
        for ip, data in items.items():
            self._store[(token_hash, namespace, ip)] = (stored_at, data)
