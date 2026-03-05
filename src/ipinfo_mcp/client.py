import httpx


class IPinfoClient:
    """Async HTTP client for the IPinfo API."""

    def __init__(self, base_url: str, token: str | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "IPinfoClient":
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._http:
            await self._http.aclose()

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError(
                "Client not initialized. Use 'async with' context manager."
            )
        return self._http

    async def lookup(self, ip: str | None = None) -> dict:
        """Look up a single IP via the Lite endpoint.

        If ip is None, looks up the caller's own IP.
        """
        path = "/lite/me" if ip is None else f"/lite/{ip}"
        response = await self.http.get(path)
        response.raise_for_status()
        return response.json()

    async def batch_lookup(self, ips: list[str]) -> dict[str, dict]:
        """Batch lookup of multiple IPs."""
        response = await self.http.post("/batch", json=ips)
        response.raise_for_status()
        return response.json()

    async def summarize(self, ips: list[str]) -> dict:
        """Summarize a set of IPs by country, continent, and ASN."""
        response = await self.http.post("/tools/summarize-ips", json=ips)
        response.raise_for_status()
        return response.json()

    async def create_map(self, ips: list[str]) -> dict:
        """Create an interactive map for a set of IPs."""
        response = await self.http.post("/tools/map", json=ips)
        response.raise_for_status()
        return response.json()
