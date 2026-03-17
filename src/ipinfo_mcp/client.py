from typing import cast

import httpx

from ipinfo_mcp.types import BatchResponse, MeResponse

# Maximum number of IPs the batch endpoint accepts
MAX_BATCH_SIZE = 1000


class IPinfoClient:
    """
    Async HTTP client for the IPinfo API.

    Uses the unified /batch endpoint
    (e.g. "lite/8.8.8.8", "1.1.1.1", "resproxy/2.2.2.2").
    """

    def __init__(self, base_url: str) -> None:
        self._base_url: str = base_url.rstrip("/")
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "IPinfoClient":
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Accept": "application/json"},
            timeout=httpx.Timeout(30.0, connect=10.0),
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._http:
            await self._http.aclose()

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        return self._http

    async def batch(self, keys: list[str], *, token: str | None = None) -> BatchResponse:
        """
        Send a batch request.

        Keys can be prefixed with the endpoint type:
        - "lite/8.8.8.8" for lite lookups
        - "8.8.8.8" for full lookups
        - "resproxy/8.8.8.8" for residential proxy checks

        Response keys match input keys.
        HTTP errors (403, 429, etc.) are propagated as httpx.HTTPStatusError.
        """
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = await self.http.post("/batch", json=keys, headers=headers)
        _ = response.raise_for_status()
        result: BatchResponse = cast(BatchResponse, response.json())
        return result

    async def me(self, *, token: str | None = None) -> MeResponse:
        """
        Get account info and quota via GET /me.

        Note: /me only exists on ipinfo.io, not api.ipinfo.io,
        so this uses a direct request to ipinfo.io.
        HTTP errors are propagated as httpx.HTTPStatusError.
        """
        headers: dict[str, str] = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(
            base_url="https://ipinfo.io",
            headers=headers,
            timeout=httpx.Timeout(30.0, connect=10.0),
        ) as http:
            response = await http.get("/me")
            _ = response.raise_for_status()
            result: MeResponse = cast(MeResponse, response.json())
            return result
