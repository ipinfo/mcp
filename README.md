## IPinfo MCP Server

IPinfo API MCP Server for Residential Proxy, Lite, Core, and Plus bundles.

## Development

### Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

### Setup

```bash
uv sync --dev
cp .env.example .env
# Add your IPinfo token to .env
```

Get a free API token at [ipinfo.io/signup](https://ipinfo.io/signup).

### Running the server

The server supports two transports: stdio (default) and HTTP.

```bash
# stdio (default, used by MCP clients)
uv run ipinfo-mcp-server

# HTTP
IPINFO_TRANSPORT=http IPINFO_HOST=0.0.0.0 IPINFO_PORT=8000 uv run ipinfo-mcp-server
```

### Environment variables

| Variable              | Default                 | Description                           |
| --------------------- | ----------------------- | ------------------------------------- |
| `IPINFO_TOKEN`        |                         | API token                             |
| `IPINFO_API_BASE_URL` | `https://api.ipinfo.io` | Base URL for `api.ipinfo.io` endpoints |
| `IPINFO_LEGACY_BASE_URL` | `https://ipinfo.io`  | Base URL for legacy `ipinfo.io` endpoints (e.g. `/me`) |
| `IPINFO_CACHE_TTL`    | `3600`                  | Seconds a cached IP result stays fresh |
| `IPINFO_TRANSPORT`    | `stdio`                 | Transport type (`stdio` or `http`)    |
| `IPINFO_HOST`         | `0.0.0.0`               | HTTP host (only for `http` transport) |
| `IPINFO_PORT`         | `8000`                  | HTTP port (only for `http` transport) |

### Tests

```bash
# All tests tests
uv run pytest

# Integration tests (requires IPINFO_TOKEN)
uv run pytest tests/integration/
```

Integration tests hit the real IPinfo API and validate response structure only (no exact value assertions). They require `IPINFO_TOKEN` to be set and are skipped otherwise.

### Type checking

```bash
uv run pyright
```

### Linting

```bash
uv run ruff check .
uv run ruff format .
```
