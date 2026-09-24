## IPinfo MCP Server

The official IPinfo MCP Server lets AI assistants such as Claude answer questions about IP addresses. Ask where an IP is located, which company or network it belongs to, or whether it's a VPN, proxy, Tor exit node, or residential proxy, and the assistant looks it up with [IPinfo](https://ipinfo.io) data.

It implements the [Model Context Protocol](https://modelcontextprotocol.io) (MCP), the open standard AI assistants use to connect to external tools, so it works with any MCP-compatible client. It supports the IPinfo Lite, Core, Plus, and Residential Proxy plans.

For the full guide, see the [official documentation](https://ipinfo.io/developers/mcp-server).

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipinfo/mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/ipinfo/mcp)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14811/badge)](https://www.bestpractices.dev/projects/14811)
[![smithery badge](https://smithery.ai/badge/ipinfo/mcp-server)](https://smithery.ai/servers/ipinfo/mcp-server)

<!-- mcp-name: io.github.ipinfo/mcp -->

## Installation

All tools require an IPinfo API token. Get a free one at [ipinfo.io/signup](https://ipinfo.io/signup).

### Hosted server

Point your MCP client at `https://mcp.ipinfo.io/` (Streamable HTTP) and send your token as a bearer credential:

```
Authorization: Bearer <your-ipinfo-token>
```

### Local server (PyPI)

The server is published on PyPI as [`ipinfo-mcp-server`](https://pypi.org/project/ipinfo-mcp-server/) and runs over stdio. With [uv](https://docs.astral.sh/uv/) installed, add it to your MCP client configuration:

```json
{
  "mcpServers": {
    "ipinfo": {
      "command": "uvx",
      "args": ["ipinfo-mcp-server"],
      "env": {
        "IPINFO_TOKEN": "<your-ipinfo-token>"
      }
    }
  }
}
```

### Claude Desktop extension

Download `mcp.mcpb` from the [latest GitHub release](https://github.com/ipinfo/mcp/releases/latest) and open it with Claude Desktop. You'll be asked for your API token during installation.

### MCP Registry

The server is listed in the [MCP Registry](https://registry.modelcontextprotocol.io/) as `io.github.ipinfo/mcp`.

## Tools

| Tool                             | Description                                                       | Plan requirement                      |
| -------------------------------- | ----------------------------------------------------------------- | ------------------------------------- |
| `ipinfo_lookup`                  | Full IP data: geolocation, network, and metadata                  | Any; `detailed: true` needs Core/Plus |
| `ipinfo_geolocate`               | Geographic location                                               | Any; `detailed: true` needs Core/Plus |
| `ipinfo_asn`                     | Autonomous system (network ownership)                             | Any; `detailed: true` needs Core/Plus |
| `ipinfo_check_privacy`           | VPN, proxy, relay, Tor, hosting, anycast, mobile, satellite flags | Paid plan                             |
| `ipinfo_check_residential_proxy` | Residential proxy detection                                       | Residential Proxy access              |
| `ipinfo_quota`                   | API usage and remaining quota                                     | Any                                   |

Tools that lack access for the token's plan return an `ACCESS_DENIED` error.

### Common parameters

All tools except `ipinfo_quota` take a list of IPs and are paginated:

| Parameter   | Type       | Default  | Description                                                                                                                                  |
| ----------- | ---------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `ips`       | `string[]` | required | Public IPv4 or IPv6 addresses. Private, loopback, reserved, multicast, and bogon addresses are rejected and reported in `validation_errors`. |
| `page`      | `integer`  | `1`      | 1-based page of the result set. Values below 1 are clamped to 1.                                                                             |
| `page_size` | `integer`  | `25`     | IPs resolved per page, up to 1000. Only IPs on the requested page are fetched, so smaller pages consume less quota per call.                 |

`ipinfo_lookup`, `ipinfo_geolocate`, and `ipinfo_asn` also take:

| Parameter  | Type      | Default | Description                                                                                            |
| ---------- | --------- | ------- | ------------------------------------------------------------------------------------------------------ |
| `detailed` | `boolean` | `false` | `false` queries the Lite endpoint. `true` queries the full lookup endpoint, which returns more fields. |

### Common output

IP-based tools return:

| Field               | Description                                                                                                 |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| `results`           | Object keyed by IP with the tool-specific data below.                                                       |
| `errors`            | Object keyed by IP for IPs the API returned an error for. These IPs are left out of `results`.              |
| `validation_errors` | Object keyed by input for values that aren't valid public IPs. Only present when there are any.             |
| `_pagination`       | `total_results`, `page`, `page_size`, `total_pages`, `has_next`, `has_previous`.                            |
| `_meta`             | `api_calls_made` and `from_cache`. Results are cached in memory, so repeat lookups don't consume API quota. |

If the whole request fails (for example a missing or invalid token), the tool returns an error object instead, with `code` (`ACCESS_DENIED`, `RATE_LIMITED`, `INVALID_TOKEN`, `NO_TOKEN`, `API_ERROR`, or `UNKNOWN`), `message`, and `suggestion`.

### `ipinfo_lookup`

Returns the raw IPinfo API response for each IP.

- `detailed: false` ([Lite](https://ipinfo.io/developers/lite-api)): `ip`, `asn`, `as_name`, `as_domain`, `country`, `country_code`, `continent`, `continent_code`.
- `detailed: true` (full lookup): `ip`, `hostname`, `geo` (city, region, country, continent, coordinates, timezone, postal code), `as` (ASN, name, domain, type), `anonymous` (proxy, relay, Tor, VPN), `mobile`, and the `is_anonymous`, `is_anycast`, `is_hosting`, `is_mobile`, `is_satellite` flags. Some fields are only available on Plus.

### `ipinfo_geolocate`

Returns, per IP: `ip`, `country`, `country_code`, `continent`, `continent_code`. With `detailed: true`, also `city`, `region`, `region_code`, `latitude`, `longitude`, `timezone`, `postal_code`.

### `ipinfo_asn`

Returns, per IP: `ip`, `asn`, `name`, `domain`. With `detailed: true`, also `type` (`isp`, `hosting`, `business`, `education`) and `last_changed`.

### `ipinfo_check_privacy`

Returns, per IP: `ip`, `is_anonymous`, `anonymous` (`is_proxy`, `is_relay`, `is_tor`, `is_vpn`), `is_anycast`, `is_hosting`, `is_mobile`, `is_satellite`.

### `ipinfo_check_residential_proxy`

Returns, per IP: `ip` and `is_residential_proxy`. For residential proxies, also `service` (proxy service name), `last_seen` (date), and `percent_days_seen`.

### `ipinfo_quota`

Takes no parameters. Returns `token`, `requests` (`day`, `month`, `limit`, `remaining`), and per-feature quotas under `features`.

## Configuration

The server is configured through environment variables:

| Variable                 | Default                 | Description                                                             |
| ------------------------ | ----------------------- | ----------------------------------------------------------------------- |
| `IPINFO_TOKEN`           |                         | API token (stdio transport; over HTTP the token comes from the request) |
| `IPINFO_API_BASE_URL`    | `https://api.ipinfo.io` | Base URL for `api.ipinfo.io` endpoints                                  |
| `IPINFO_LEGACY_BASE_URL` | `https://ipinfo.io`     | Base URL for legacy `ipinfo.io` endpoints (e.g. `/me`)                  |
| `IPINFO_CACHE_TTL`       | `3600`                  | Seconds a cached IP result stays fresh                                  |
| `IPINFO_TRANSPORT`       | `stdio`                 | Transport type (`stdio` or `http`)                                      |
| `HOST`                   | `0.0.0.0`               | HTTP host (only for `http` transport)                                   |
| `PORT`                   | `8000`                  | HTTP port (only for `http` transport)                                   |

With the `http` transport, each request authenticates with its own `Authorization: Bearer <token>` header.

## Feedback

- **Bugs and feature requests:** open an issue on [GitHub Issues](https://github.com/ipinfo/mcp/issues).
- **Security vulnerabilities:** don't open a public issue; follow the [security policy](SECURITY.md).
- **Questions about your IPinfo account or plan:** contact [support@ipinfo.io](mailto:support@ipinfo.io).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and the requirements a change has to meet.

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

### Running the server

The server supports two transports: stdio (default) and HTTP.

```bash
# stdio (default, used by MCP clients)
uv run ipinfo-mcp-server

# HTTP
IPINFO_TRANSPORT=http HOST=0.0.0.0 PORT=8000 uv run ipinfo-mcp-server
```

### Tests

```bash
# All tests
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
