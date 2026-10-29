# IPinfo plugin

Connects your AI assistant to the hosted [IPinfo MCP Server](https://github.com/ipinfo/mcp), so it can answer questions about IP addresses with [IPinfo](https://ipinfo.io) data: where an IP is located, which company or network it belongs to, and whether it's a VPN, proxy, Tor exit node, or residential proxy.

## Setup

Install the plugin, then sign in with your IPinfo account when your client asks. There is nothing else to configure: the plugin connects to `https://mcp.ipinfo.io/` and authenticates through OAuth.

You need an IPinfo account. Sign up for free at [ipinfo.io/signup](https://ipinfo.io/signup).

## Tools

| Tool                             | Description                                                       | Plan requirement                      |
| -------------------------------- | ----------------------------------------------------------------- | ------------------------------------- |
| `ipinfo_lookup`                  | Full IP data: geolocation, network, and metadata                  | Any; `detailed: true` needs Core/Plus |
| `ipinfo_geolocate`               | Geographic location                                               | Any; `detailed: true` needs Core/Plus |
| `ipinfo_asn`                     | Autonomous system (network ownership)                             | Any; `detailed: true` needs Core/Plus |
| `ipinfo_check_privacy`           | VPN, proxy, relay, Tor, hosting, anycast, mobile, satellite flags | Paid plan                             |
| `ipinfo_check_residential_proxy` | Residential proxy detection                                       | Residential Proxy access              |
| `ipinfo_quota`                   | API usage and remaining quota                                     | Any                                   |

All tools are read-only. Try asking:

- "Where is the IP address 8.8.8.8 located?"
- "Is 185.220.101.1 a VPN, proxy, or Tor exit node?"
- "Which company operates the network for 1.1.1.1?"

## Support

- Documentation: [ipinfo.io/developers/mcp-server](https://ipinfo.io/developers/mcp-server)
- Support: [support.ipinfo.io](https://support.ipinfo.io/hc/en-us) or support@ipinfo.io
- Privacy policy: [ipinfo.io/privacy-policy](https://ipinfo.io/privacy-policy)

## Packaging

This folder is both an [Agent Plugins](https://agent-plugins.org) package and a Cursor plugin:

- `plugin.json` and `mcp.json` are the portable package. OpenAI-specific listing and review details live under `extensions.com.openai` in `plugin.json`.
- `.cursor-plugin/plugin.json` adds the Cursor listing details, such as the logo. The repository's `.cursor-plugin/marketplace.json` points Cursor at this folder.

To build the ZIP for the OpenAI plugin portal, run this from the `plugins` directory. It leaves out the Cursor manifest:

```bash
zip -r -X ipinfo-plugin.zip ipinfo -x '*.DS_Store' 'ipinfo/.cursor-plugin/*'
```

Bump `version` in both manifests before every new upload.
