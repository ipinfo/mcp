import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network

BOGON_NETWORKS: list[IPv4Network | IPv6Network] = [
    ip_network("0.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("172.16.0.0/12"),
    ip_network("192.0.0.0/24"),
    ip_network("192.0.2.0/24"),
    ip_network("192.168.0.0/16"),
    ip_network("198.18.0.0/15"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
    ip_network("224.0.0.0/4"),
    ip_network("240.0.0.0/4"),
    ip_network("255.255.255.255/32"),
    ip_network("::/128"),
    ip_network("::1/128"),
    ip_network("::ffff:0:0/96"),
    ip_network("::/96"),
    ip_network("100::/64"),
    ip_network("2001:10::/28"),
    ip_network("2001:db8::/32"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
    ip_network("fec0::/10"),
    ip_network("ff00::/8"),
    ip_network("2002::/24"),
    ip_network("2002:a00::/24"),
    ip_network("2002:7f00::/24"),
    ip_network("2002:a9fe::/32"),
    ip_network("2002:ac10::/28"),
    ip_network("2002:c000::/40"),
    ip_network("2002:c000:200::/40"),
    ip_network("2002:c0a8::/32"),
    ip_network("2002:c612::/31"),
    ip_network("2002:c633:6400::/40"),
    ip_network("2002:cb00:7100::/40"),
    ip_network("2002:e000::/20"),
    ip_network("2002:f000::/20"),
    ip_network("2002:ffff:ffff::/48"),
    ip_network("2001::/40"),
    ip_network("2001:0:a00::/40"),
    ip_network("2001:0:7f00::/40"),
    ip_network("2001:0:a9fe::/48"),
    ip_network("2001:0:ac10::/44"),
    ip_network("2001:0:c000::/56"),
    ip_network("2001:0:c000:200::/56"),
    ip_network("2001:0:c0a8::/48"),
    ip_network("2001:0:c612::/47"),
    ip_network("2001:0:c633:6400::/56"),
    ip_network("2001:0:cb00:7100::/56"),
    ip_network("2001:0:e000::/36"),
    ip_network("2001:0:f000::/36"),
    ip_network("2001:0:ffff:ffff::/64"),
]


def _is_bogon(addr: IPv4Address | IPv6Address) -> bool:
    """Check if an IP address is in a known bogon range."""
    return any(addr in network for network in BOGON_NETWORKS)


def validate_ip(ip_str: str) -> str:
    """
    Validate and normalize an IP address string.

    Returns the normalized IP string.
    Raises ValueError with a clear message if invalid.
    """
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        raise ValueError(
            f"'{ip_str}' is not a valid IP address. "
            "Provide a valid IPv4 (e.g., 8.8.8.8) or IPv6 (e.g., 2001:4860:4860::8888) address."
        )

    if addr.is_private:
        raise ValueError(
            f"'{addr}' is a private IP address. Only public IP addresses can be looked up."
        )
    if addr.is_loopback:
        raise ValueError(
            f"'{addr}' is a loopback address. Only public IP addresses can be looked up."
        )
    if addr.is_reserved:
        raise ValueError(
            f"'{addr}' is a reserved address. Only public IP addresses can be looked up."
        )
    if addr.is_multicast:
        raise ValueError(
            f"'{addr}' is a multicast address. Only public IP addresses can be looked up."
        )
    if _is_bogon(addr):
        raise ValueError(
            f"'{addr}' is a bogon address. Only public IP addresses can be looked up."
        )

    return str(addr)


def validate_ips(ips: list[str]) -> tuple[list[str], dict[str, str]]:
    """
    Validate IPs, separating valid from invalid.

    Returns (valid_ips, {invalid_ip: error_message}).
    """
    valid: list[str] = []
    errors: dict[str, str] = {}
    for ip in ips:
        try:
            valid.append(validate_ip(ip))
        except ValueError as exc:
            errors[ip.strip()] = str(exc)
    return valid, errors
