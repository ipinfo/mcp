"""IP address validation utilities."""

import ipaddress


def validate_ip(ip_str: str) -> str:
    """Validate and normalize an IP address string.

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

    return str(addr)


def validate_ips(ips: list[str], max_count: int) -> list[str]:
    """Validate a list of IPs. Returns normalized list.

    Raises ValueError if list is empty, too large, or contains invalid IPs.
    """
    if not ips:
        raise ValueError("IP list must not be empty.")
    if len(ips) > max_count:
        raise ValueError(f"Too many IPs: {len(ips)}. Maximum is {max_count}.")
    return [validate_ip(ip) for ip in ips]
