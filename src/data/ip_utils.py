"""
Utility functions for handling ip addresses
"""

import ipaddress

__all__ = ["get_ipv6", "get_ipv4"]


def get_ipv6(ip: str | bytes) -> ipaddress.IPv6Address:
    """
    Return an IPv6Address object.
    For IPv4, returns the IPv4-mapped IPv6 address (::ffff:W.X.Y.Z).
    """
    if isinstance(ip, bytes):
        if len(ip) == 16:
            return ipaddress.IPv6Address(ip)
        elif len(ip) == 4:
            return ipaddress.IPv6Address('::ffff:' + str(ipaddress.IPv4Address(ip)))
        else:
            raise ValueError("IP bytes must be length 4 or 16")
    obj = ipaddress.ip_address(ip)
    if isinstance(obj, ipaddress.IPv4Address):
        return ipaddress.IPv6Address('::ffff:' + str(obj))
    return ipaddress.IPv6Address(obj)


def get_ipv4(ip: str | bytes) -> ipaddress.IPv4Address:
    """
    Return an IPv4Address object.
    Accepts IPv4, or an IPv4-mapped IPv6 address.
    """
    if isinstance(ip, bytes):
        if len(ip) == 4:
            return ipaddress.IPv4Address(ip)
        elif len(ip) == 16:
            obj = ipaddress.IPv6Address(ip)
            if obj.ipv4_mapped:
                return obj.ipv4_mapped
            raise ValueError("IPv6 bytes are not an IPv4-mapped address.")
        else:
            raise ValueError("IP bytes must be length 4 or 16")
    obj = ipaddress.ip_address(ip)
    if isinstance(obj, ipaddress.IPv4Address):
        return obj
    if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped:
        return obj.ipv4_mapped
    raise ValueError("Not an IPv4 address or IPv4-mapped IPv6 address.")
