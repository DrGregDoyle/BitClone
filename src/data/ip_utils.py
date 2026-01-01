"""
Utilities for working with IP address objects
"""
from ipaddress import IPv4Address, IPv6Address

V4_PREFIX = b'\x00' * 10 + b'\xff' * 2
IP_ADDRESS = [IPv4Address, IPv6Address]

__all__ = ["IP_ADDRESS", "ip_display", "ip_from_netaddr", "netaddr_bytes"]


def ip_from_netaddr(raw16: bytes) -> IP_ADDRESS:
    """Decode Bitcoin net_addr IP bytes (16 bytes) into IPv4Address or IPv6Address."""
    if len(raw16) != 16:
        raise ValueError("IP field must be exactly 16 bytes")
    if raw16.startswith(V4_PREFIX):
        return IPv4Address(raw16[12:16])  # last 4 bytes
    return IPv6Address(raw16)


def netaddr_bytes(ip: IP_ADDRESS) -> bytes:
    """Encode IPv4/IPv6 into Bitcoin net_addr 16-byte IP field."""
    if isinstance(ip, IPv4Address):
        return V4_PREFIX + ip.packed  # 12 + 4 = 16
    return ip.packed  # already 16


def ip_display(ip: IP_ADDRESS) -> str:
    """Return a human-friendly IPv4/IPv6 string (unwrap IPv4-mapped IPv6)."""
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)  # "1.2.3.4"
    return str(ip)  # "2001:db8::1" or "1.2.3.4"
