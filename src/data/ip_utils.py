"""
Canonical IP helpers for BitClone.
One internal type (IPv6) everywhere; map IPv4 -> v6-mapped at edges.
"""

from __future__ import annotations

import ipaddress as _ip
from io import BytesIO

__all__ = ["normalize", "to_display", "pack16", "read_ip16", "write_ip16", "IPLike"]

IPLike = str | bytes | _ip.IPv4Address | _ip.IPv6Address


def normalize(ip: IPLike) -> _ip.IPv6Address:
    """
    Return an IPv6Address. IPv4 is mapped to ::ffff:W.X.Y.Z.
    Accepts str/bytes/IPv4Address/IPv6Address.
    - Strings may include brackets [::1] and scope IDs (e.g., fe80::1%eth0).
    """
    # Fast paths for objects
    if isinstance(ip, _ip.IPv6Address):
        return ip
    if isinstance(ip, _ip.IPv4Address):
        return _ip.IPv6Address(b"\x00" * 10 + b"\xff\xff" + ip.packed)

    # Bytes → recurse
    if isinstance(ip, (bytes, bytearray, memoryview)):
        b = bytes(ip)
        if len(b) == 16:
            return _ip.IPv6Address(b)
        if len(b) == 4:
            return normalize(_ip.IPv4Address(b))
        raise ValueError("IP bytes must be length 4 or 16")

    # Strings -> recurse
    if isinstance(ip, str):
        s = ip.strip()
        obj = _ip.ip_address(s)
        return normalize(obj)

    raise TypeError(f"Unsupported IP input type: {type(ip)}")


def to_display(ip: IPLike) -> str:
    """Human-friendly string: dotted-quad for mapped v4; compressed for native v6."""
    ip6 = normalize(ip)
    return str(ip6.ipv4_mapped) if ip6.ipv4_mapped else str(ip6)


def pack16(ip: IPLike) -> bytes:
    """16-byte network-order representation."""
    ip6 = normalize(ip)
    return ip6.packed


def read_ip16(stream: BytesIO) -> _ip.IPv6Address:
    """Read exactly 16 bytes from stream and return IPv6Address."""
    data = stream.read(16)
    if len(data) != 16:
        raise ValueError("Insufficient data for ipv6 ip address")
    return _ip.IPv6Address(data)


def write_ip16(ip: IPLike) -> bytes:
    """Symmetric writer for 16-byte IP field."""
    ip6 = normalize(ip)
    return pack16(ip6)
