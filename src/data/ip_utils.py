"""
Utilities for working with IP address objects
"""
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Union

from src.core import Serializable, get_bytes, SERIALIZED

V4_PREFIX = b'\x00' * 10 + b'\xff' * 2
IP_ADDRESS = Union[IPv4Address, IPv6Address]

__all__ = ["IP_ADDRESS", "ip_display", "ip_from_netaddr", "netaddr_bytes", "parse_ip_address", "BitIP"]


def ip_from_netaddr(raw16: bytes) -> IP_ADDRESS:
    """Decode Bitcoin net_addr IP bytes (16 bytes) into IPv4Address or IPv6Address."""
    if len(raw16) != 16:
        raise ValueError("IP field must be exactly 16 bytes")
    if raw16.startswith(V4_PREFIX):
        return IPv4Address(raw16[12:16])  # last 4 bytes
    return IPv6Address(raw16)


def parse_ip_address(ip_addr: IP_ADDRESS | str):
    """
    Convert string IP addresses to IPv4Address or IPv6Address objects.
    Pass through existing IP address objects unchanged.
    """
    if isinstance(ip_addr, (IPv4Address, IPv6Address)):
        return ip_addr

    if isinstance(ip_addr, str):
        # ip_address() automatically detects IPv4 or IPv6
        return ip_address(ip_addr)

    raise ValueError(f"Invalid IP address type: {type(ip_addr)}")


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


class BitIP(Serializable):
    """
    We have a wrapper class to handle all IP objects within BitClone
    """

    def __init__(self, ip: str | IP_ADDRESS):
        self.ip_obj = parse_ip_address(ip)

    @property
    def is_v4(self):
        return isinstance(self.ip_obj, IPv4Address)

    @property
    def ip(self) -> str:
        """
        Returns ip_display
        """
        return ip_display(self.ip_obj)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        ip_bytes = get_bytes(byte_stream)
        return cls(ip_from_netaddr(ip_bytes))

    def to_bytes(self) -> bytes:
        return netaddr_bytes(self.ip_obj)

    def to_dict(self, formatted: bool = True) -> dict:
        return {
            "ip": self.to_bytes().hex() if formatted else ip_display(self.ip_obj)
        }
