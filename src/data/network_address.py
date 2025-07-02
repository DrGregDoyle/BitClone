"""
The NetAddr class for the network address data structure

"""
import ipaddress as IP
import json
from datetime import datetime
from io import BytesIO
from time import time as now

from src.data.byte_stream import get_stream, read_little_int, read_stream, read_big_int

__all__ = ["NetAddr"]


class NetAddr:
    """
    -----------------------------------------------------------------
    |   Name            | Data type | Formatted             | Size  |
    -----------------------------------------------------------------
    |   time            | int       | little-endian         | 4     |
    |   Services        | bytes     | little-endian         | 8     |
    |   ip address      | ipv6      | network byte order    | 16    |
    |   port            | int       | network byte order    | 2     |
    -----------------------------------------------------------------
    """
    IPV6_BYTES = bytes.fromhex("00000000000000000000ffff")
    TIME_BYTES = 4
    SERVICES_BYTES = 8
    IP_BYTES = 16
    PORT_BYTES = 2
    TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(self, timestamp: int, services: bytes, ip_addr: str, port: int, is_version: bool = False):
        self.timestamp = timestamp
        self.services = services
        self.ip_address = self._get_ipv6(ip_addr)
        self.port = port
        self.is_version = is_version

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, is_version=False):
        # Get stream
        stream = get_stream(byte_stream)

        # Check version message
        if not is_version:
            timestamp = read_little_int(stream, cls.TIME_BYTES, "time")
        else:
            timestamp = int(now())

        # Get the rest
        services = read_stream(stream, cls.SERVICES_BYTES, "services")
        ip_bytes = read_stream(stream, cls.IP_BYTES, "ip")
        ip_address = IP.IPv6Address(ip_bytes)
        port = read_big_int(stream, 2, "port")

        return cls(timestamp, services, str(ip_address), port, is_version)

    @property
    def display_ip(self) -> str:
        return str(self.ip_address.ipv4_mapped) if self.ip_address.ipv4_mapped else str(self.ip_address)

    @property
    def display_time(self) -> str:
        return datetime.utcfromtimestamp(self.timestamp).strftime(self.TIME_FORMAT)

    def to_bytes(self, is_version=False):
        # Add time if not version Address
        payload = self.timestamp.to_bytes(self.TIME_BYTES, "little") if not is_version else b''
        payload += self.services + self.ip_address.packed + self.port.to_bytes(self.PORT_BYTES, "big")
        return payload

    def _get_ipv6(self, ip_addr: str):
        temp_ip = IP.ip_address(ip_addr)
        if isinstance(temp_ip, IP.IPv4Address):
            return IP.IPv6Address(self.IPV6_BYTES + temp_ip.packed)
        elif isinstance(temp_ip, IP.IPv6Address):
            return temp_ip
        else:
            raise ValueError(f"Given ip address not in IPv4/IPv6 format: {ip_addr}")

    def to_dict(self):
        if not self.is_version:
            net_addr_dict = {"time": self.display_time}
        else:
            net_addr_dict = {}
        net_addr_dict.update({
            "services": self.services.hex(),
            "ip_address": self.display_ip,
            "port": self.port
        })
        return net_addr_dict

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# TESTING
if __name__ == "__main__":
    version_addr1 = bytes.fromhex("010000000000000000000000000000000000FFFF0A000001208D")
    version_addr2 = bytes.fromhex("010000000000000000000000000000000000FFFF0A000002208D")

    test_addr1 = NetAddr.from_bytes(version_addr1, is_version=True)
    test_addr2 = NetAddr.from_bytes(version_addr2, is_version=True)
    print(f"TEST ADDR1: {test_addr1.to_json()}")
    print("===" * 80)
    print(f"TEST ADDR2: {test_addr2.to_json()}")
