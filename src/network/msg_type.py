"""
Types of Messages used in Bitcoin
"""
import io
import ipaddress
import json
from datetime import datetime

from src.data import Serializable, check_length, from_little_bytes, read_compact_size, to_little_bytes, \
    write_compact_size, bytes_to_binary_string


class Version(Serializable):
    """
    Display class for version message
    """

    def __init__(self,
                 protocol_version: int,
                 services: bytes,
                 timestamp: int,
                 remote_services: bytes,
                 remote_ip: str | ipaddress.IPv6Address | ipaddress.IPv4Address,
                 remote_port: int,
                 local_services: bytes,
                 local_ip: str | ipaddress.IPv6Address | ipaddress.IPv4Address,
                 local_port: int,
                 nonce: int,
                 user_agent: str,
                 last_block: int
                 ):
        self.protocol_version = protocol_version
        self.services = services
        self.timestamp = timestamp
        self.remote_services = remote_services
        self.remote_ip = self._get_ip(remote_ip)
        self.remote_port = remote_port
        self.local_services = local_services
        self.local_ip = self._get_ip(local_ip)
        self.local_port = local_port
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    def _get_ip(self, unknown_format_ip):
        # Accept str or ipaddress types
        if isinstance(unknown_format_ip, str):
            return ipaddress.IPv6Address(unknown_format_ip)
        elif isinstance(unknown_format_ip, (ipaddress.IPv6Address, ipaddress.IPv4Address)):
            # Converts IPv4 to IPv6-mapped, leaves IPv6 as-is
            return ipaddress.IPv6Address(unknown_format_ip)
        else:
            raise ValueError(f"Unknown format for given ip address: {unknown_format_ip}")

    @classmethod
    def from_bytes(cls, byte_stream):
        """
        Deserialize a version payload
        -----------------------------------------------------------
        | Name                |  Format                | Size     |
        -----------------------------------------------------------
        | protocol version    | little                | 4         |
        | services            | little                | 8         |
        | time                | little                | 8         |
        | remote services     | little                | 8         |
        | remote ip           | ipv6, big             | 16        |
        | remote port         | big                   | 2         |
        | local services      | little                | 8         |
        | local ip            | ipv6, big             | 16        |
        | local port          | big                   | 2         |
        | nonce               | little                | 8         |
        | user agent          | compact size, ascii   | compact   |
        | last block          | little                | 4         |
        -----------------------------------------------------------
        """
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Helpers
        def read_little_int(stream_size: int, data_type: str):
            byte_read = stream.read(stream_size)
            check_length(byte_read, stream_size, data_type)
            return from_little_bytes(byte_read)

        def read_big_int(stream_size: int, data_type: str):
            byte_read = stream.read(stream_size)
            check_length(byte_read, stream_size, data_type)
            return int.from_bytes(byte_read, "big")

        def read_little_bytes(stream_size: int, data_type: str):
            byte_read = stream.read(stream_size)
            check_length(byte_read, stream_size, data_type)
            return byte_read[::-1]  # Big-endian

        def read_ip(data_type: str):
            ip_bytes = stream.read(16)
            check_length(ip_bytes, 16, data_type)
            return ipaddress.IPv6Address(ip_bytes)

        def read_ascii(stream_size: int):
            ua_bytes = stream.read(stream_size)
            check_length(ua_bytes, stream_size, "user_agent")
            return ua_bytes.decode("ascii")

        protocol_version = read_little_int(4, "protocol_version")
        services = read_little_bytes(8, "services")
        timestamp = read_little_int(8, "unix_timestamp")
        remote_services = read_little_bytes(8, "remote_services")
        remote_ip = read_ip("remote_ip")
        remote_port = read_big_int(2, "remote_port")
        local_services = read_little_bytes(8, "local_services")
        local_ip = read_ip("local_ip")
        local_port = read_big_int(2, "local_port")
        nonce = read_little_int(8, "nonce")
        user_agent_size = read_compact_size(stream)
        user_agent = read_ascii(user_agent_size)
        last_block = read_little_int(4, "last_block")

        return cls(protocol_version, services, timestamp, remote_services, remote_ip, remote_port, local_services,
                   local_ip, local_port, nonce, user_agent, last_block)

    def to_bytes(self):
        # Helper: Ensure services are 8 bytes little-endian
        def to_8bytes_le(val):
            return val if isinstance(val, bytes) and len(val) == 8 else to_little_bytes(val, 8)

        # Protocol version
        b = to_little_bytes(self.protocol_version, 4)
        # Services
        b += to_8bytes_le(self.services)
        # Timestamp (seconds since epoch)
        b += to_little_bytes(self.timestamp, 8)
        # Remote node's services
        b += to_8bytes_le(self.remote_services)
        # Remote node's IP (16 bytes, big-endian)
        b += self.remote_ip.packed
        # Remote node's port (2 bytes, big-endian)
        b += self.remote_port.to_bytes(2, "big")
        # Local services
        b += to_8bytes_le(self.local_services)
        # Local IP (16 bytes, big-endian)
        b += self.local_ip.packed
        # Local port (2 bytes, big-endian)
        b += self.local_port.to_bytes(2, "big")
        # Nonce (8 bytes, little-endian)
        b += to_little_bytes(self.nonce, 8)
        # User agent: CompactSize-prefixed
        user_agent_bytes = self.user_agent.encode("ascii")
        b += write_compact_size(len(user_agent_bytes)) + user_agent_bytes
        # Last block seen (4 bytes, little-endian)
        b += to_little_bytes(self.last_block, 4)
        return b

    def to_dict(self):
        def ip_display(ipv6):
            # If it's IPv4-mapped, return the IPv4 string, else the IPv6 string
            if ipv6.ipv4_mapped:
                return str(ipv6.ipv4_mapped)
            else:
                return str(ipv6)

        version_dict = {
            "protocol_version": self.protocol_version,
            "services": bytes_to_binary_string(self.services),
            "time": datetime.fromtimestamp(self.timestamp).isoformat(),
            "remote_services": bytes_to_binary_string(self.remote_services),
            "remote_ip": ip_display(self.remote_ip),
            "remote_port": self.remote_port,
            "local_services": bytes_to_binary_string(self.local_services),
            "local_ip": ip_display(self.local_ip),
            "local_port": self.local_port,
            "nonce": self.nonce,
            "user_agent": self.user_agent,
            "last_block": self.last_block
        }
        return version_dict

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING
if __name__ == "__main__":
    test_version_bytes = bytes.fromhex(
        "80110100090c00000000000047564b6800000000000000000000000000000000000000000000ffffc654ed0ad049090c00000000000000000000000000000000000000000000000018e1ff1e44c4dd0c102f5361746f7368693a32382e302e302f7bbf0d0001")
    test_version_obj = Version.from_bytes(test_version_bytes)
    print(f"TEST VERSION: {test_version_obj.to_json()}")
