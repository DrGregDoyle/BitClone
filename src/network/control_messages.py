"""
Control Messages:
    -Addr
    -Alert
    -FeeFilter
    -FilterClear
    -FilerLoad
    -GetAddr
    -Reject
    -SendHeaders
"""
from datetime import datetime
from io import BytesIO

from src.data import get_stream, read_little_int, read_stream, read_ip, read_big_int, read_compact_size, get_ipv6, \
    write_compact_size, MAINNET
from src.network.messages import ControlMessage


class Version(ControlMessage):
    """
    -----------------------------------------------------------------
    |   Name            | Data type | Formatted         | Size      |
    -----------------------------------------------------------------
    |   (Protocol) version  | int   | little-endian     | 4         |
    |   Services            | bytes | little-endian     | 8         |
    |   Time                | int   | little-endian     | 8         |
    |   Remote services     | bytes | little-endian     | 8         |
    |   Remote ip           | str   | ipv6, big-endian  | 16        |
    |   Remote port         | int   | big-endian        | 2         |
    |   Local services      | bytes | little-endian     | 8         |
    |   Local ip            | str   | ipv6, big-endian  | 16        |
    |   Local port          | int   | big-endian        | 2         |
    |   nonce               | int   | little-endian     | 8         |
    |   user agent size     | *     | compact_size      | varint    |
    |   user agent          | str   | ascii bytes       | varint    |
    |   last block          | int   | little-endian     | 4         |
    -----------------------------------------------------------------
    """
    # --- BYTE SIZES
    PORT_BYTES = 2
    VERSION_BYTES = LAST_BLOCK_BYTES = 4
    SERVICE_BYTES = TIME_BYTES = NONCE_BYTES = 8
    IP_BYTES = 16

    def __init__(self, version: int, services: bytes, timestamp: int, r_services: bytes, r_ip: str, r_port: int,
                 l_services: bytes, l_ip: str, l_port: int, nonce: int, user_agent: str, last_block: int,
                 magic_bytes: bytes = MAINNET):
        # Magic Bytes
        super().__init__(magic_bytes)
        self.magic_bytes = magic_bytes

        # Raw Data
        self.protocol_version = version
        self.services = services
        self.timestamp = timestamp
        self.remote_services = r_services
        self.remote_ip = r_ip
        self.remote_port = r_port
        self.local_services = l_services
        self.local_ip = l_ip
        self.local_port = l_port
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Setup stream
        stream = get_stream(byte_stream)

        # Read in data
        version = read_little_int(stream, cls.VERSION_BYTES, "protocol_version")
        services = read_stream(stream, cls.SERVICE_BYTES, "services")
        timestamp = read_little_int(stream, cls.TIME_BYTES, "time")
        r_services = read_stream(stream, cls.SERVICE_BYTES, "remote_services")
        r_ip = read_ip(stream, cls.IP_BYTES, "remote_ip")
        r_port = read_big_int(stream, cls.PORT_BYTES, "remote_port")
        l_services = read_stream(stream, cls.SERVICE_BYTES, "local_services")
        l_ip = read_ip(stream, cls.IP_BYTES, "local_ip")
        l_port = read_big_int(stream, cls.PORT_BYTES, "local_port")
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        user_agent_size = read_compact_size(stream, "user_agent_size")
        user_agent = read_stream(stream, user_agent_size, "user_agent").decode("ascii")
        last_block = read_little_int(stream, cls.LAST_BLOCK_BYTES, "last_block")

        return cls(version, services, timestamp, r_services, r_ip, r_port, l_services, l_ip, l_port, nonce, user_agent,
                   last_block, magic_bytes)

    @property
    def command(self) -> str:
        return "version"

    def payload(self):
        byte_string = b''

        # Get ip addresses
        local_ipv6 = get_ipv6(self.local_ip)
        remote_ipv6 = get_ipv6(self.remote_ip)

        # Protocol version, services, time
        byte_string += self.protocol_version.to_bytes(self.VERSION_BYTES, "little")
        byte_string += self.services[::-1]
        byte_string += self.timestamp.to_bytes(self.TIME_BYTES, "little")

        # Remote services, ip and port
        byte_string += self.remote_services[::-1]
        byte_string += remote_ipv6.packed
        byte_string += self.remote_port.to_bytes(self.PORT_BYTES, "big")

        # Local services, ip and port
        byte_string += self.local_services[::-1]
        byte_string += local_ipv6.packed
        byte_string += self.local_port.to_bytes(self.PORT_BYTES, "big")

        # Nonce, user agent and last block
        byte_string += self.nonce.to_bytes(self.NONCE_BYTES, "little")
        user_agent = self.user_agent.encode("ascii")
        user_agent_size = write_compact_size(len(user_agent))
        byte_string += user_agent_size + user_agent
        byte_string += self.last_block.to_bytes(self.LAST_BLOCK_BYTES, "little")

        return byte_string

    def _payload_dict(self) -> dict:
        version_dict = {
            "protocol_version": self.protocol_version,
            "services": self.services.hex(),
            "time": datetime.utcfromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "remote_services": self.remote_services.hex(),
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "local_services": self.local_services.hex(),
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "nonce": self.nonce,
            "user_agent": self.user_agent,
            "last_block": self.last_block
        }
        return version_dict


class VerAck(ControlMessage):

    @property
    def command(self) -> str:
        return "verack"

    def payload(self):
        return b''


class Ping(ControlMessage):
    """
    -------------------------------------------------
    |   Name    | Data type | format        | size  |
    -------------------------------------------------
    |   Nonce   | int       | little-endian | 8     |
    -------------------------------------------------
    """
    NONCE_BYTES = 8

    def __init__(self, nonce: int, magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        self.nonce = nonce
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, bytes_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        stream = get_stream(bytes_stream)
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        return cls(nonce, magic_bytes)

    @property
    def command(self):
        return "ping"

    def payload(self):
        return self.nonce.to_bytes(self.NONCE_BYTES, "little")

    def _payload_dict(self) -> dict:
        return {"nonce": self.nonce}


class Pong(ControlMessage):
    """
    -------------------------------------------------
    |   Name    | Data type | format        | size  |
    -------------------------------------------------
    |   Nonce   | int       | little-endian | 8     |
    -------------------------------------------------
    """
    NONCE_BYTES = 8

    def __init__(self, nonce: int, magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        self.nonce = nonce
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, bytes_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        stream = get_stream(bytes_stream)
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        return cls(nonce, magic_bytes)

    @property
    def command(self):
        return "pong"

    def payload(self):
        return self.nonce.to_bytes(self.NONCE_BYTES, "little")

    def _payload_dict(self) -> dict:
        return {"nonce": self.nonce}


if __name__ == "__main__":
    from random import randint

    test_version_bytes = bytes.fromhex(
        "7E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")
    test_version = Version.from_bytes(test_version_bytes)
    print(f"TEST VERSION: {test_version.to_json()}")

    test_verack = VerAck()
    print(f"VERACK: {test_verack.to_json()}")

    random_ping = Ping(randint(250, 500))
    print(f"RANDOM PING: {random_ping.to_json()}")
    print(f"PONG: = {Pong(random_ping.nonce).to_json()}")
