"""
Control Messages:
    -Alert
    -FeeFilter
    -FilterClear
    -FilerLoad
    -GetAddr
    -Reject
    -SendHeaders
"""
import ipaddress
from datetime import datetime
from io import BytesIO
from time import time as now

from src.data import get_stream, read_little_int, read_stream, read_compact_size, write_compact_size, MAINNET, NetAddr
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

    def __init__(self, version: int, services: bytes, timestamp: int, remote_addr: NetAddr, local_addr: NetAddr,
                 nonce: int,
                 user_agent: str,
                 last_block: int,
                 magic_bytes: bytes = MAINNET):
        # Magic Bytes
        super().__init__(magic_bytes)
        self.magic_bytes = magic_bytes

        # Raw Data
        self.protocol_version = version
        self.services = services
        self.timestamp = timestamp
        self.remote_net_addr = remote_addr
        self.local_net_addr = local_addr
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Setup stream
        stream = get_stream(byte_stream)

        # Read version, services and timestamp
        version = read_little_int(stream, cls.VERSION_BYTES, "protocol_version")
        services = read_stream(stream, cls.SERVICE_BYTES, "services")
        timestamp = read_little_int(stream, cls.TIME_BYTES, "time")

        # Read in remote and local NetAddr
        remote_netaddr = NetAddr.from_bytes(stream, is_version=True)
        local_netaddr = NetAddr.from_bytes(stream, is_version=True)

        # Read in nonce, user agent and last block
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        user_agent_size = read_compact_size(stream, "user_agent_size")
        user_agent = read_stream(stream, user_agent_size, "user_agent").decode("ascii")
        last_block = read_little_int(stream, cls.LAST_BLOCK_BYTES, "last_block")

        return cls(version, services, timestamp, remote_netaddr, local_netaddr, nonce, user_agent, last_block,
                   magic_bytes)

    @property
    def command(self) -> str:
        return "version"

    def payload(self):
        byte_string = b''

        # Protocol version, services, time
        byte_string += self.protocol_version.to_bytes(self.VERSION_BYTES, "little")
        byte_string += self.services[::-1]
        byte_string += self.timestamp.to_bytes(self.TIME_BYTES, "little")

        # Remote and local netaddr
        byte_string += self.remote_net_addr.to_bytes() + self.local_net_addr.to_bytes()

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
            "remote_netaddr": self.remote_net_addr.to_dict(),
            "local_netaddr": self.local_net_addr.to_dict(),
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


class Addr(ControlMessage):

    def __init__(self, addr_list: list[NetAddr], magic_bytes: bytes = MAINNET):
        super().__init__()
        self.addr_list = addr_list
        self.count = len(addr_list)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Get stream
        stream = get_stream(byte_stream)

        # Get count
        count = read_compact_size(stream, "addr_count")

        # Get addrs
        addr_list = []
        for _ in range(count):
            addr_list.append(NetAddr.from_bytes(stream))

        return cls(addr_list, magic_bytes)

    @property
    def command(self) -> str:
        return "addr"

    def payload(self) -> bytes:
        payload = write_compact_size(self.count)
        for a in self.addr_list:
            payload += a.to_bytes()
        return payload

    def _payload_dict(self) -> dict:
        # Collect addresses first
        addr_dict = {}
        for x in range(self.count):
            temp_addr = self.addr_list[x]
            addr_dict.update({f"net_addr{x}": temp_addr.to_dict()})
        payload_dict = {
            "count": self.count,
            "addr_list": addr_dict
        }
        return payload_dict


if __name__ == "__main__":
    from random import randint
    from secrets import token_bytes

    test_version_bytes = bytes.fromhex(
        "7E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")
    test_version = Version.from_bytes(test_version_bytes)
    print(f"TEST VERSION: {test_version.to_json()}")

    test_verack = VerAck()
    print(f"VERACK: {test_verack.to_json()}")

    random_ping = Ping(randint(250, 500))
    print(f"RANDOM PING: {random_ping.to_json()}")
    print(f"PONG: = {Pong(random_ping.nonce).to_json()}")


    def random_netaddr() -> NetAddr:
        # Random services
        services = token_bytes(8)

        # Random ip
        ip_addr = str(ipaddress.IPv4Address(randint(0, 2 ** 32 - 1)))

        # Random port
        port = randint(0, 0xffff)

        return NetAddr(int(now()), services, ip_addr, port)


    net_addr_list = [random_netaddr() for _ in range(randint(1, 5))]
    test_addr = Addr(net_addr_list)
    print(f"TEST ADDR: {test_addr.to_json()}")
