"""
Control messages
"""
import time

from src.core import SERIALIZED, get_stream, read_little_int, read_stream
from src.core.byte_stream import read_compact_size
from src.data import write_compact_size
from src.network.message import EmptyMessage, Message
from src.network.network_data import NetAddr
from src.network.network_types import Services

__all__ = ["Version", "Pong", "Ping", "VerAck"]


class Version(Message):
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
    COMMAND = "version"
    __slots__ = ("protocol_version", "services", "timestamp", "remote_net_addr", "local_net_addr", "nonce",
                 "user_agent", "last_block")

    def __init__(self, version: int, services: int | Services, timestamp: int, remote_addr: NetAddr,
                 local_addr: NetAddr, nonce: int, user_agent: str, last_block: int):
        # Magic Bytes
        super().__init__()

        # Raw Data
        self.protocol_version = version
        self.services = Services(services) if isinstance(services, int) else services
        self.timestamp = timestamp
        self.remote_net_addr = remote_addr
        self.local_net_addr = local_addr
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        # Setup stream
        stream = get_stream(byte_stream)

        # Read version, services and timestamp
        version = read_little_int(stream, 4, "protocol_version")
        services = read_little_int(stream, 8, "services")
        timestamp = read_little_int(stream, 8, "time")

        # Read in remote and local NetAddr
        remote_netaddr = NetAddr.from_bytes(stream, is_version=True)
        local_netaddr = NetAddr.from_bytes(stream, is_version=True)

        # Read in nonce, user agent and last block
        nonce = read_little_int(stream, 8, "nonce")
        user_agent_size = read_compact_size(stream)
        user_agent = read_stream(stream, user_agent_size, "user_agent").rstrip(b'\x00').decode("ascii")
        last_block = read_little_int(stream, 4, "last_block")

        return cls(version, services, timestamp, remote_netaddr, local_netaddr, nonce, user_agent, last_block)

    def to_payload(self) -> bytes:
        encoded_agent = self.user_agent.encode("ascii")
        parts = [
            self.protocol_version.to_bytes(4, "little"),
            self.services.to_bytes(8, "little"),
            self.timestamp.to_bytes(8, "little"),
            self.remote_net_addr.to_bytes(),
            self.local_net_addr.to_bytes(),
            self.nonce.to_bytes(8, "little"),
            write_compact_size(len(encoded_agent)) + encoded_agent,
            self.last_block.to_bytes(4, "little")
        ]
        return b''.join(parts)

    def payload_dict(self) -> dict:
        return {
            "protocol_version": self.protocol_version,
            "services": self.services.name,
            "time": self.timestamp,
            "remote_netaddr": self.remote_net_addr.to_dict(),
            "local_netaddr": self.local_net_addr.to_dict(),
            "nonce": self.nonce,
            "user_agent": self.user_agent,
            "last_block": self.last_block
        }


class Ping(Message):
    COMMAND = "ping"

    def __init__(self, nonce: int):
        super().__init__()
        self.nonce = nonce

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)
        nonce = read_little_int(stream, 8)
        return cls(nonce)

    def to_payload(self) -> bytes:
        return self.nonce.to_bytes(8, "little")

    def payload_dict(self) -> dict:
        return {"nonce": self.nonce}


class Pong(Message):
    COMMAND = "pong"

    def __init__(self, nonce: int):
        super().__init__()
        self.nonce = nonce

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)
        nonce = read_little_int(stream, 8)
        return cls(nonce)

    def to_payload(self) -> bytes:
        return self.nonce.to_bytes(8, "little")

    def payload_dict(self) -> dict:
        return {"nonce": self.nonce}


class Addr(Message):
    """Provide information on known nodes of the network.
    =================================================================================
    |   Name        | data type         | format                            | size  |
    =================================================================================
    |   count       |   int             |   compactSize                     |   var |
    |   addr_list   |   list[NetAddr]   |   timestamp + NetAddr.to_bytes()  |   var |
    =================================================================================
    *The timestamp is a 4-byte (32-bit) little-endian integer (Unix timestamp)
    """
    COMMAND = "addr"
    __slots__ = ("addr_list",)

    def __init__(self, addr_list: list[NetAddr]):
        super().__init__()
        self.addr_list = addr_list

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # count
        count = read_compact_size(stream)

        # timestamp + net_addr
        addr_list = []
        for _ in range(count):
            temp_timestamp = read_little_int(stream, 4)
            # TODO: add timestamp validation for version >= 31402
            addr_list.append(NetAddr.from_bytes(stream))

    def to_payload(self) -> bytes:
        count = len(self.addr_list)
        parts = [write_compact_size(count)]
        for addr in self.addr_list:
            timestamp_int = int(time.time())
            parts.append(timestamp_int.to_bytes(4, "little") + addr.to_bytes())
        return b''.join(parts)

    def payload_dict(self, formatted: bool = True) -> dict:
        count = len(self.addr_list)
        addr_dict = {}
        for x in range(count):
            temp_addr = self.addr_list[x]
            addr_dict.update({f"addr_{x}": temp_addr.to_dict(formatted)})
        return {
            "count": write_compact_size(count).hex() if formatted else count,
            "net_addrs": addr_dict
        }


# --- EMPTY MESSAGES --- #
class VerAck(EmptyMessage):
    COMMAND = "verack"


# --- TESTING ---
if __name__ == "__main__":
    sep = "===" * 40

    # VerAck
    test_verack = VerAck()
    print(f"VERACK: {test_verack.to_json()}")
    print(sep)

    # Ping
    test_ping = Ping(1234)
    print(f"PING: {test_ping.to_json()}")
    print(sep)

    # Version
    test_lmab_version_bytes = bytes.fromhex(
        "F9BEB4D976657273696F6E0000000000550000002C2F86F37E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")
    test_version = Version.from_payload(test_lmab_version_bytes)
    print(f"TEST VERSION: {test_version.to_json()}")
