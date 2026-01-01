"""
Contains the Header class along with other classes necessary for Network communication
"""
import json
from abc import ABC, abstractmethod
from ipaddress import IPv4Address

from src.core import Serializable, MAGICBYTES, NetworkError, SERIALIZED, get_stream, read_stream, read_little_int, \
    read_big_int
from src.cryptography import hash256
from src.data import read_compact_size, IP_ADDRESS, ip_from_netaddr, netaddr_bytes, write_compact_size, ip_display
from src.network.services import Services

# IP_ADDRESS = Union[IPv4Address, IPv6Address]
LMAB_IP = IPv4Address("162.120.69.182")

DEFAULT_MAGIC_BYTES = MAGICBYTES.MAINNET
VALID_MAGIC_BYTES = {MAGICBYTES.MAINNET, MAGICBYTES.TESTNET, MAGICBYTES.REGTEST}
ALLOWED_COMMANDS = [
    "version", "verack", "addr", "inv", "getdata", "getblocks", "getheaders", "tx", "block", "headers", "getaddr",
    "ping", "pong", "notfound", "mempool", "reject", "filterload", "filteradd", "filterclear", "merkleblock",
    "sendheaders", "feefilter", "sendcmpct", "cmpctblock", "getblocktxn", "blocktxn"
]
DEPRECATED_COMMANDS = [
    "submitoder", "checkorder", "reply", "alert"
]


# --- Message Header --- #

class MsgHeader(Serializable):
    """
    The MsgHeader class. Every Network message sent to/from a peer will have the MsgHeader attached
    """
    LENGTH = 24

    def __init__(self, command: str, size: int, checksum: bytes, magic_bytes: bytes = DEFAULT_MAGIC_BYTES):
        # Validation
        if command in DEPRECATED_COMMANDS:
            raise NetworkError(f"Command {command} has been deprecated")
        if command not in ALLOWED_COMMANDS:
            raise NetworkError(f"No command found of the type: {command}")
        if len(checksum) != 4:
            raise NetworkError("Given checksum not of correct length")
        if magic_bytes not in VALID_MAGIC_BYTES:
            raise NetworkError("Given magic bytes are not recognized")

        # Class vars
        self.magic_bytes = magic_bytes
        self.command = command
        self.size = size
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        """
        We read in the header values from the byte stream
        """
        stream = get_stream(byte_stream)

        # Magic bytes
        mb = read_stream(stream, 4, "magic_bytes")
        # Command | Strip out padding
        encoded_command = read_stream(stream, 12, "command")
        command = encoded_command.rstrip(b'\x00').decode(encoding="ascii")
        # Size
        size = read_little_int(stream, 4, "size")
        # Checksum
        checksum = read_stream(stream, 4, "checksum")

        return MsgHeader(command=command, size=size, checksum=checksum, magic_bytes=mb)

    def to_bytes(self) -> bytes:
        """
        The encoded message header. We pad the encoded command with 00 bytes to reach length 12
        """
        encoded_command = self.command.encode("ascii")
        parts = [
            self.magic_bytes,
            encoded_command + b'\x00' * (12 - len(encoded_command)),
            self.size.to_bytes(4, "little"),
            self.checksum
        ]
        return b''.join(parts)

    def to_dict(self):
        # Find network by comparing magic bytes with MAGICBYTES attributes
        network = next(
            (name.lower() for name in dir(MAGICBYTES)
             if not name.startswith('_') and getattr(MAGICBYTES, name) == self.magic_bytes),
            None
        )
        return {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command,
            "size": self.size,
            "checksum": self.checksum.hex(),
            "network": network

        }


# --- Network Message Parent --- #

class NetworkMsg(Serializable, ABC):
    """
    Abstract base class for all Bitcoin network messages
    """
    COMMAND: str = None  # Override in subclasses

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the message body to bytes"""
        pass

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        """Deserialize the message body from bytes"""
        pass

    @classmethod
    def from_message(cls, byte_stream: SERIALIZED):
        """Deserialize the message = header + body"""
        stream = get_stream(byte_stream)

        # Header
        header_bytes = read_stream(stream, MsgHeader.LENGTH)
        header = MsgHeader.from_bytes(header_bytes)

        # Command validation
        if header.command != cls.COMMAND:
            raise NetworkError(f"Expected command '{cls.COMMAND}', got '{header.command}'")

        # Body (read exactly size bytes)
        payload = read_stream(stream, header.size, "payload")
        body = cls.from_bytes(payload)

        # Validate
        if body.create_header() != header:
            raise NetworkError("Deserialized Header doesn't match Header recovered from message body")

        return body

    @abstractmethod
    def to_dict(self) -> dict:
        """Return a dictionary representation of the message"""
        pass

    def message_dict(self) -> dict:
        """Return a dictionary representation of the header + body"""
        header = self.create_header()
        return {
            "header": header.to_dict(),
            "body": self.to_dict()
        }

    def message_json(self):
        return json.dumps(self.message_dict(), indent=2)

    def create_header(self, magic_bytes: bytes = DEFAULT_MAGIC_BYTES) -> MsgHeader:
        """
        Create a header for this message
        """

        body = self.to_bytes()
        size = len(body)
        checksum = hash256(body)[:4]
        return MsgHeader(
            command=self.COMMAND,
            size=size,
            checksum=checksum,
            magic_bytes=magic_bytes
        )

    def to_network_message(self, magic_bytes: bytes = DEFAULT_MAGIC_BYTES) -> bytes:
        """
        Create complete network message (header + body)
        """
        header = self.create_header(magic_bytes)
        return header.to_bytes() + self.to_bytes()


# ============================================================================
# HANDSHAKE AND CONNECTION MESSAGES
# ============================================================================

class VersionMessage(NetworkMsg):
    """
    Version message for initial handshake
    Contains node capabilities and connection information
    """
    COMMAND = "version"

    def __init__(self,
                 protocol_version: int,
                 services: Services,
                 epoch_time: int,
                 remote_services: Services,
                 remote_ip: IP_ADDRESS,
                 remote_port: int,
                 local_services: Services,
                 local_ip: IP_ADDRESS,
                 local_port: int,
                 nonce: int,
                 user_agent: str,
                 last_block: int):
        self.protocol_version = protocol_version
        self.services = services
        self.epoch_time = epoch_time
        self.remote_services = remote_services
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.local_services = local_services
        self.local_ip = local_ip
        self.local_port = local_port
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Read in data
        protocol_version = read_little_int(stream, 4)
        service_int = read_little_int(stream, 8)
        epoch_time = read_little_int(stream, 8)
        remote_service_int = read_little_int(stream, 8)
        remote_ip_bytes = read_stream(stream, 16)
        remote_port = read_big_int(stream, 2)
        local_service_int = read_little_int(stream, 8)
        local_ip_bytes = read_stream(stream, 16)
        local_port = read_big_int(stream, 2)
        nonce = read_little_int(stream, 8)
        user_agent_size = read_compact_size(stream)
        user_agent_bytes = read_stream(stream, user_agent_size)
        last_block = read_little_int(stream, 4)

        # Convert data
        services = Services(service_int)
        remote_services = Services(remote_service_int)
        local_services = Services(local_service_int)
        remote_ip = ip_from_netaddr(remote_ip_bytes)
        local_ip = ip_from_netaddr(local_ip_bytes)
        user_agent = user_agent_bytes.decode("ascii")

        return VersionMessage(
            protocol_version, services, epoch_time, remote_services, remote_ip, remote_port, local_services,
            local_ip, local_port, nonce, user_agent, last_block
        )

    def to_bytes(self) -> bytes:
        encoded_user_agent = self.user_agent.encode("ascii")
        parts = [
            self.protocol_version.to_bytes(4, "little"),
            self.services.to_bytes(8, "little"),
            self.epoch_time.to_bytes(8, "little"),
            self.remote_services.to_bytes(8, "little"),
            netaddr_bytes(self.remote_ip),
            self.remote_port.to_bytes(2, "big"),
            self.local_services.to_bytes(8, "little"),
            netaddr_bytes(self.local_ip),
            self.local_port.to_bytes(2, "big"),
            self.nonce.to_bytes(8, "little"),
            write_compact_size(len(encoded_user_agent)),
            encoded_user_agent,
            self.last_block.to_bytes(4, "little")
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "protocol_version": self.protocol_version,
            "services": self.services,
            "time": self.epoch_time,
            "remote_services": self.remote_services,
            "remote_ip": ip_display(self.remote_ip),
            "remote_port": self.remote_port,
            "local_services": self.local_services,
            "local_ip": ip_display(self.local_ip),
            "local_port": self.local_port,
            "nonce": self.nonce,
            "user_agent": self.user_agent,
            "last_block": self.last_block
        }


# class VerackMessage(NetworkMsg):
#     """
#     Version acknowledgment - confirms version message receipt
#     Empty payload
#     """
#     COMMAND = "verack"
#
#     def to_bytes(self) -> bytes:
#         return b''
#
#     @classmethod
#     def from_bytes(cls, byte_stream: SERIALIZED):
#         return cls()


# --- TESTING --- #
if __name__ == "__main__":
    sep = "===" * 40

    # Test LMAB version message
    version_bytes = bytes.fromhex(
        "F9BEB4D976657273696F6E0000000000550000002C2F86F37E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")

    test_version = VersionMessage.from_message(version_bytes)
    print(f"TEST VERSION: {test_version.to_json()}")
    print(f"MESSAGE DICT: {test_version.message_json()}")
