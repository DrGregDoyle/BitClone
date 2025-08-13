"""
Classes and Methods for help with p2p messaging/networking
"""
from datetime import datetime
from io import BytesIO
from time import time as now

from src.crypto import hash256
from src.data.byte_stream import get_stream, read_little_int, read_stream, read_big_int
from src.data.data_types import InvType, NodeType
from src.data.formats import Wire, Display
from src.data.ip_utils import IPLike, normalize, to_display, read_ip16
from src.data.serializable import Serializable
from src.data.varint import write_compact_size, read_compact_size

__all__ = ["Inventory", "NetAddr", "ShortID", "Header", "BlockTxRequest"]

# BTF = BitcoinFormats.Time
# BTI = BitcoinFormats.Inventory
_inv = Wire.InventoryEntry
_hdr = Wire.Header
_sid = Wire.ShortIDSpec


# BTN = BitcoinFormats.Network


# --- INVENTORY --- #
class Inventory(Serializable):
    """
    ---------------------------------------------------------
    |   Name    | datatype  | format                | size  |
    ---------------------------------------------------------
    |   Type    |   int     | little-endian         | 4     |
    |   hash    |   bytes   | natural byte order    | 32    |
    ---------------------------------------------------------
    """

    __slots__ = ["inv_type", "hash"]

    def __init__(self, inv_type: int | InvType, hash_: bytes):
        # Error checking
        if not isinstance(inv_type, (int, InvType)):
            raise ValueError("inv_type must be int or InvType")

        self.inv_type = InvType(inv_type) if isinstance(inv_type, int) else inv_type
        self.hash = hash_

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get stream
        stream = get_stream(byte_stream)

        # Type
        invtype = read_little_int(stream, _inv.TYPE_LEN, "inventory type")

        # Hash
        invhash = read_stream(stream, _inv.HASH_LEN, "inventory hash")

        return cls(invtype, invhash)

    def to_bytes(self):
        """
        Formatted inventory
        """
        return self.inv_type.value.to_bytes(_inv.TYPE_LEN, "little") + self.hash

    def to_dict(self):
        inv_dict = {
            "type": self.inv_type.name,
            "hash": self.hash.hex()
        }
        return inv_dict


class NetAddr(Serializable):
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
    __slots__ = ["timestamp", "services", "ip_address", "port", "is_version"]

    def __init__(self, timestamp: int, services: int | NodeType, ip_addr: IPLike, port: int, is_version: bool = False):
        self.timestamp = timestamp
        self.services = NodeType(services) if isinstance(services, int) else services
        self.ip_address = normalize(ip_addr)  # IPv6Address
        self.port = port
        self.is_version = is_version

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, is_version=False):
        # Get stream
        stream = get_stream(byte_stream)

        # Check version message
        if not is_version:
            timestamp = read_little_int(stream, Wire.NetAddr.TIME_LEN, "time")
        else:
            timestamp = int(now())

        # Get the rest
        services = read_little_int(stream, Wire.NetAddr.SERVICES_LEN, "services")
        ipv6 = read_ip16(stream)
        port = read_big_int(stream, 2, "port")

        return cls(timestamp, services, ipv6, port, is_version)

    @property
    def display_ip(self) -> str:
        return to_display(self.ip_address)

    @property
    def display_time(self) -> str:
        return datetime.utcfromtimestamp(self.timestamp).strftime(Display.TIME_FORMAT)

    def to_bytes(self):
        # Add time if not version Address
        payload = self.timestamp.to_bytes(Wire.NetAddr.TIME_LEN, "little") if not self.is_version else b''
        payload += self.services.byte_format() + self.ip_address.packed + self.port.to_bytes(Wire.NetAddr.PORT_LEN,
                                                                                             "big")
        return payload

    def to_dict(self):
        if not self.is_version:
            net_addr_dict = {"time": self.display_time}
        else:
            net_addr_dict = {}
        net_addr_dict.update({
            "services": self.services.name,
            "ip_address": self.display_ip,
            "port": self.port
        })
        return net_addr_dict


class ShortID(Serializable):
    """
    A 6-byte integer, padded with 2 null-bytes, so it can be read as an 8-byte integer
    """
    __slots__ = ["short_id"]

    def __init__(self, short_id: int | bytes):
        # short_id as integer
        if isinstance(short_id, int):
            # Error checking
            int_byte_length = (short_id.bit_length() + 7) // 8
            if int_byte_length > _sid.PAYLOAD_LEN:
                raise ValueError(
                    f"Given integer {short_id} has byte length greater than {_sid.PAYLOAD_LEN}")
            self.short_id = short_id.to_bytes(_sid.PADDED_LEN, "little")
        elif isinstance(short_id, bytes):
            # Error checking
            if len(short_id) > _sid.PAYLOAD_LEN:
                raise ValueError(
                    f"Given bytes object {short_id.hex()} has byte length greater than {_sid.PAYLOAD_LEN}")
            self.short_id = short_id + b'\x00' * (_sid.PADDED_LEN - len(short_id))
        else:
            raise ValueError("Incorrect short_id type")

        # Underlying integer
        self.int_value = int.from_bytes(self.short_id, "little")

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        int_val = read_little_int(stream, _sid.PADDED_LEN, "short_id")
        return cls(int_val)

    def to_bytes(self):
        return self.short_id

    def to_dict(self):
        return {
            "short_id": self.short_id.hex(),
            "int_value": self.int_value
        }


class Header(Serializable):
    """
    -----------------------------------------
    |   Name        | Format        | Size  |
    -----------------------------------------
    |   Magic Bytes | Bytes         | 4     |
    |   Command     | Ascii bytes   | 12    |
    |   Size        | little-endian | 4     |
    |   Checksum    | bytes         | 4     |
    -----------------------------------------
    """
    __slots__ = ["magic_bytes", "command", "size", "checksum"]

    def __init__(self, magic_bytes: bytes, command: str, size: int, checksum: bytes):
        self.magic_bytes = magic_bytes
        self.command = command
        self.size = size
        self.checksum = checksum[:4]

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get byte stream
        stream = get_stream(byte_stream)

        # Get byte data
        magic_bytes = read_stream(stream, _hdr.MAGIC_LEN, "magic_bytes")
        command = read_stream(stream, _hdr.COMMAND_LEN, "command").rstrip(b'\x00').decode("ascii")
        size = read_little_int(stream, _hdr.SIZE_LEN, "size")
        checksum = read_stream(stream, _hdr.CHECKSUM_LEN, "checksum")

        return cls(magic_bytes, command, size, checksum)

    @classmethod
    def from_payload(cls, payload: bytes, command: str, magic_bytes: bytes):
        size = len(payload)
        payload_checksum = hash256(payload)[:4]
        return cls(magic_bytes, command, size, payload_checksum)

    def to_bytes(self) -> bytes:
        """
        Serialization of the header | 24 bytes
        """
        command_bytes = self.command.encode("ascii")
        command_bytes = command_bytes.ljust(12, b'\x00')[:12]
        header_bytes = (
                self.magic_bytes
                + command_bytes
                + self.size.to_bytes(_hdr.SIZE_LEN, "little")
                + self.checksum
        )
        return header_bytes

    def to_dict(self) -> dict:
        """
        Returns display dict with instance values
        """
        header_dict = {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command.rstrip('\x00'),
            "size": self.size,
            "checksum": self.checksum.hex()
        }
        return header_dict


class BlockTxRequest(Serializable):
    """
    -------------------------------------------------------------------------------------
    |   Name        |   data type   |   byte format                         |   size    |
    -------------------------------------------------------------------------------------
    |   block_hash  |   bytes       |   internal byte order                 |   32      |
    |   index_num   |   int         |   CompactSize                         |   varint  |
    |   indexes     |   list        |   diff-encoded list of CompactSize    |   var     |
    -------------------------------------------------------------------------------------
    """
    __slots__ = ["block_hash", "indexes", "index_num"]

    def __init__(self, block_hash: bytes, indexes: list):
        self.block_hash = block_hash
        self.index_num = len(indexes)
        self.indexes = indexes

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # hash
        block_hash = read_stream(stream, Wire.BlockHeader.PREV_HASH_LEN, "block_hash")

        # indexes
        index_num = read_compact_size(stream, "index_num")
        indexes = [read_compact_size(stream, "indexes") for _ in range(index_num)]

        return cls(block_hash, indexes)

    def to_bytes(self) -> bytes:
        parts = [self.block_hash, write_compact_size(self.index_num)]
        parts += [write_compact_size(i) for i in self.indexes]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "block_hash": self.block_hash.hex(),
            "index_num": self.index_num,
            "indexes": {f"index_{x}": self.indexes[x].hex() for x in range(self.index_num)}
        }
