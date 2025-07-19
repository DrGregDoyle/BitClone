"""
Classes and Methods for help with p2p messaging/networking
"""
from io import BytesIO

from src.data.byte_stream import get_stream, read_little_int, read_stream
from src.data.data_types import InvType

__all__ = ["Inventory"]


# --- INVENTORY --- #
class Inventory:
    """
    ---------------------------------------------------------
    |   Name    | datatype  | format                | size  |
    ---------------------------------------------------------
    |   Type    |   int     | little-endian         | 4     |
    |   hash    |   bytes   | natural byte order    | 32    |
    ---------------------------------------------------------
    """
    TYPE_BYTES = 4
    HASH_BYTES = 32

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
        type = read_little_int(stream, cls.TYPE_BYTES, "inventory type")

        # Hash
        hash = read_stream(stream, cls.HASH_BYTES, "inventory hash")

        return cls(type, hash)

    def to_bytes(self):
        """
        Formatted inventory
        """
        return self.inv_type.value.to_bytes(self.TYPE_BYTES, "little") + self.hash

    def to_dict(self):
        inv_dict = {
            "type": self.inv_type.name,
            "hash": self.hash.hex()
        }
        return inv_dict
