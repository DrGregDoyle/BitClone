"""
Inventory Vector Data Type
"""

import json
from enum import Enum
from io import BytesIO

from src.data.byte_stream import get_stream, read_little_int, read_stream


class InvType(Enum):
    ERROR = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4
    MSG_WITNESS_TX = 0x40000001
    MSG_WITNESS_BLOCK = 0x40000002
    MSG_FILTERED_WITNESS_BLOCK = 0x40000003


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

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# -- TESTING
if __name__ == "__main__":
    dummy_hash = bytes.fromhex("aa325e9122aa39ca18c75aabe2a3ceaf9802acd1a40720925bfd77fff58ed821")
    test_inv = Inventory(1, dummy_hash)
    print(f"TEST INVENTORY: {test_inv.to_bytes().hex()}")
    print(f"TEST INV DICT: {test_inv.to_json()}")
