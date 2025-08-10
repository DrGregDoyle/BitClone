"""
The various ENUM classes indicating different types
"""

from enum import IntEnum, IntFlag

__all__ = ["InvType", "BloomType", "RejectType", "NodeType"]


class InvType(IntEnum):
    ERROR = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4
    MSG_WITNESS_TX = 0x40000001  # or (1<<30)+MSG_TX
    MSG_WITNESS_BLOCK = 0x40000002  # or (1<<30)+MST_BLOCK
    MSG_FILTERED_WITNESS_BLOCK = 0x40000003  # or (1<<30)+MSG_FILTERED_BLOCK


class BloomType(IntEnum):
    BLOOM_UPDATE_NONE = 0
    BLOOM_UPDATE_ALL = 1
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2

    def to_byte(self):
        """
        1-byte serialization
        """
        return self.value.to_bytes(1, "little")


class RejectType(IntEnum):
    REJECT_MALFORMED = 0x01
    REJECT_INVALID = 0x10
    REJECT_OBSOLETE = 0x11
    REJECT_DUPLICATE = 0x12
    REJECT_NONSTANDARD = 0x40
    REJECT_DUST = 0x41
    REJECT_INSUFFICIENTFEE = 0x42
    REJECT_CHECKPOINT = 0x43

    def to_byte(self):
        return self.value.to_bytes(1, "little")


class NodeType(IntFlag):
    NONE = 0
    NODE_NETWORK = 0x01
    NODE_GETUTXO = 0x02
    NODE_BLOOM = 0x04
    NODE_WITNESS = 0x08
    NODE_XTHIN = 0x10
    NODE_COMPACT_FILTERS = 0x40
    NODE_NETWORK_LIMITED = 0x400

    def byte_format(self, width: int = 8) -> bytes:
        """Little‑endian serialization (default 8 bytes, per protocol services)."""
        return int(self).to_bytes(width, "little", signed=False)

    @classmethod
    def _missing_(cls, value: object) -> "NodeType":
        # Whenever NodeType(value) is called with a value not in the enum,
        # fall back to NONE instead of ValueError.
        return cls.NONE


# --- TESTING
from random import choice

if __name__ == "__main__":
    node_val = choice([0, 1, 2, 4, 8, 16, 64, 1024])
    dummy_node = NodeType(node_val)
    print(f"DUMMY NODE: {dummy_node.name}")
    print(f"BYTE VALS: {dummy_node.byte_format().hex()}")
